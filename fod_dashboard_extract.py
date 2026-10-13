#!/usr/bin/env python3
"""
AppSec dashboard extract: Fortify on Demand -> single CSV for Power BI.

Emits one file with a RowType discriminator:
    RowType = "Monthly"   one row per release x scan type x month  (tiles, ageing, trend)
    RowType = "Scan"      one row per scan                          (scan history)

FoD stores no historical state. It stores enough DATES to rebuild it:
    introducedDate  first seen                      (issue list)
    closedDate      fixed / not-an-issue            (issue list)
    grant date      became Risk Accepted            (/history, historyType=Audit)
    expiry date     EXP:yyyy-mm-dd in an audit comment

Every finding is classified at every month end from those dates.

    python3 fod_dashboard_extract.py --out appsec_dashboard_latest.csv

Exit codes: 0 ok, 1 fatal, 2 completed with per-release failures over the threshold.
"""
import argparse, csv, json, logging, os, re, subprocess, sys, time
import datetime as dt
from collections import defaultdict

LOG = logging.getLogger("extract")

SEV = ("Critical", "High", "Medium", "Low")
BUCKETS = ("0_14", "15_60", "61_90", "90Plus")

# Tenant-configurable. Verify with: fcli fod rest call -X GET "/api/v3/lookup-items"
OPEN_STATUSES = {"Pending Review", "Remediation Required", "Remediation Deferred",
                 "Risk Mitigated", "Suspicious"}
DEBT_STATUSES = {"Risk Accepted"}
RESOLVED_STATUSES = {"Not an Issue"}
ALL_STATUSES = OPEN_STATUSES | DEBT_STATUSES | RESOLVED_STATUSES

SCAN_LABEL = {"Static": "SAST", "Dynamic": "DAST"}   # OpenSource/Mobile out of scope

GRANT_RE = re.compile(r"Changed Auditor Status from '.*?' to '(.*?)'")
EXPIRY_RE = re.compile(r"EXP:(\d{4}-\d{2}-\d{2})")

COLUMNS = [
    "ExtractedAt", "RowType", "ScanType", "ApplicationId", "ApplicationName",
    "ReleaseId", "ReleaseName", "SDLCStatus", "Suspended", "BusinessCriticality",
    "StarRating", "Region", "Platform", "ValueStream", "InternalExternal",
    "LastScanDate", "MonthStartDate", "MonthLabel", "ScanCount", "IsCurrentSnapshot",
    "Detected", "Remediated", "FalsePositive", "RiskAccepted", "TotalBacklog",
    *[f"Open_{s}" for s in SEV], *[f"Debt_{s}" for s in SEV], *[f"Resolved_{s}" for s in SEV],
    *[f"Age_{b}" for b in BUCKETS],
    *[f"ExcActive_{b}" for b in BUCKETS], *[f"ExcExpired_{b}" for b in BUCKETS],
    "ScanId", "AssessmentTypeName", "AnalysisStatusType", "StartedDateTime",
    "CompletedDateTime", "ScanDurationHours", "ScanMonth", "TotalIssues",
    "IssueCountCritical", "IssueCountHigh", "IssueCountMedium", "IssueCountLow",
    "ScanMethodTypeName", "ScanTool", "ScanToolVersion", "IsRemediationScan",
    "EntitlementUnitsConsumed", "StartedByUserName",
]

# Tenant attributes carrying the dashboard's dimension filters. Confirm the exact
# names with: fcli fod attribute list -o json
ATTRIBUTE_MAP = {"Region": "Region", "Platform": "Platform",
                 "Value Stream": "ValueStream", "Internal/External": "InternalExternal"}


# --------------------------------------------------------------------- fcli plumbing
class FcliError(RuntimeError):
    pass


def fcli(*args, retries=4):
    """Run fcli, parse JSON, retry on transient failure with backoff."""
    cmd = ["fcli", *args]
    for attempt in range(retries):
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0:
            try:
                return json.loads(proc.stdout or "[]")
            except json.JSONDecodeError as e:
                raise FcliError(f"bad JSON from {' '.join(args[:4])}: {e}") from e
        err = (proc.stderr or "").strip()
        transient = any(t in err.lower() for t in
                        ("429", "timeout", "timed out", "502", "503", "504",
                         "connection reset", "too many requests"))
        if not transient or attempt == retries - 1:
            raise FcliError(f"{' '.join(cmd[:6])} failed: {err[:300]}")
        wait = 2 ** attempt * 5
        LOG.warning("transient failure, retrying in %ss: %s", wait, err[:120])
        time.sleep(wait)


def rest(path, retries=4):
    return fcli("fod", "rest", "call", "-X", "GET", path, "-o", "json", retries=retries)


def rest_paged(path, page=200, cap=200_000):
    """Page a REST collection until a short page comes back."""
    out, offset = [], 0
    sep = "&" if "?" in path else "?"
    while len(out) < cap:
        chunk = rest(f"{path}{sep}offset={offset}&limit={page}")
        items = chunk.get("items", chunk) if isinstance(chunk, dict) else chunk
        out += items
        if len(items) < page:
            return out
        offset += page
    LOG.warning("hit the %s record cap on %s", cap, path)
    return out


# --------------------------------------------------------------------------- helpers
def d(s):
    return dt.date.fromisoformat(s[:10]) if s else None


def month_periods(n, today):
    """n (start, end) pairs, oldest first. Newest ends today, not month end."""
    out, y, m = [], today.year, today.month
    for i in range(n):
        if i == 0:
            out.append((dt.date(y, m, 1), today))
        else:
            m -= 1
            if m == 0:
                m, y = 12, y - 1
            nxt = dt.date(y + (m == 12), (m % 12) + 1, 1)
            out.append((dt.date(y, m, 1), nxt - dt.timedelta(days=1)))
    return list(reversed(out))


def age_bucket(days):
    return ("0_14" if days <= 14 else "15_60" if days <= 60
            else "61_90" if days <= 90 else "90Plus")


def expiry_bucket(days):
    a = abs(days)
    return ("0_14" if a <= 14 else "15_60" if a <= 60
            else "61_90" if a <= 90 else "90Plus")


def attributes_of(obj):
    out = {v: "" for v in ATTRIBUTE_MAP.values()}
    for a in (obj.get("attributes") or []):
        col = ATTRIBUTE_MAP.get(a.get("name"))
        if col:
            out[col] = a.get("value") or ""
    return out


def blank_row(extracted_at, row_type):
    r = {c: "" for c in COLUMNS}
    r["ExtractedAt"], r["RowType"] = extracted_at, row_type
    return r


# ------------------------------------------------------------------------ core logic
def classify(issue, when, grant):
    """Which bucket was this finding in, as at `when`? None if it did not exist."""
    intro = d(issue.get("introducedDate"))
    if intro is None or intro > when:
        return None
    closed = d(issue.get("closedDate"))
    if closed and closed <= when:
        return "Resolved"
    status = issue.get("auditorStatus")
    if status not in ALL_STATUSES:
        raise FcliError(f"unmapped auditorStatus {status!r} (add it to the status sets)")
    if status in RESOLVED_STATUSES and not closed:
        return "Resolved"
    g = grant.get(issue["instanceId"])
    if g and g <= when:
        return "Debt"
    return "Open"


def exception_dates(release_id, issues):
    """Grant and expiry dates, fetched only for the Risk Accepted subset."""
    grant, expiry = {}, {}
    accepted = [i for i in issues if i.get("auditorStatus") in DEBT_STATUSES]
    for i in accepted:
        iid, vid = i["instanceId"], i["vulnId"]
        try:
            for ev in rest(f"/api/v3/releases/{release_id}/vulnerabilities/{vid}/history"):
                if ev.get("historyType") != "Audit":
                    continue
                m = GRANT_RE.search(ev.get("content", ""))
                if m and m.group(1) in DEBT_STATUSES:
                    day = d(ev["historyDateTime"])
                    if day and (iid not in grant or day < grant[iid]):
                        grant[iid] = day
            if i.get("hasComments"):
                for c in rest(f"/api/v3/releases/{release_id}/vulnerabilities/{vid}/comments"):
                    m = EXPIRY_RE.search(c.get("comment") or "")
                    if m:
                        expiry[iid] = d(m.group(1))
        except FcliError as e:
            LOG.warning("exception detail failed for %s: %s", iid, e)
    return grant, expiry, len(accepted)


def monthly_rows(rel, dims, issues, grant, expiry, periods, extracted_at, scan_months):
    by_scan = defaultdict(list)
    for i in issues:
        label = SCAN_LABEL.get(i.get("scantype") or i.get("scanType"))
        if label:
            by_scan[label].append(i)

    for scan_type, items in by_scan.items():
        last_scan = max((d(i.get("scanCompletedDate")) for i in items
                         if i.get("scanCompletedDate")), default=None)
        for n, (start, end) in enumerate(periods):
            r = blank_row(extracted_at, "Monthly")
            r.update(dims)
            r.update({
                "ScanType": scan_type,
                "ApplicationId": rel["applicationId"], "ApplicationName": rel["applicationName"],
                "ReleaseId": rel["releaseId"], "ReleaseName": rel["releaseName"],
                "SDLCStatus": rel.get("sdlcStatusType"),
                "Suspended": "Yes" if rel.get("suspended") else "No",
                "StarRating": rel.get("rating", ""),
                "LastScanDate": last_scan.isoformat() if last_scan else "",
                "MonthStartDate": start.isoformat(), "MonthLabel": start.strftime("%b %Y"),
                "ScanCount": scan_months.get((rel["releaseId"], scan_type, start), 0),
                "IsCurrentSnapshot": "Yes" if n == len(periods) - 1 else "No",
            })
            for k in ("Detected", "Remediated", "FalsePositive", "RiskAccepted", "TotalBacklog"):
                r[k] = 0
            for s in SEV:
                r[f"Open_{s}"] = r[f"Debt_{s}"] = r[f"Resolved_{s}"] = 0
            for b in BUCKETS:
                r[f"Age_{b}"] = r[f"ExcActive_{b}"] = r[f"ExcExpired_{b}"] = 0

            for i in items:
                sev = i.get("severityString")
                if sev not in SEV:
                    continue                       # Info / Best_Practice excluded
                intro, closed = d(i.get("introducedDate")), d(i.get("closedDate"))
                g, x = grant.get(i["instanceId"]), expiry.get(i["instanceId"])

                if intro and start <= intro <= end:
                    r["Detected"] += 1
                if closed and start <= closed <= end:
                    key = ("FalsePositive" if i.get("auditorStatus") in RESOLVED_STATUSES
                           else "Remediated")
                    r[key] += 1
                if g and start <= g <= end:
                    r["RiskAccepted"] += 1

                state = classify(i, end, grant)
                if state is None:
                    continue
                r[f"{state}_{sev}"] += 1
                if state == "Open":
                    r["TotalBacklog"] += 1
                    r[f"Age_{age_bucket((end - intro).days)}"] += 1
                elif state == "Debt" and x:
                    days = (x - end).days
                    prefix = "ExcActive" if days >= 0 else "ExcExpired"
                    r[f"{prefix}_{expiry_bucket(days)}"] += 1
            yield r


def scan_rows(scans, rel_index, extracted_at):
    for s in scans:
        rel = rel_index.get(s.get("releaseId"))
        if rel is None:
            continue                                # not a production release
        label = SCAN_LABEL.get(s.get("scanType"))
        if label is None:
            continue
        started, completed = s.get("startedDateTime"), s.get("completedDateTime")
        dur = ""
        if started and completed:
            try:
                a = dt.datetime.fromisoformat(started[:19])
                b = dt.datetime.fromisoformat(completed[:19])
                dur = round((b - a).total_seconds() / 3600, 2)
            except ValueError:
                pass
        r = blank_row(extracted_at, "Scan")
        r.update(rel["_dims"])
        r.update({
            "ScanType": label,
            "ApplicationId": s.get("applicationId"), "ApplicationName": s.get("applicationName"),
            "ReleaseId": s.get("releaseId"), "ReleaseName": s.get("releaseName"),
            "SDLCStatus": rel.get("sdlcStatusType"),
            "Suspended": "Yes" if rel.get("suspended") else "No",
            "StarRating": s.get("starRating", ""),
            "ScanId": s.get("scanId"), "AssessmentTypeName": s.get("assessmentTypeName"),
            "AnalysisStatusType": s.get("analysisStatusType"),
            "StartedDateTime": started or "", "CompletedDateTime": completed or "",
            "ScanDurationHours": dur,
            "ScanMonth": (completed or started or "")[:7] + "-01" if (completed or started) else "",
            "TotalIssues": s.get("totalIssues", ""),
            "IssueCountCritical": s.get("issueCountCritical", ""),
            "IssueCountHigh": s.get("issueCountHigh", ""),
            "IssueCountMedium": s.get("issueCountMedium", ""),
            "IssueCountLow": s.get("issueCountLow", ""),
            "ScanMethodTypeName": s.get("scanMethodTypeName", ""),
            "ScanTool": s.get("scanTool", ""), "ScanToolVersion": s.get("scanToolVersion", ""),
            "IsRemediationScan": "Yes" if s.get("isRemediationScan") else "No",
            "EntitlementUnitsConsumed": s.get("entitlementUnitsConsumed", ""),
            "StartedByUserName": s.get("startedByUserName", ""),
        })
        yield r


def fetch_scans(periods):
    """Tenant-wide scan history, one windowed call per month. Far cheaper than
    looping releases (12 calls rather than two per release)."""
    out = []
    for start, end in periods:
        got = rest_paged("/api/v3/scans"
                         f"?completedOnStartDate={start.isoformat()}"
                         f"&completedOnEndDate={end.isoformat()}")
        LOG.info("  scans %s: %d", start.strftime("%b %Y"), len(got))
        out += got
    return out


# -------------------------------------------------------------------------- pipeline
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="appsec_dashboard_latest.csv")
    ap.add_argument("--months", type=int, default=12)
    ap.add_argument("--max-failures", type=int, default=5,
                    help="per-release failures tolerated before exiting 2")
    ap.add_argument("--skip-scans", action="store_true")
    ap.add_argument("--limit-releases", type=int, default=0, help="smoke test")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(message)s")
    today = dt.date.today()
    extracted_at = dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    periods = month_periods(args.months, today)
    t0 = time.time()

    sessions = fcli("fod", "session", "list")
    if not any(s.get("expired") == "No" for s in sessions):
        LOG.error("no active fcli FoD session. Run: fcli fod session login ...")
        return 1

    releases = fcli("fod", "release", "list",
                    "--query", "sdlcStatusType=='Production' && suspended==false", "-o", "json")
    if args.limit_releases:
        releases = releases[:args.limit_releases]
    LOG.info("%d production releases", len(releases))

    apps = {a["applicationId"]: a for a in fcli("fod", "app", "list", "-o", "json")}
    for rel in releases:
        app = apps.get(rel["applicationId"], {})
        dims = attributes_of(app)
        for k, v in attributes_of(rel).items():
            if v:                                   # release attribute wins only if set
                dims[k] = v
        dims["BusinessCriticality"] = app.get("businessCriticalityType", "")
        rel["_dims"] = dims
    rel_index = {r["releaseId"]: r for r in releases}

    scan_months, scans = defaultdict(int), []
    if not args.skip_scans:
        scans = fetch_scans(periods)
        for s in scans:
            label = SCAN_LABEL.get(s.get("scanType"))
            when = (s.get("completedDateTime") or s.get("startedDateTime") or "")[:10]
            if label and when and s.get("releaseId") in rel_index:
                scan_months[(s["releaseId"], label, d(when).replace(day=1))] += 1

    tmp = args.out + ".tmp"
    written, failures = 0, []
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()

        for n, rel in enumerate(releases, 1):
            rid = rel["releaseId"]
            try:
                issues = fcli("fod", "issue", "list", f"--rel={rid}",
                              "--include=visible,suppressed,fixed", "-o", "json")
                grant, expiry, n_acc = exception_dates(rid, issues)
                for row in monthly_rows(rel, rel["_dims"], issues, grant, expiry,
                                        periods, extracted_at, scan_months):
                    w.writerow(row); written += 1
                LOG.info("[%d/%d] release %s %-28s %5d issues, %3d exceptions",
                         n, len(releases), rid, rel["releaseName"][:28], len(issues), n_acc)
            except FcliError as e:
                failures.append((rid, str(e)))
                LOG.error("[%d/%d] release %s FAILED: %s", n, len(releases), rid, e)
            # issues discarded here: memory stays flat regardless of portfolio size

        for row in scan_rows(scans, rel_index, extracted_at):
            w.writerow(row); written += 1

    os.replace(tmp, args.out)                       # atomic: no half-written file
    LOG.info("%d rows -> %s (%.1f MB) in %.0f s",
             written, args.out, os.path.getsize(args.out) / 1e6, time.time() - t0)

    if failures:
        LOG.error("%d releases failed: %s", len(failures), [f[0] for f in failures])
        if len(failures) > args.max_failures:
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())