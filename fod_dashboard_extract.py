#!/usr/bin/env python3
"""
AppSec dashboard extract: Fortify on Demand -> two CSVs for Power BI.

    --out         one row per release x scan type x month  (tiles, ageing, trend)
    --scans-out   one row per scan                          (scan history)
                  default: <out>_scans.csv; not written with --skip-scans

Both carry ApplicationId/ReleaseId/ScanType and the dimension columns, so they
join in the Power BI model.

FoD stores no historical state. It stores enough DATES to rebuild it:
    introducedDate  first seen                      (issue list)
    closedDate      fixed / not-an-issue            (issue list)
    debt periods    in/out of Risk Accepted         (/history, historyType=Audit)
    expiry date     EXP:yyyy-mm-dd in an audit comment

Every finding is classified at every month end from those dates.

    python3 fod_dashboard_extract.py --out appsec_dashboard_latest.csv
    python3 fod_dashboard_extract.py --scan-type SAST     # SAST only (or DAST)
    python3 fod_dashboard_extract.py --limit-releases 2   # smoke test -> test.csv, test_scans.csv

Only applications listed in dashboard_apps.csv are reported (gradual rollout), and
its filled-in dimension cells override FoD attributes. --apps-file picks another
list, --all-apps reports every application with FoD attributes only.

Only Production releases are reported; --all-releases adds every other SDLC status
(QA, Development, Retired). Suspended releases are always left out.

Exit codes: 0 ok, 1 fatal, 2 completed with per-release failures over the threshold.
"""
import argparse, csv, json, logging, os, re, subprocess, sys, time
import datetime as dt
from collections import defaultdict

LOG = logging.getLogger("extract")

SEV = ("Critical", "High", "Medium", "Low")
BUCKETS = ("0_14", "15_60", "61_90", "90Plus")

# Tenant-configurable; there is no lookup API for them. List those in use with:
#   fcli fod issue list --rel=<id> --include=visible,suppressed,fixed -o 'expr={auditorStatus}\n' | sort -u
OPEN_STATUSES = {"Pending Review", "Remediation Required", "Remediation Deferred",
                 "Risk Mitigated", "Suspicious"}
DEBT_STATUSES = {"Risk Accepted"}
RESOLVED_STATUSES = {"Not an Issue"}
ALL_STATUSES = OPEN_STATUSES | DEBT_STATUSES | RESOLVED_STATUSES

SCAN_LABEL = {"Static": "SAST", "Dynamic": "DAST"}   # OpenSource/Mobile out of scope
# Release field holding the latest scan of each type; set even when it found nothing.
RELEASE_SCAN_DATE = {"Static": "staticScanDate", "Dynamic": "dynamicScanDate"}

STATUS_RE = re.compile(r"Changed Auditor Status from '.*?' to '(.*?)'")
EXPIRY_RE = re.compile(r"EXP:(\d{4}-\d{2}-\d{2})")

COMMON_COLUMNS = [
    "ExtractedAt", "ScanType", "ApplicationId", "ApplicationName",
    "ReleaseId", "ReleaseName", "SDLCStatus", "Suspended",
    "StarRating", "Region", "Platform", "ValueStream", "InternalExternal",
]
MONTHLY_COLUMNS = COMMON_COLUMNS + [
    "LastScanDate", "MonthStartDate", "MonthLabel", "ScanCount", "IsCurrentSnapshot",
    "Detected", "Remediated", "FalsePositive", "RiskAccepted", "TotalBacklog",
    *[f"Open_{s}" for s in SEV], *[f"Debt_{s}" for s in SEV], *[f"Resolved_{s}" for s in SEV],
    *[f"Age_{b}" for b in BUCKETS],
    *[f"ExcActive_{b}" for b in BUCKETS], *[f"ExcExpired_{b}" for b in BUCKETS],
]
SCAN_COLUMNS = COMMON_COLUMNS + [
    "ScanId", "AssessmentTypeName", "AnalysisStatusType", "StartedDateTime",
    "CompletedDateTime", "ScanDurationHours", "ScanDate", "TotalIssues",
    "IssueCountCritical", "IssueCountHigh", "IssueCountMedium", "IssueCountLow",
    "ScanMethodTypeName", "ScanTool", "ScanToolVersion", "IsRemediationScan",
    "EntitlementUnitsConsumed", "StartedByUserName",
]

# Tenant attributes carrying the dashboard's dimension filters. Confirm the exact
# names with: fcli fod attribute list -o json
ATTRIBUTE_MAP = {"Region": "Region", "Platform": "Platform",
                 "Value Stream": "ValueStream", "Internal/External": "InternalExternal"}
DIM_COLUMNS = tuple(ATTRIBUTE_MAP.values())     # the dashboard's filter columns

# Rollout list: the applications the dashboard reports on, plus dimension values the
# tenant doesn't hold yet. Lives next to the script so the pipeline finds it
# regardless of working directory.
APPS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard_apps.csv")
APPS_KEYS = ("ApplicationId", "ApplicationName")
APPS_IGNORED = ("Notes",)


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
    """GET a FoD endpoint. fcli loads every page itself (FoD caps limit at 50)."""
    return fcli("fod", "rest", "call", "-X", "GET", path, "-o", "json", retries=retries)


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


def selected_scan_types(only=None):
    """{FoD scanType: label} for the run. `only` is a label (SAST/DAST) or None for all."""
    return {k: v for k, v in SCAN_LABEL.items() if only in (None, v)}


def load_app_list(path):
    """Rollout list rows as [(line, id, name, {dimension: value})].

    CSV (Excel's UTF-8 BOM is fine) with an ApplicationId and/or ApplicationName
    column, any of DIM_COLUMNS, and an ignored Notes column. A row is matched on
    ApplicationId when set, else on ApplicationName (case-insensitive, surrounding
    spaces ignored). Blank dimension cells leave the FoD value in place."""
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        header = [h.strip() for h in next(reader, [])]
        unknown = [h for h in header if h not in (*APPS_KEYS, *DIM_COLUMNS, *APPS_IGNORED)]
        if unknown:
            raise ValueError(f"unknown columns {unknown}; allowed: "
                             f"{[*APPS_KEYS, *DIM_COLUMNS, *APPS_IGNORED]}")
        if not set(APPS_KEYS) & set(header):
            raise ValueError("needs an ApplicationName or ApplicationId column")
        rows = []
        for cells in reader:
            row = {h: c.strip() for h, c in zip(header, cells)}
            if not any(row.values()):
                continue                            # blank line, or Excel's ",,,,"
            n = reader.line_num
            aid, name = row.get("ApplicationId", ""), row.get("ApplicationName", "")
            if not aid and not name:
                raise ValueError(f"line {n}: no ApplicationId or ApplicationName")
            try:
                aid = int(aid) if aid else None
            except ValueError:
                raise ValueError(f"line {n}: bad ApplicationId {aid!r}") from None
            rows.append((n, aid, name, {k: row[k] for k in DIM_COLUMNS if row.get(k)}))
    return rows


def select_apps(apps, rows):
    """({application id: dimension overrides}, [rows that matched nothing])."""
    by_name = {a["applicationName"].strip().lower(): aid for aid, a in apps.items()}
    keep, unmatched = {}, []
    for n, aid, name, dims in rows:
        hit = aid if aid is not None else by_name.get(name.lower())
        if hit not in apps:
            unmatched.append(f"line {n}: {aid if aid is not None else name}")
        elif hit in keep:
            raise ValueError(f"line {n}: {apps[hit]['applicationName']!r} is listed twice")
        else:
            keep[hit] = dims
    return keep, unmatched


def attributes_of(obj):
    out = {v: "" for v in ATTRIBUTE_MAP.values()}
    for a in (obj.get("attributes") or []):
        col = ATTRIBUTE_MAP.get(a.get("name"))
        if col:
            out[col] = a.get("value") or ""
    return out


def blank_row(extracted_at, columns):
    r = {c: "" for c in columns}
    r["ExtractedAt"] = extracted_at
    return r


# ------------------------------------------------------------------------ core logic
def debt_since(spans, when):
    """Start of the Risk Accepted span covering `when`, or None. Spans are
    (accepted, reverted-or-None) pairs from audit_dates()."""
    for start, stop in spans:
        if start <= when and (stop is None or when < stop):
            return start
    return None


def classify(issue, when, grant):
    """Which bucket was this finding in, as at `when`? None if it did not exist."""
    intro = d(issue.get("introducedDate"))
    if intro is None or intro > when:
        return None
    closed = closed_on(issue)
    if closed and closed <= when:
        return "Resolved"
    status = issue.get("auditorStatus")
    if status not in ALL_STATUSES:
        raise FcliError(f"unmapped auditorStatus {status!r} (add it to the status sets)")
    if debt_since(grant.get(issue["instanceId"], ()), when):
        return "Debt"
    return "Open"


def closed_on(issue):
    """Date the finding left the backlog: FoD's closedDate, or for a resolved status
    FoD never closes (Not an Issue) the date audit_dates() found."""
    return d(issue.get("closedDate")) or issue.get("_resolvedOn")


def audit_dates(release_id, issues, window_start):
    """Dates FoD only keeps in audit history.

    grant:  {instanceId: [(accepted, reverted or None), ...]} for findings now Risk
            Accepted, replayed from every status change so an undone-then-redone
            acceptance leaves the gap as Open
    expiry: {instanceId: EXP: date from a comment}
    Also stores _resolvedOn on unclosed Not an Issue findings."""
    for i in issues:
        if i.get("auditorStatus") not in RESOLVED_STATUSES or i.get("closedDate"):
            continue
        # The status change bumps lastModifiedDate, so it happened on or before it:
        # history is only needed when that falls inside the reporting window.
        modified = d(i.get("lastModifiedDate"))
        i["_resolvedOn"] = modified or d(i.get("introducedDate"))
        if modified is None or modified < window_start:
            continue
        try:
            changes = [d(ev["historyDateTime"])
                       for ev in rest(f"/api/v3/releases/{release_id}/vulnerabilities/"
                                      f"{i['vulnId']}/history")
                       if ev.get("historyType") == "Audit"
                       and (m := STATUS_RE.search(ev.get("content", "")))
                       and m.group(1) in RESOLVED_STATUSES]
            if changes:
                i["_resolvedOn"] = max(changes)         # latest move into its current status
        except FcliError as e:
            LOG.warning("resolution date failed for %s, using last modified: %s",
                        i["instanceId"], e)

    grant, expiry = {}, {}
    accepted = [i for i in issues if i.get("auditorStatus") in DEBT_STATUSES]
    for i in accepted:
        iid, vid = i["instanceId"], i["vulnId"]
        try:
            spans, start = [], None
            history = rest(f"/api/v3/releases/{release_id}/vulnerabilities/{vid}/history")
            for ev in sorted(history, key=lambda e: e.get("historyDateTime") or ""):
                m = (ev.get("historyType") == "Audit"
                     and STATUS_RE.search(ev.get("content", "")))
                if not m or not ev.get("historyDateTime"):
                    continue
                day = d(ev["historyDateTime"])
                if m.group(1) in DEBT_STATUSES:
                    start = start or day
                elif start:
                    spans.append((start, day)); start = None
            if start:
                spans.append((start, None))
                grant[iid] = spans
            if i.get("hasComments"):
                for c in rest(f"/api/v3/releases/{release_id}/vulnerabilities/{vid}/comments"):
                    m = EXPIRY_RE.search(c.get("comment") or "")
                    if m:
                        try:
                            expiry[iid] = d(m.group(1))
                        except ValueError:          # e.g. EXP:2026-13-45: treated as no expiry
                            LOG.warning("invalid expiry %r on %s ignored", m.group(0), iid)
        except FcliError as e:
            LOG.warning("exception detail failed for %s: %s", iid, e)
        if iid not in grant:
            # Risk Accepted now, but no acceptance in history (call failed, or worded
            # differently): accepted by its last modification at the latest
            since = d(i.get("lastModifiedDate")) or d(i.get("introducedDate"))
            LOG.warning("no acceptance date in history for %s, using %s", iid, since)
            grant[iid] = [(since, None)]
    return grant, expiry, len(accepted)


def monthly_rows(rel, dims, issues, grant, expiry, periods, extracted_at, scan_months,
                 scan_types):
    by_scan = defaultdict(list)
    for fod_type, label in scan_types.items():
        if rel.get(RELEASE_SCAN_DATE[fod_type]):
            by_scan[label] = []                     # scanned clean still gets (zero) rows
    for i in issues:
        label = scan_types.get(i.get("scantype") or i.get("scanType"))
        if label:
            by_scan[label].append(i)

    rel_scan = {label: d(rel.get(RELEASE_SCAN_DATE[k])) for k, label in scan_types.items()}
    for scan_type, items in by_scan.items():
        dates = [d(i["scanCompletedDate"]) for i in items if i.get("scanCompletedDate")]
        if rel_scan[scan_type]:
            dates.append(rel_scan[scan_type])
        last_scan = max(dates, default=None)
        for n, (start, end) in enumerate(periods):
            r = blank_row(extracted_at, MONTHLY_COLUMNS)
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
                "ScanCount": ("" if scan_months is None     # --skip-scans: unknown, not 0
                              else scan_months.get((rel["releaseId"], scan_type, start), 0)),
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
                intro, closed = d(i.get("introducedDate")), closed_on(i)
                spans, x = grant.get(i["instanceId"], ()), expiry.get(i["instanceId"])

                if intro and start <= intro <= end:
                    r["Detected"] += 1
                if closed and start <= closed <= end:
                    key = ("FalsePositive" if i.get("auditorStatus") in RESOLVED_STATUSES
                           else "Remediated")
                    r[key] += 1
                if any(start <= a <= end for a, _ in spans):
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
                elif state == "Debt":
                    # no EXP: date: expired from the day it was (last) accepted
                    r[f"ExcExpired_{expiry_bucket((end - debt_since(spans, end)).days)}"] += 1
            yield r


def scan_rows(scans, rel_index, extracted_at, scan_types):
    for s in scans:
        rel = rel_index.get(s.get("releaseId"))
        if rel is None:
            continue                                # release not selected
        label = scan_types.get(s.get("scanType"))
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
        r = blank_row(extracted_at, SCAN_COLUMNS)
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
            "ScanDate": (completed or started or "")[:10],  # date only, for a Power BI date table
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
    """Scan history, one windowed call per month across everything the API key can
    see (FoD can't filter this endpoint by application). Scope the key to the
    rollout's applications to keep it small; scan_rows() drops the rest."""
    out = []
    for start, end in periods:
        got = rest("/api/v3/scans"
                   f"?completedOnStartDate={start.isoformat()}"
                   f"&completedOnEndDate={end.isoformat()}")
        LOG.info("  scans %s: %d", start.strftime("%b %Y"), len(got))
        out += got
    return out


# -------------------------------------------------------------------------- pipeline
class ArgParser(argparse.ArgumentParser):
    def error(self, message):
        """Usage errors are fatal (exit 1); argparse's default 2 means release failures here."""
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


def positive_int(s):
    n = int(s)
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be 1 or more, got {n}")
    return n


def main():
    ap = ArgParser()
    ap.add_argument("--out", help="default: test.csv with --limit-releases, "
                                  "else appsec_dashboard_latest.csv")
    ap.add_argument("--months", type=positive_int, default=6,
                    help="months of history incl. the current one (default: %(default)s)")
    ap.add_argument("--max-failures", type=int, default=5,
                    help="per-release failures tolerated before exiting 2")
    ap.add_argument("--scans-out", help="scan history CSV (default: <out>_scans.csv)")
    ap.add_argument("--skip-scans", action="store_true",
                    help="don't fetch scan history: no scans file, ScanCount left blank")
    ap.add_argument("--scan-type", choices=sorted(set(SCAN_LABEL.values())),
                    help="only extract this scan type (default: all)")
    ap.add_argument("--limit-releases", type=int, default=0, help="smoke test")
    ap.add_argument("--apps-file", default=APPS_FILE,
                    help="rollout list of applications to report (default: %(default)s)")
    ap.add_argument("--all-releases", action="store_true",
                    help="every SDLC status, not just Production (suspended still excluded)")
    ap.add_argument("--all-apps", action="store_true",
                    help="ignore the rollout list and report every application")
    args = ap.parse_args()
    if args.out is None:
        args.out = "test.csv" if args.limit_releases else "appsec_dashboard_latest.csv"
    if args.scans_out is None:
        base, ext = os.path.splitext(args.out)
        args.scans_out = f"{base}_scans{ext or '.csv'}"

    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(message)s")
    today = dt.date.today()
    extracted_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    periods = month_periods(args.months, today)
    scan_types = selected_scan_types(args.scan_type)
    t0 = time.time()

    sessions = fcli("fod", "session", "list", "-o", "json")
    if not any(s.get("expired") == "No" for s in sessions):
        LOG.error("no active fcli FoD session. Run: fcli fod session login ...")
        return 1

    query = "suspended==false" if args.all_releases else \
        "sdlcStatusType=='Production' && suspended==false"
    releases = fcli("fod", "release", "list", "--query", query, "-o", "json")
    kind = "active" if args.all_releases else "production"
    apps = {a["applicationId"]: a for a in fcli("fod", "app", "list", "-o", "json")}

    keep = {}
    if not args.all_apps:
        try:
            keep, unmatched = select_apps(apps, load_app_list(args.apps_file))
        except (OSError, ValueError, csv.Error) as e:
            LOG.error("cannot use app list %s: %s (--all-apps to report every application)",
                      args.apps_file, e)
            return 1
        if unmatched:
            LOG.warning("%d app list entries match no FoD application: %s",
                        len(unmatched), unmatched)
        releases = [r for r in releases if r["applicationId"] in keep]
        no_prod = keep.keys() - {r["applicationId"] for r in releases}
        if no_prod:
            LOG.warning("%d listed applications have no %s release: %s",
                        len(no_prod), kind, sorted(apps[a]["applicationName"] for a in no_prod))
        if not releases:                            # never publish an empty dashboard
            LOG.error("app list %s selects no %s releases", args.apps_file, kind)
            return 1
        LOG.info("app list %s: %d applications", args.apps_file, len(keep))

    if args.limit_releases:
        releases = releases[:args.limit_releases]
    LOG.info("%d %s releases, scan types: %s",
             len(releases), kind, ", ".join(scan_types.values()))

    for rel in releases:
        app = apps.get(rel["applicationId"], {})
        dims = attributes_of(app)
        for k, v in attributes_of(rel).items():
            if v:                                   # release attribute wins only if set
                dims[k] = v
        dims.update(keep.get(rel["applicationId"], {}))  # app list cells win when filled
        rel["_dims"] = dims
    rel_index = {r["releaseId"]: r for r in releases}

    scan_months, scans = None, []
    if not args.skip_scans:
        try:
            scans = fetch_scans(periods)
        except FcliError as e:
            LOG.error("scan history fetch failed: %s", e)
            return 1
        scan_months = defaultdict(int)
        for s in scans:
            label = scan_types.get(s.get("scanType"))
            when = (s.get("completedDateTime") or s.get("startedDateTime") or "")[:10]
            if label and when and s.get("releaseId") in rel_index:
                scan_months[(s["releaseId"], label, d(when).replace(day=1))] += 1

    tmp = args.out + ".tmp"
    written, failures = 0, []
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=MONTHLY_COLUMNS, extrasaction="ignore")
        w.writeheader()

        for n, rel in enumerate(releases, 1):
            rid = rel["releaseId"]
            try:
                cmd = ["fod", "issue", "list", f"--rel={rid}",
                       "--include=visible,suppressed,fixed", "-o", "json"]
                if len(scan_types) == 1:            # filter server side: fewer issues, fewer history calls
                    cmd.append(f"--filters-param=scantype:{next(iter(scan_types))}")
                issues = fcli(*cmd)
                grant, expiry, n_acc = audit_dates(rid, issues, periods[0][0])
                # all or nothing: a release that fails part way leaves no partial rows
                rows = list(monthly_rows(rel, rel["_dims"], issues, grant, expiry,
                                         periods, extracted_at, scan_months, scan_types))
                w.writerows(rows); written += len(rows)
                LOG.info("[%d/%d] release %s %-28s %5d issues, %3d exceptions",
                         n, len(releases), rid, rel["releaseName"][:28], len(issues), n_acc)
            except FcliError as e:
                failures.append((rid, str(e)))
                LOG.error("[%d/%d] release %s FAILED: %s", n, len(releases), rid, e)
            # issues discarded here: memory stays flat regardless of portfolio size

    os.replace(tmp, args.out)                       # atomic: no half-written file
    LOG.info("%d rows -> %s (%.1f MB)", written, args.out, os.path.getsize(args.out) / 1e6)

    if not args.skip_scans:
        tmp, n_scans = args.scans_out + ".tmp", 0
        with open(tmp, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=SCAN_COLUMNS, extrasaction="ignore")
            w.writeheader()
            for row in scan_rows(scans, rel_index, extracted_at, scan_types):
                w.writerow(row); n_scans += 1
        os.replace(tmp, args.scans_out)
        LOG.info("%d rows -> %s (%.1f MB)",
                 n_scans, args.scans_out, os.path.getsize(args.scans_out) / 1e6)
    LOG.info("done in %.0f s", time.time() - t0)

    if failures:
        LOG.error("%d releases failed: %s", len(failures), [f[0] for f in failures])
        if len(failures) > args.max_failures:
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())