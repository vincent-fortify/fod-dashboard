"""Offline tests for fod_dashboard_extract.py: no FoD session needed.

    python3 -m unittest -v test_fod_dashboard_extract

FoD is replaced by FakeFod (fcli is patched), so main() runs end to end on fixture
data. Tests marked expectedFailure document known defects; they start passing
(and unittest reports "unexpected success") once the defect is fixed.
"""
import csv, datetime as dt, logging, os, sys, tempfile, unittest
from unittest import mock

import fod_dashboard_extract as m

D = dt.date


def issue(iid, scantype="Static", sev="Critical", status="Pending Review", intro="2026-03-10",
          closed=None, modified=None, comments=False, scan_done=None):
    return {"instanceId": iid, "vulnId": f"v-{iid}", "scantype": scantype, "severityString": sev,
            "auditorStatus": status, "introducedDate": intro, "closedDate": closed,
            "lastModifiedDate": modified, "hasComments": comments, "scanCompletedDate": scan_done}


def audit(day, to_status):
    return {"historyType": "Audit", "historyDateTime": f"{day}T10:00:00",
            "content": f"Changed Auditor Status from 'Pending Review' to '{to_status}'"}


REL = {"releaseId": 1, "applicationId": 9, "applicationName": "App", "releaseName": "main",
       "sdlcStatusType": "Production", "suspended": False}
PERIODS = [(D(2026, 3, 1), D(2026, 3, 31)), (D(2026, 4, 1), D(2026, 4, 30)),
           (D(2026, 5, 1), D(2026, 5, 31))]
ALL_TYPES = m.selected_scan_types()


def rows(issues, grant=None, expiry=None, rel=None, scan_months=None, types=ALL_TYPES):
    return list(m.monthly_rows(rel or REL, {}, issues, grant or {}, expiry or {}, PERIODS,
                               "x", scan_months, types))


def by_month(rs, scan_type="SAST"):
    return {r["MonthStartDate"]: r for r in rs if r["ScanType"] == scan_type}


# ------------------------------------------------------------------------- helpers
class MonthPeriods(unittest.TestCase):
    def test_six_months_newest_ends_today(self):
        p = m.month_periods(6, D(2026, 10, 14))
        self.assertEqual(p[0], (D(2026, 5, 1), D(2026, 5, 31)))
        self.assertEqual(p[-1], (D(2026, 10, 1), D(2026, 10, 14)))
        self.assertEqual(len(p), 6)
        for (_, end), (start, _) in zip(p, p[1:]):        # contiguous, no gaps or overlaps
            self.assertEqual(end + dt.timedelta(days=1), start)

    def test_year_boundary(self):
        p = m.month_periods(4, D(2026, 2, 10))
        self.assertEqual([s for s, _ in p], [D(2025, 11, 1), D(2025, 12, 1), D(2026, 1, 1),
                                             D(2026, 2, 1)])
        self.assertEqual(p[1][1], D(2025, 12, 31))

    def test_leap_february(self):
        self.assertEqual(m.month_periods(2, D(2028, 3, 5))[0], (D(2028, 2, 1), D(2028, 2, 29)))

    def test_single_month(self):
        self.assertEqual(m.month_periods(1, D(2026, 10, 14)), [(D(2026, 10, 1), D(2026, 10, 14))])


class Buckets(unittest.TestCase):
    def test_age_boundaries(self):
        for days, b in ((0, "0_14"), (14, "0_14"), (15, "15_60"), (60, "15_60"),
                        (61, "61_90"), (90, "61_90"), (91, "90Plus")):
            self.assertEqual(m.age_bucket(days), b, days)

    def test_expiry_uses_distance_either_side(self):
        for days, b in ((14, "0_14"), (-14, "0_14"), (-15, "15_60"), (-91, "90Plus"), (61, "61_90")):
            self.assertEqual(m.expiry_bucket(days), b, days)


# ---------------------------------------------------------------------- classify
class Classify(unittest.TestCase):
    def test_not_yet_introduced(self):
        i = issue("a", intro="2026-04-10")
        self.assertIsNone(m.classify(i, D(2026, 4, 9), {}))
        self.assertEqual(m.classify(i, D(2026, 4, 10), {}), "Open")

    def test_closed_is_resolved_from_close_date(self):
        i = issue("a", closed="2026-04-15")
        self.assertEqual(m.classify(i, D(2026, 4, 14), {}), "Open")
        self.assertEqual(m.classify(i, D(2026, 4, 15), {}), "Resolved")

    def test_not_an_issue_resolved_from_audit_date(self):
        i = issue("a", status="Not an Issue")
        i["_resolvedOn"] = D(2026, 4, 20)
        self.assertEqual(m.classify(i, D(2026, 3, 31), {}), "Open")
        self.assertEqual(m.classify(i, D(2026, 4, 30), {}), "Resolved")

    def test_risk_accepted_is_debt_from_grant_until_closed(self):
        i = issue("a", status="Risk Accepted", closed="2026-05-10")
        grant = {"a": [(D(2026, 4, 5), None)]}
        self.assertEqual(m.classify(i, D(2026, 3, 31), grant), "Open")
        self.assertEqual(m.classify(i, D(2026, 4, 30), grant), "Debt")
        self.assertEqual(m.classify(i, D(2026, 5, 31), grant), "Resolved")

    def test_undone_acceptance_is_open_in_the_gap(self):
        i = issue("a", status="Risk Accepted")
        grant = {"a": [(D(2026, 3, 5), D(2026, 4, 1)), (D(2026, 5, 1), None)]}
        self.assertEqual([m.classify(i, e, grant) for _, e in PERIODS], ["Debt", "Open", "Debt"])
        self.assertEqual(m.classify(i, D(2026, 4, 1), grant), "Open")     # reverted that day

    def test_unmapped_status_fails_the_release(self):
        with self.assertRaises(m.FcliError):
            m.classify(issue("a", status="Brand New Status"), D(2026, 5, 31), {})


# ------------------------------------------------------------------- audit_dates
class AuditDates(unittest.TestCase):
    WINDOW = D(2026, 3, 1)

    def run_audit(self, issues, responses):
        calls = []

        def fake_rest(path, retries=4):
            calls.append(path)
            r = responses.get(path.rsplit("/", 2)[-2] + "/" + path.rsplit("/", 1)[-1], [])
            if isinstance(r, Exception):
                raise r
            return r
        with mock.patch.object(m, "rest", fake_rest):
            grant, expiry, n = m.audit_dates(1, issues, self.WINDOW)
        return grant, expiry, n, calls

    def test_not_an_issue_with_closed_date_needs_no_history(self):
        i = issue("a", status="Not an Issue", closed="2026-04-01", modified="2026-04-01")
        *_, calls = self.run_audit([i], {})
        self.assertEqual(calls, [])
        self.assertNotIn("_resolvedOn", i)

    def test_not_an_issue_modified_before_window_skips_history(self):
        i = issue("a", status="Not an Issue", intro="2025-01-01", modified="2025-06-01T00:00:00")
        *_, calls = self.run_audit([i], {})
        self.assertEqual(calls, [])
        self.assertEqual(i["_resolvedOn"], D(2025, 6, 1))

    def test_not_an_issue_takes_latest_move_into_status(self):
        i = issue("a", status="Not an Issue", modified="2026-05-02T00:00:00")
        hist = [audit("2026-03-05", "Not an Issue"), audit("2026-04-01", "Pending Review"),
                audit("2026-04-20", "Not an Issue"),
                {"historyType": "Comment", "historyDateTime": "2026-05-02T00:00:00", "content": "x"}]
        *_, calls = self.run_audit([i], {"v-a/history": hist})
        self.assertEqual(len(calls), 1)
        self.assertEqual(i["_resolvedOn"], D(2026, 4, 20))

    def test_not_an_issue_history_failure_falls_back_to_last_modified(self):
        i = issue("a", status="Not an Issue", modified="2026-05-02T00:00:00")
        with self.assertLogs("extract", "WARNING"):
            self.run_audit([i], {"v-a/history": m.FcliError("boom")})
        self.assertEqual(i["_resolvedOn"], D(2026, 5, 2))

    def test_not_an_issue_without_last_modified_uses_introduced(self):
        i = issue("a", status="Not an Issue", intro="2026-03-10")
        *_, calls = self.run_audit([i], {})
        self.assertEqual((calls, i["_resolvedOn"]), ([], D(2026, 3, 10)))

    def test_grant_and_expiry(self):
        i = issue("a", status="Risk Accepted", comments=True)
        grant, expiry, n, _ = self.run_audit([i], {
            "v-a/history": [audit("2026-04-05", "Risk Accepted")],
            "v-a/comments": [{"comment": "approved by CISO. EXP:2026-11-01"}]})
        self.assertEqual((grant, expiry, n), ({"a": [(D(2026, 4, 5), None)]}, {"a": D(2026, 11, 1)}, 1))

    def test_comments_only_fetched_when_present(self):
        i = issue("a", status="Risk Accepted", comments=False)
        *_, calls = self.run_audit([i], {"v-a/history": [audit("2026-04-05", "Risk Accepted")]})
        self.assertEqual([c.rsplit("/", 1)[-1] for c in calls], ["history"])

    def test_expiry_format_is_strict(self):
        i = issue("a", status="Risk Accepted", comments=True)
        for text in ("exp:2026-11-01", "EXP: 2026-11-01", "EXP:1/11/2026"):
            _, expiry, _, _ = self.run_audit([i], {
                "v-a/history": [audit("2026-04-05", "Risk Accepted")],
                "v-a/comments": [{"comment": text}]})
            self.assertEqual(expiry, {}, text)

    def test_acceptance_replayed_from_every_change(self):
        i = issue("a", status="Risk Accepted")
        grant, *_ = self.run_audit([i], {"v-a/history": [          # API order isn't trusted
            audit("2026-05-01", "Risk Accepted"), audit("2026-03-05", "Risk Accepted"),
            audit("2026-04-01", "Pending Review"), audit("2026-03-20", "Risk Accepted")]})
        self.assertEqual(grant["a"], [(D(2026, 3, 5), D(2026, 4, 1)), (D(2026, 5, 1), None)])

    def test_no_acceptance_in_history_falls_back_to_last_modified(self):
        for hist in (m.FcliError("boom"), [audit("2026-04-05", "Pending Review")]):
            i = issue("a", status="Risk Accepted", modified="2026-04-09T00:00:00")
            with self.assertLogs("extract", "WARNING"):
                grant, *_ = self.run_audit([i], {"v-a/history": hist})
            self.assertEqual(grant["a"], [(D(2026, 4, 9), None)], hist)

    def test_invalid_expiry_date_is_ignored_with_warning(self):
        # EXP:2026-13-45 matches the pattern but isn't a date: treated as no expiry
        i = issue("a", status="Risk Accepted", comments=True)
        with self.assertLogs("extract", "WARNING"):
            _, expiry, _, _ = self.run_audit([i], {
                "v-a/history": [audit("2026-04-05", "Risk Accepted")],
                "v-a/comments": [{"comment": "EXP:2026-13-45"}]})
        self.assertEqual(expiry, {})


# ------------------------------------------------------------------ monthly_rows
class MonthlyRows(unittest.TestCase):
    def assert_consistent(self, rs, issues):
        for r in rs:
            end = dict(PERIODS)[D.fromisoformat(r["MonthStartDate"])]
            existing = sum(1 for i in issues
                           if i["severityString"] in m.SEV
                           and m.SCAN_LABEL.get(i["scantype"]) == r["ScanType"]
                           and D.fromisoformat(i["introducedDate"]) <= end)
            open_, debt, res = (sum(r[f"{k}_{s}"] for s in m.SEV)
                                for k in ("Open", "Debt", "Resolved"))
            self.assertEqual(open_ + debt + res, existing, r["MonthStartDate"])
            self.assertEqual(r["TotalBacklog"], open_)
            self.assertEqual(sum(r[f"Age_{b}"] for b in m.BUCKETS), open_)
            self.assertEqual(sum(r[f"ExcActive_{b}"] + r[f"ExcExpired_{b}"] for b in m.BUCKETS), debt)

    def test_flows_land_in_the_right_month(self):
        nai = issue("n", status="Not an Issue", intro="2026-03-02")
        nai["_resolvedOn"] = D(2026, 5, 3)
        iss = [issue("o", intro="2026-03-10"),
               issue("f", intro="2026-03-12", closed="2026-04-15"),
               issue("r", status="Risk Accepted", intro="2026-04-01"),
               nai]
        rs = rows(iss, grant={"r": [(D(2026, 4, 20), None)]})
        mo = by_month(rs)
        self.assertEqual([mo[k]["Detected"] for k in sorted(mo)], [3, 1, 0])
        self.assertEqual([mo[k]["Remediated"] for k in sorted(mo)], [0, 1, 0])
        self.assertEqual([mo[k]["RiskAccepted"] for k in sorted(mo)], [0, 1, 0])
        self.assertEqual([mo[k]["FalsePositive"] for k in sorted(mo)], [0, 0, 1])
        self.assertEqual([mo[k]["TotalBacklog"] for k in sorted(mo)], [3, 2, 1])
        self.assert_consistent(rs, iss)

    def test_ageing_at_month_end(self):
        mo = by_month(rows([issue("a", intro="2026-03-20")]))
        self.assertEqual(mo["2026-03-01"]["Age_0_14"], 1)      # 11 days
        self.assertEqual(mo["2026-04-01"]["Age_15_60"], 1)     # 41 days
        self.assertEqual(mo["2026-05-01"]["Age_61_90"], 1)     # 72 days

    def test_exception_expiry_buckets(self):
        iss = [issue(k, status="Risk Accepted", intro="2026-03-01") for k in ("fut", "past", "none")]
        grant = {k: [(D(2026, 3, 1), None)] for k in ("fut", "past", "none")}
        rs = rows(iss, grant, {"fut": D(2026, 12, 31), "past": D(2026, 4, 10)})
        mo = by_month(rs)
        self.assertEqual((mo["2026-03-01"]["ExcActive_0_14"], mo["2026-03-01"]["ExcActive_90Plus"],
                          mo["2026-03-01"]["ExcExpired_15_60"]), (1, 1, 1))
        self.assertEqual((mo["2026-05-01"]["ExcExpired_15_60"], mo["2026-05-01"]["ExcExpired_90Plus"]),
                         (1, 1))                                 # past: 21 days; none: 91 days
        self.assert_consistent(rs, iss)

    def test_undone_acceptance_rows(self):
        iss = [issue("a", status="Risk Accepted", intro="2026-03-01")]
        rs = rows(iss, grant={"a": [(D(2026, 3, 5), D(2026, 4, 1)), (D(2026, 5, 1), None)]})
        mo = by_month(rs)
        self.assertEqual([mo[k]["Debt_Critical"] for k in sorted(mo)], [1, 0, 1])
        self.assertEqual([mo[k]["Open_Critical"] for k in sorted(mo)], [0, 1, 0])
        self.assertEqual([mo[k]["RiskAccepted"] for k in sorted(mo)], [1, 0, 1])
        self.assertEqual(mo["2026-05-01"]["ExcExpired_15_60"], 1)   # no expiry: 30 days since re-acceptance
        self.assert_consistent(rs, iss)

    def test_info_findings_count_as_scanned_clean(self):
        rs = rows([issue("i", sev="Info"), issue("b", sev="Best Practice")])
        self.assertEqual({r["ScanType"] for r in rs}, {"SAST"})
        self.assertTrue(all(r["Detected"] == r["TotalBacklog"] == 0 for r in rs))

    def test_open_source_and_mobile_ignored(self):
        self.assertEqual(rows([issue("o", scantype="OpenSource"), issue("m", scantype="Mobile")]), [])

    def test_scanned_clean_release_gets_zero_rows(self):
        rs = rows([], rel={**REL, "staticScanDate": "2025-01-05T00:00:00"})
        self.assertEqual([r["ScanType"] for r in rs], ["SAST"] * 3)
        self.assertTrue(all(r["TotalBacklog"] == 0 and r["Detected"] == 0 for r in rs))
        self.assertEqual(rs[0]["LastScanDate"], "2025-01-05")

    def test_never_scanned_release_gets_no_rows(self):
        self.assertEqual(rows([]), [])

    def test_clean_type_alongside_type_with_findings(self):
        rs = rows([issue("d", scantype="Dynamic")], rel={**REL, "staticScanDate": "2026-01-01"})
        self.assertEqual(sorted({r["ScanType"] for r in rs}), ["DAST", "SAST"])

    def test_scan_type_filter(self):
        rs = rows([issue("s"), issue("d", scantype="Dynamic")], rel={**REL, "dynamicScanDate": "2026-01-01"},
                  types=m.selected_scan_types("SAST"))
        self.assertEqual({r["ScanType"] for r in rs}, {"SAST"})

    def test_snapshot_flag_labels_and_scan_count(self):
        rs = rows([issue("a")], scan_months={(1, "SAST", D(2026, 4, 1)): 2})
        self.assertEqual([r["IsCurrentSnapshot"] for r in rs], ["No", "No", "Yes"])
        self.assertEqual([r["MonthLabel"] for r in rs], ["Mar 2026", "Apr 2026", "May 2026"])
        self.assertEqual([r["ScanCount"] for r in rs], [0, 2, 0])
        self.assertEqual({r["ScanCount"] for r in rows([issue("a")])}, {""})   # --skip-scans

    def test_last_scan_date_is_latest_of_issue_and_release(self):
        rel = {**REL, "staticScanDate": "2026-04-02T00:00:00"}
        rs = rows([issue("a", scan_done="2026-03-15T00:00:00")], rel=rel)
        self.assertEqual(rs[0]["LastScanDate"], "2026-04-02")

    def test_unmapped_status_raises(self):
        with self.assertRaises(m.FcliError):
            rows([issue("a", status="Brand New Status")])


# --------------------------------------------------------------------- scan_rows
class ScanRows(unittest.TestCase):
    REL_INDEX = {1: {**REL, "_dims": {"Region": "APAC"}}}

    def scan(self, **kw):
        return {"releaseId": 1, "scanType": "Static", "scanId": 5,
                "startedDateTime": "2026-06-01T03:00:00", "completedDateTime": "2026-06-01T04:30:00", **kw}

    def out(self, scans, types=ALL_TYPES):
        return list(m.scan_rows(scans, self.REL_INDEX, "x", types))

    def test_basic_fields(self):
        r, = self.out([self.scan()])
        self.assertEqual((r["ScanType"], r["ScanDurationHours"], r["ScanDate"], r["Region"]),
                         ("SAST", 1.5, "2026-06-01", "APAC"))

    def test_filters(self):
        self.assertEqual(self.out([self.scan(releaseId=2), self.scan(scanType="OpenSource")]), [])
        self.assertEqual(self.out([self.scan()], m.selected_scan_types("DAST")), [])

    def test_incomplete_and_bad_dates(self):
        r, = self.out([self.scan(completedDateTime=None)])
        self.assertEqual((r["ScanDate"], r["ScanDurationHours"]), ("2026-06-01", ""))
        r, = self.out([self.scan(completedDateTime="garbage")])
        self.assertEqual(r["ScanDurationHours"], "")


# ---------------------------------------------------------------------- app list
class AppList(unittest.TestCase):
    APPS = {10: {"applicationName": "Juice Shop"}, 11: {"applicationName": "111"},
            111: {"applicationName": "Other"}, 12: {"applicationName": " eShop "}}

    def load(self, text, bom=False):
        with tempfile.NamedTemporaryFile("wb", suffix=".csv", delete=False) as f:
            f.write((b"\xef\xbb\xbf" if bom else b"") + text.encode())
        self.addCleanup(os.unlink, f.name)
        return m.load_app_list(f.name)

    def test_excel_file_with_bom_blank_rows_and_notes(self):
        rows_ = self.load("ApplicationName,ApplicationId,Region,Notes\r\n"
                          "  juice SHOP ,,APAC,wave 1\r\n,,,\r\n111,,,\r\n,111,EMEA,\r\neshop,,,\r\n", bom=True)
        keep, unmatched = m.select_apps(self.APPS, rows_)
        self.assertEqual(keep, {10: {"Region": "APAC"}, 11: {}, 111: {"Region": "EMEA"}, 12: {}})
        self.assertEqual(unmatched, [])

    def test_unmatched_entries_are_reported(self):
        keep, unmatched = m.select_apps(self.APPS, self.load("ApplicationName\nNope\n"))
        self.assertEqual((keep, unmatched), ({}, ["line 2: Nope"]))

    def test_errors(self):
        for text, msg in (("ApplicationName,Value Stream\nA,B\n", "unknown columns"),
                          ("Region\nAPAC\n", "needs an ApplicationName"),
                          ("ApplicationId\nabc\n", "bad ApplicationId"),
                          ("ApplicationName,Region\n,APAC\n", "no ApplicationId or ApplicationName")):
            with self.assertRaisesRegex(ValueError, msg):
                self.load(text)
        with self.assertRaisesRegex(ValueError, "listed twice"):
            m.select_apps(self.APPS, self.load("ApplicationName,ApplicationId\nJuice Shop,\n,10\n"))

    def test_attributes_of(self):
        obj = {"attributes": [{"name": "Region", "value": "APAC"}, {"name": "Value Stream", "value": "Claims"},
                              {"name": "Unrelated", "value": "x"}]}
        self.assertEqual(m.attributes_of(obj), {"Region": "APAC", "Platform": "", "ValueStream": "Claims",
                                                "InternalExternal": ""})


# ------------------------------------------------------------- main, end to end
TODAY = D.today()


def ago(days):
    return (TODAY - dt.timedelta(days=days)).isoformat()


class FakeFod:
    """Answers the fcli calls main() makes, from fixture data."""
    def __init__(self):
        self.apps = [
            {"applicationId": 1, "applicationName": "Alpha", "attributes": [{"name": "Region", "value": "EMEA"}]},
            {"applicationId": 2, "applicationName": "Beta", "attributes": []},
            {"applicationId": 3, "applicationName": "Gamma", "attributes": []},
            {"applicationId": 4, "applicationName": "Delta", "attributes": []}]
        rel = lambda rid, aid, name, sdlc, **kw: {"releaseId": rid, "applicationId": aid, "applicationName": name,
                                                   "releaseName": f"r{rid}", "sdlcStatusType": sdlc,
                                                   "suspended": False, **kw}
        self.releases = [rel(10, 1, "Alpha", "Production"), rel(11, 1, "Alpha", "QA"),
                         rel(20, 2, "Beta", "Production", staticScanDate=ago(30)),   # scanned clean
                         rel(30, 3, "Gamma", "Production"), rel(40, 4, "Delta", "QA")]
        self.issues = {10: [issue("a1", intro=ago(40)), issue("a2", scantype="Dynamic", intro=ago(40)),
                            issue("a3", scantype="OpenSource", intro=ago(40))],
                       11: [issue("q1", intro=ago(40))], 20: [], 30: [issue("g1", intro=ago(40))],
                       40: [issue("d1", intro=ago(40))]}
        self.scans = [{"releaseId": 10, "scanType": "Static", "scanId": 1, "startedDateTime": f"{ago(40)}T01:00:00",
                       "completedDateTime": f"{ago(40)}T02:00:00"},
                      {"releaseId": 10, "scanType": "OpenSource", "scanId": 2, "completedDateTime": f"{ago(40)}T02:00:00"},
                      {"releaseId": 30, "scanType": "Static", "scanId": 3, "completedDateTime": f"{ago(40)}T02:00:00"}]
        self.session_ok, self.fail_releases, self.fail_scans = True, set(), False
        self.calls = []

    def __call__(self, *args, retries=4):
        self.calls.append(args)
        if args[:3] == ("fod", "session", "list"):
            return [{"expired": "No" if self.session_ok else "Yes"}]
        if args[:3] == ("fod", "release", "list"):
            q = args[args.index("--query") + 1]
            return [dict(r) for r in self.releases if "Production" not in q or r["sdlcStatusType"] == "Production"]
        if args[:3] == ("fod", "app", "list"):
            return self.apps
        if args[:3] == ("fod", "issue", "list"):
            rid = int(next(a for a in args if a.startswith("--rel=")).split("=")[1])
            if rid in self.fail_releases:
                raise m.FcliError("issue list failed")
            only = next((a.split(":")[1] for a in args if a.startswith("--filters-param=scantype:")), None)
            return [dict(i) for i in self.issues[rid] if only in (None, i["scantype"])]
        if args[:3] == ("fod", "rest", "call"):
            path = args[5]
            if path.startswith("/api/v3/scans"):
                if self.fail_scans:
                    raise m.FcliError("scans failed")
                start = path.split("completedOnStartDate=")[1][:10]
                end = path.split("completedOnEndDate=")[1][:10]
                return [s for s in self.scans if start <= (s.get("completedDateTime") or "")[:10] <= end]
            return []
        raise AssertionError(f"unexpected fcli call {args}")


class EndToEnd(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.apps_csv = self.path("apps.csv")
        with open(self.apps_csv, "w") as f:
            f.write("ApplicationName,Region\nAlpha,APAC\nBeta,\n")
        self.fod = FakeFod()

    def path(self, name):
        return os.path.join(self.dir.name, name)

    def run_main(self, *argv, out="out.csv"):
        argv = ["x", "--apps-file", self.apps_csv, *argv]
        if out:
            argv += ["--out", self.path(out)]
        with mock.patch.object(m, "fcli", self.fod), mock.patch.object(sys, "argv", argv):
            return m.main()

    def read(self, name):
        with open(self.path(name), newline="") as f:
            return list(csv.DictReader(f))

    def groups(self, rs):
        return sorted({(int(r["ReleaseId"]), r["ScanType"]) for r in rs})

    def test_default_run(self):
        self.assertEqual(self.run_main(), 0)
        mo = self.read("out.csv")
        self.assertEqual(self.groups(mo), [(10, "DAST"), (10, "SAST"), (20, "SAST")])
        self.assertEqual(len(mo), 3 * 6)
        self.assertNotIn("RowType", mo[0])
        self.assertNotIn("BusinessCriticality", mo[0])
        self.assertEqual({r["Region"] for r in mo if r["ReleaseId"] == "10"}, {"APAC"})  # list beats FoD
        cur = [r for r in mo if r["IsCurrentSnapshot"] == "Yes" and r["ReleaseId"] == "10" and r["ScanType"] == "SAST"]
        self.assertEqual(cur[0]["TotalBacklog"], "1")
        scans = self.read("out_scans.csv")
        self.assertEqual([r["ScanId"] for r in scans], ["1"])           # not OpenSource, not Gamma
        self.assertEqual(sum(int(r["ScanCount"]) for r in mo), 1)

    def test_all_releases_adds_non_production(self):
        self.assertEqual(self.run_main("--all-releases"), 0)
        self.assertIn((11, "SAST"), self.groups(self.read("out.csv")))

    def test_all_apps_uses_fod_attributes(self):
        self.assertEqual(self.run_main("--all-apps"), 0)
        mo = self.read("out.csv")
        self.assertIn((30, "SAST"), self.groups(mo))
        self.assertEqual({r["Region"] for r in mo if r["ReleaseId"] == "10"}, {"EMEA"})
        self.assertEqual(sorted(r["ScanId"] for r in self.read("out_scans.csv")), ["1", "3"])

    def test_scan_type_filter_is_server_side(self):
        self.assertEqual(self.run_main("--scan-type", "SAST"), 0)
        self.assertEqual({r["ScanType"] for r in self.read("out.csv")}, {"SAST"})
        issue_calls = [c for c in self.fod.calls if c[:3] == ("fod", "issue", "list")]
        self.assertTrue(all("--filters-param=scantype:Static" in c for c in issue_calls))

    def test_skip_scans(self):
        self.assertEqual(self.run_main("--skip-scans"), 0)
        self.assertFalse(os.path.exists(self.path("out_scans.csv")))
        self.assertEqual({r["ScanCount"] for r in self.read("out.csv")}, {""})
        self.assertFalse(any(c[:3] == ("fod", "rest", "call") and "/api/v3/scans" in c[5] for c in self.fod.calls))

    def test_default_output_names(self):
        cwd = os.getcwd()
        os.chdir(self.dir.name)
        self.addCleanup(os.chdir, cwd)
        self.assertEqual(self.run_main("--limit-releases", "1", out=None), 0)
        self.assertTrue(os.path.exists("test.csv") and os.path.exists("test_scans.csv"))

    def test_no_session_is_fatal(self):
        self.fod.session_ok = False
        self.assertEqual(self.run_main(), 1)
        self.assertFalse(os.path.exists(self.path("out.csv")))

    def write_apps(self, content):
        with open(self.apps_csv, "w") as f:
            f.write(content)

    def test_missing_app_list_is_fatal(self):
        os.unlink(self.apps_csv)
        self.assertEqual(self.run_main("--skip-scans"), 1)

    def test_app_list_matching_nothing_is_fatal(self):
        self.write_apps("ApplicationName\nNobody\n")
        self.assertEqual(self.run_main("--skip-scans"), 1)
        self.assertFalse(os.path.exists(self.path("out.csv")))

    def test_listed_app_without_production_release(self):
        self.write_apps("ApplicationName\nDelta\n")                     # QA release only
        self.assertEqual(self.run_main("--skip-scans"), 1)
        self.assertEqual(self.run_main("--skip-scans", "--all-releases"), 0)

    def test_unmatched_entry_is_only_a_warning(self):
        self.write_apps("ApplicationName\nAlpha\nNobody\n")
        self.assertEqual(self.run_main("--skip-scans"), 0)

    def test_release_failures_and_threshold(self):
        self.fod.fail_releases = {20}
        self.assertEqual(self.run_main(), 0)                              # 1 failure <= 5
        self.assertEqual(self.run_main("--max-failures", "0"), 2)         # 1 failure > 0
        self.assertEqual(self.groups(self.read("out.csv")), [(10, "DAST"), (10, "SAST")])  # still written

    def test_scan_fetch_failure_is_fatal(self):
        self.fod.fail_scans = True
        self.assertEqual(self.run_main(), 1)

    def test_failed_release_leaves_no_partial_rows(self):
        # DAST findings hit an unmapped status after the SAST rows were built
        self.fod.issues[10][1]["auditorStatus"] = "Brand New Status"
        self.run_main("--skip-scans")
        self.assertNotIn("10", {r["ReleaseId"] for r in self.read("out.csv")})

    def test_bad_arguments_exit_1(self):
        for argv in (("--months", "0"), ("--months", "x"), ("--scan-type", "SCA")):
            with self.assertRaises(SystemExit) as e, mock.patch.object(sys, "stderr"):
                self.run_main(*argv, "--skip-scans")
            self.assertEqual(e.exception.code, 1, argv)


if __name__ == "__main__":
    unittest.main()
