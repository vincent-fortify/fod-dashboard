# AppSec Dashboard Extract (Fortify on Demand → Power BI)

A nightly Azure DevOps pipeline that pulls SAST and DAST findings from Fortify on Demand (FoD), rebuilds six months of history from them, and publishes two CSV files to Azure Blob Storage for the Power BI AppSec Vulnerability Dashboard.

```
Fortify on Demand ──fcli──▶ fod_dashboard_extract.py ──▶ 2 CSVs ──▶ Azure Blob ──▶ Power BI
       (API key)            (Azure DevOps, nightly)                  (powerbi container)
```

Only applications listed in `dashboard_apps.csv` are reported, so the dashboard can be rolled out one application at a time.

---

## Contents

1. [What's in this repository](#1-whats-in-this-repository)
2. [Output files](#2-output-files)
3. [Setup](#3-setup)
4. [Running locally](#4-running-locally)
5. [Command-line options](#5-command-line-options)
6. [How the numbers are calculated](#6-how-the-numbers-are-calculated)
7. [Dashboard mapping](#7-dashboard-mapping)
8. [Known limitations](#8-known-limitations)
9. [Operations and troubleshooting](#9-operations-and-troubleshooting)
10. [Maintenance](#10-maintenance)

---

## 1. What's in this repository

| File | Purpose |
|---|---|
| `fod_dashboard_extract.py` | The extract. Python 3.11+, standard library only; all FoD access goes through `fcli`. |
| `dashboard_apps.csv` | The rollout list: which applications to report, plus dashboard filter values FoD doesn't hold yet. **Must be committed**; the pipeline reads it from the repo. |
| `azure-pipelines.yml` | The nightly Azure DevOps pipeline. |
| `test_fod_dashboard_extract.py` | Offline unit and end-to-end tests (FoD is faked). Run locally after changing the script. |

---

## 2. Output files

Both files share the release and filter columns (`ApplicationId`, `ReleaseId`, `ScanType`, `Region`, …) so they can be related in the Power BI model.

### `appsec_dashboard_latest.csv`: monthly snapshot

One row per **release × scan type (SAST/DAST) × month**. The newest month ends on the run date and has `IsCurrentSnapshot = Yes`; the dashboard tiles read those rows, and the trend chart reads all of them.

| Column group | Columns |
|---|---|
| Identity | `ExtractedAt`, `ScanType`, `ApplicationId`, `ApplicationName`, `ReleaseId`, `ReleaseName`, `SDLCStatus`, `Suspended`, `StarRating` |
| Dashboard filters | `Region`, `Platform`, `ValueStream`, `InternalExternal` |
| Time | `MonthStartDate`, `MonthLabel`, `IsCurrentSnapshot`, `LastScanDate`, `ScanCount` |
| Events in the month | `Detected`, `Remediated`, `FalsePositive`, `RiskAccepted` |
| State at month end | `TotalBacklog`, `Open_<Sev>`, `Debt_<Sev>`, `Resolved_<Sev>` (Sev = Critical, High, Medium, Low) |
| Ageing of open findings | `Age_0_14`, `Age_15_60`, `Age_61_90`, `Age_90Plus` |
| Exception expiry | `ExcActive_<bucket>` (days until expiry), `ExcExpired_<bucket>` (days since expiry), same four buckets |

### `appsec_dashboard_latest_scans.csv`: scan history

One row per SAST/DAST scan completed in the reporting window, for the reported releases: `ScanId`, `AssessmentTypeName`, `AnalysisStatusType`, `StartedDateTime`, `CompletedDateTime`, `ScanDate` (date only, for a Power BI date table), `ScanDurationHours`, `TotalIssues`, `IssueCount<Sev>`, `ScanMethodTypeName`, `ScanTool`, `ScanToolVersion`, `IsRemediationScan`, `EntitlementUnitsConsumed`, `StartedByUserName` (always empty: FoD doesn't return it).

---

## 3. Setup

Do these in order. Steps 3.1–3.4 are one-off; 3.5 is ongoing as the rollout grows.

### 3.1 Fortify on Demand: API key

1. In FoD, go to **Administration → Settings → API** and add a key.
2. Give it a **read-only** role: the script only makes GET calls.
3. Restrict its application access to the rollout applications if your tenant allows it. The scan history call returns every scan the key can see, so a narrowly scoped key keeps the nightly run fast and follows least privilege.
4. Note the **API key** and **secret**, and your FoD API URL (for example `https://api.ams.fortify.com`).

Check the key can see the applications you'll list (on a machine with `fcli`, see [4.1](#41-install-fcli)):

```bash
fcli fod session login --url https://api.ams.fortify.com --client-id <key> --client-secret <secret>
fcli fod app list -o json        # every rollout application must appear here
fcli fod session logout
```

An application the key can't see is reported as a warning ("match no FoD application") and silently missing from the dashboard.

### 3.2 Azure: storage for the CSVs

1. Create (or reuse) a **storage account**. The pipeline expects `stappsecdashboard`; change `STORAGE_ACCOUNT` in `azure-pipelines.yml` if yours differs.
2. Create a blob **container** named `powerbi` (or change `STORAGE_CONTAINER`).

Each night the pipeline writes:

```
powerbi/
├── appsec_dashboard_latest.csv          ← Power BI reads these two (overwritten nightly)
├── appsec_dashboard_latest_scans.csv
└── archive/YYYY/MM/DD/…                 ← dated copies, never read by Power BI
```

Consider a lifecycle management rule to delete `archive/` blobs after, say, 90 days.

### 3.3 Azure DevOps: connection, secrets, pipeline

**a. Service connection to Azure**

1. **Project settings → Service connections → New → Azure Resource Manager** (workload identity federation recommended).
2. Name it `appsec-dashboard-arm` (or change `AZURE_SERVICE_CONNECTION`).
3. In the Azure portal, on the storage account, **Access control (IAM) → Add role assignment → Storage Blob Data Contributor** for the service connection's identity. Without this the upload fails with an authorisation error: the pipeline uses `--auth-mode login`, not storage keys.

**b. Variable group with the FoD secrets**

1. **Pipelines → Library → + Variable group**, named `fortify-fod`.
2. Add these variables and click the lock icon on each to make it secret:

| Variable | Value |
|---|---|
| `FOD_URL` | `https://api.ams.fortify.com` (your FoD API URL) |
| `FOD_CLIENT_ID` | API key from 3.1 |
| `FOD_CLIENT_SECRET` | API secret from 3.1 |

The tenant isn't needed: the API key identifies it, and `fcli` rejects `--tenant` with client credentials.

**c. Commit and create the pipeline**

1. Commit `fod_dashboard_extract.py`, `dashboard_apps.csv` and `azure-pipelines.yml` to the `main` branch. Without `dashboard_apps.csv` the run fails with exit code 1.
2. **Pipelines → New pipeline →** your repo **→ Existing Azure Pipelines YAML file → `/azure-pipelines.yml`**, then save (don't run yet).
3. Run it once manually. Azure DevOps will ask you to **permit** the pipeline to use the `fortify-fod` variable group and the `appsec-dashboard-arm` service connection; approve both.

After that, it runs every night at **17:00 UTC** (04:00 AEDT / 03:00 AEST), defined by `schedules:` in the YAML. Scheduled runs only use the `main` branch.

### 3.4 Power BI

1. **Get data → Azure Blob Storage** (or Azure Data Lake Storage Gen2), storage account from 3.2.
2. Choose the `powerbi` container and load **only** `appsec_dashboard_latest.csv` and `appsec_dashboard_latest_scans.csv`. Filter out the `archive/` folder.
3. Relate the two tables on `ReleaseId` + `ScanType` (or through a shared release dimension).
4. Use `MonthStartDate` (monthly table) and `ScanDate` (scans table) with a date table for time intelligence.
5. In the Power BI Service, set the dataset's credentials for the storage account and schedule refresh **after** the pipeline finishes. The pipeline starts at 17:00 UTC; allow for its runtime (see [9.3](#93-runtime)).

[Section 7](#7-dashboard-mapping) maps each dashboard element to its columns.

### 3.5 The rollout list: `dashboard_apps.csv`

One row per application to report. Open and save it in Excel if you like (Excel's UTF-8 format is fine).

```csv
ApplicationName,ApplicationId,Region,Platform,ValueStream,InternalExternal,Notes
Claims Portal,181116,APAC,Web,Claims,External,wave 1
Broker API,,APAC,,,Internal,wave 1
```

| Column | Rules |
|---|---|
| `ApplicationId` | FoD application ID. Preferred: survives renames, and avoids ambiguity with numeric names. Used when filled. |
| `ApplicationName` | Used when `ApplicationId` is blank. Matched case-insensitively, ignoring surrounding spaces. |
| `Region`, `Platform`, `ValueStream`, `InternalExternal` | Optional. A filled cell **overrides** FoD for every release of that application; a blank cell keeps the FoD attribute value. Drop a column once FoD holds that attribute for every application. |
| `Notes` | Ignored by the script. |

Every application in the list must also be visible to the API key (3.1).

The run **fails (exit 1)** when the file:
- is missing
- has an unknown column (for example `Value Stream` with a space)
- has a bad ID, or a row with neither ID nor name
- lists the same application twice
- selects no production releases at all

It only **warns** for entries that match no FoD application, and for applications with no matching release.

To add an application: add a row, commit to `main`; the next nightly run picks it up.

---

## 4. Running locally

### 4.1 Install fcli

```bash
curl -fsSL -o fcli.tgz https://github.com/fortify/fcli/releases/download/v3.28.0/fcli-linux.tgz
tar -xzf fcli.tgz && sudo mv fcli /usr/local/bin/ && fcli --version
```

Use the same version as `FCLI_VERSION` in the pipeline.

### 4.2 Log in

Use the pipeline's API key where possible: a personal login can see different applications, so local results may not match the pipeline.

```bash
fcli fod session login --url https://api.ams.fortify.com --client-id <key> --client-secret <secret>
fcli fod session list -o json      # "expired": "No"; sessions last about 6 hours
```

### 4.3 Run

```bash
# quick test: first 2 releases, no scan history -> test.csv
python3 fod_dashboard_extract.py --limit-releases 2 --skip-scans

# SAST only
python3 fod_dashboard_extract.py --limit-releases 2 --scan-type SAST

# full run, as the pipeline does -> appsec_dashboard_latest.csv + appsec_dashboard_latest_scans.csv
python3 fod_dashboard_extract.py
```

Progress goes to stderr. Output is written to a `.tmp` file and renamed at the end, so a failed run never leaves a half-written CSV.

### 4.4 Tests

No FoD login needed; runs in under a second:

```bash
python3 -m unittest -v test_fod_dashboard_extract
```

They cover month windows, ageing and expiry buckets, Open/Debt/Resolved at each month end, audit history replay, row totals, the scans file, the rollout list, and full runs against a fake FoD (filters, output files, exit codes). Run them after any change to the script.

---

## 5. Command-line options

| Option | Default | Meaning |
|---|---|---|
| `--out PATH` | `appsec_dashboard_latest.csv`; `test.csv` with `--limit-releases` | Monthly CSV |
| `--scans-out PATH` | `<out>_scans.csv` | Scan history CSV |
| `--months N` | `6` | Months of history, **including** the current partial month. Use `7` for six full months plus the current one. |
| `--scan-type SAST\|DAST` | both | Extract one type only (filtered by FoD, so faster) |
| `--skip-scans` | off | Don't fetch scan history: no scans file, `ScanCount` left blank |
| `--apps-file PATH` | `dashboard_apps.csv` next to the script | Rollout list |
| `--all-apps` | off | Ignore the rollout list; report every application, FoD attributes only |
| `--all-releases` | off | Include QA, Development and Retired releases, not just Production. Suspended releases are always excluded. |
| `--limit-releases N` | all | Only the first N selected releases (testing) |
| `--max-failures N` | `5` | Releases allowed to fail before the run exits 2. Set `0` in the pipeline to refuse to publish a dashboard with any release missing. |

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | OK. Some releases may have failed, up to `--max-failures`; check the log. |
| `1` | Fatal, nothing published. Causes: no FoD session, bad rollout list, nothing selected, scan history fetch failed, or bad command-line option. |
| `2` | Completed, but more releases failed than `--max-failures`. |

In the pipeline, any non-zero exit fails the step, so nothing is uploaded and Power BI keeps the previous night's data.

---

## 6. How the numbers are calculated

FoD only stores each finding's **current** state. The script rebuilds every past month from the dates FoD keeps:

| Date | Source |
|---|---|
| First detected | `introducedDate` on the finding |
| Fixed | `closedDate` on the finding |
| Marked *Not an Issue* | audit history (FoD doesn't set `closedDate` for these) |
| Risk accepted / un-accepted | audit history, every status change replayed in time order |
| Exception expiry | `EXP:yyyy-mm-dd` in a comment on the finding |

A finding's **state at each month end** is one of:

| State | Meaning |
|---|---|
| **Open** (backlog) | Detected, not fixed, not *Not an Issue*, not risk accepted at that date |
| **Debt** (technical debt) | Risk accepted at that date |
| **Resolved** | Fixed, or marked *Not an Issue*, on or before that date. Cumulative. |

Each month's **events** are counted on the date they happened:

| Event | Counted when |
|---|---|
| `Detected` | first detected in the month |
| `Remediated` | fixed in the month |
| `FalsePositive` | marked *Not an Issue* in the month |
| `RiskAccepted` | risk accepted in the month |

**Ageing** buckets count open findings by days since first detected, at the month end.

**Exceptions:**
- `ExcActive_*`: days until the `EXP:` date.
- `ExcExpired_*`: days since the `EXP:` date.
- No `EXP:` date, or an invalid one (logged as a warning): treated as **expired since the day it was accepted**. So Technical Debt always equals Expiring + Expired.

**Scope:**
- **Included:** SAST (Static) and DAST (Dynamic) findings of Critical, High, Medium and Low severity.
- **Excluded:** Info and Best Practice severities, open source (SCA, covered by Mend) and Mobile findings.
- **Releases scanned with no findings** get rows of zeros, so they appear in "Applications Scanned".
- **Releases never scanned** get no rows.

**Scan `TotalIssues` vs `TotalBacklog`:** FoD's scan totals exclude suppressed findings (risk accepted and *Not an Issue*), and each scan row is a snapshot of that scan. The backlog matches the **latest** scan for a release, not every scan.

---

## 7. Dashboard mapping

| Dashboard element | Source (monthly file unless stated) |
|---|---|
| Region / Platform / Value Stream / Internal-External filters | `Region`, `Platform`, `ValueStream`, `InternalExternal` |
| Application Name / App Version / SDLC Status filters | `ApplicationName`, `ReleaseName`, `SDLCStatus` |
| SAST / DAST tabs | `ScanType` |
| App Count (Applications Scanned) | distinct `ApplicationId` |
| Open Findings by severity | `Open_*` where `IsCurrentSnapshot = Yes` |
| Technical Debt by severity | `Debt_*` (current snapshot) |
| Resolved by severity | `Resolved_*` (current snapshot) |
| Ageing Profile tiles | `Age_*` (current snapshot) |
| Expiring / Expired Exceptions | `ExcActive_*` / `ExcExpired_*` (current snapshot) |
| Resolution Status chart | `Detected`, `Remediated`, `FalsePositive`, `RiskAccepted`, `TotalBacklog` by `MonthStartDate` |
| Refreshed timestamp | `ExtractedAt` |
| Scan history | scans file |

---

## 8. Known limitations

**Data model**
- **Ageing Profile can't filter the severity tiles.** Age buckets and severities are stored as separate totals per row, so "Critical findings older than 90 days" can't be derived. Fixing this needs a long-format redesign of the monthly file (one count per release, month, state, severity and bucket).
- **SCA tab has no data.** Open source findings are excluded by design.
- **SDLC Status filter only shows Production** unless the pipeline adds `--all-releases`.

**Rebuilt history**
- **Exception expiry depends on a comment convention:** `EXP:yyyy-mm-dd`, exactly (capital `EXP`, no space, ISO date). Exceptions without it show as Expired. If a finding has several `EXP:` comments, whichever FoD returns last is used.
- **Audit history is only read for findings that are risk accepted or *Not an Issue* today.** A finding accepted in the past but no longer accepted shows as Open for those past months. Reading history for every finding would be too slow for a large tenant.
- **Fallback dates.** If an audit history call fails, or has no matching status change, the finding's last-modified date is used instead (with a warning in the log).
- **Reopened findings.** A finding fixed and later found again isn't verified against real data; how it appears depends on how FoD resets its dates.

**Coverage**
- **Releases never scanned don't appear,** even if onboarded.
- **The API key decides what's visible.** Applications it can't see are missing, with only a warning.
- **Scan history scales with the key, not the list.** FoD's tenant-wide scans endpoint can't filter by application, and ignores the documented `fields` parameter, so the nightly scan fetch covers everything the key can see.

---

## 9. Operations and troubleshooting

### 9.1 Reading the pipeline log

The Build CSVs step logs one line per release (`[n/total] release <id> <name> <issues> issues, <exceptions> exceptions`) and these warnings:

| Warning | Meaning / action |
|---|---|
| `app list entries match no FoD application` | Typo in `dashboard_apps.csv`, or the API key can't see the application |
| `listed applications have no production release` | Application has no active Production release (use `--all-releases` if intended) |
| `release … FAILED` | That release is missing from tonight's data; the run fails only above `--max-failures` |
| `no acceptance date in history` / `resolution date failed` | Date fallback used for one finding (see [8](#8-known-limitations)) |
| `invalid expiry … ignored` | Fix the `EXP:` comment on that finding |

### 9.2 Common failures

| Symptom | Cause / fix |
|---|---|
| FoD login step fails | Wrong or expired API key/secret in `fortify-fod`; or `FOD_URL` is the portal URL rather than the API URL |
| `cannot use app list` (exit 1) | `dashboard_apps.csv` missing from the commit, or has an unknown column, bad ID or duplicate. The log names the line. |
| `selects no production releases` (exit 1) | No listed application has an active Production release visible to the key |
| `unmapped auditorStatus 'X'` (release failed) | The tenant has a custom auditor status. Add it to the right set in the script (see [10](#10-maintenance)). |
| Upload step: authorisation error | Service connection identity lacks **Storage Blob Data Contributor** on the storage account |
| Pipeline asks for permission | Approve the variable group / service connection for this pipeline (first run, or after renaming) |
| Run exceeds the job timeout | Raise `timeoutInMinutes` (180), or narrow the API key's scope |

### 9.3 Runtime

Rough figures from testing:

| Part | Time |
|---|---|
| Startup (release and application lists) | ~40 s |
| Each release | ~10 s, plus ~1–2 s per risk-accepted or recently *Not an Issue* finding |
| Scan history | ~4 s per month for a few hundred scans; grows with the API key's scope |

Example: about 15 minutes for 50 applications. The FoD session lasts about 6 hours; the job timeout is 3 hours.

### 9.4 Re-running

Re-running the pipeline the same day is safe: both the main files and the dated archive copies are overwritten.

---

## 10. Maintenance

| Change | Where |
|---|---|
| Add or remove applications, or override filter values | `dashboard_apps.csv` → commit to `main` |
| Tenant uses different auditor status names | `OPEN_STATUSES`, `DEBT_STATUSES`, `RESOLVED_STATUSES` at the top of the script. Auditor statuses are configured per tenant; list those in use on a release with `fcli fod issue list --rel=<releaseId> --include=visible,suppressed,fixed -o 'expr={auditorStatus}\n' \| sort -u`. An unlisted status fails that release with `unmapped auditorStatus`. |
| FoD attribute names differ (Region, Platform, …) | `ATTRIBUTE_MAP` at the top of the script. Check with `fcli fod attribute list -o json`. |
| Upgrade fcli | `FCLI_VERSION` in `azure-pipelines.yml` (test locally first) |
| History length | the script's `--months` default, or pass `--months` in the Build CSVs step |
| Schedule | `cron` in `azure-pipelines.yml` (UTC) |
| Storage account, container, file names | variables in `azure-pipelines.yml`. Update Power BI if the file names change. |

After changing the script, run the tests ([4.4](#44-tests)) and a quick live run ([4.3](#43-run)) before committing.
