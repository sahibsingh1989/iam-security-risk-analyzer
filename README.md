# IAM Security Risk Analyzer

A small, dependency-free Python tool that reviews a JSON export of IAM user
accounts and reports common access-management risks, each with a severity
rating and a plain remediation recommendation.

All data in `users.json` is **synthetic**. There are no real credentials or
personal details anywhere in this project.

## What it checks

| Check | Severity | Notes |
|-------|----------|-------|
| MFA disabled | HIGH | Single-factor authentication is possible. |
| Administrator access | HIGH (CRITICAL if MFA is also off) | Standing admin rights. |
| Stale credentials | MEDIUM over 90 days, HIGH over 180 days | Age from `credential_age_days`. |
| Full wildcard permission (`*`) | CRITICAL | Every action on every resource. |
| Service-wide wildcard (`service:*`) | HIGH | e.g. `iam:*`, `s3:*`. |
| Excessive permission count | MEDIUM | More than 10 individual permissions. |

Thresholds live at the top of `analyzer.py` and are easy to adjust.
Each account also gets an **overall severity** equal to its most serious
finding.

## Usage

```
python analyzer.py [path-to-json] [--csv report.csv]
```

Examples:

```
python analyzer.py                        # uses ./users.json
python analyzer.py users.json
python analyzer.py users.json --csv findings.csv
```

On Windows the launcher is usually `py` instead of `python`.

Exit codes: `0` on success, `1` if the input file is missing, unreadable,
not valid JSON, or not in the expected shape. Individual malformed user
records are reported as warnings and skipped; the rest are still analyzed.

## Input format

```json
{
  "users": [
    {
      "username": "alice.dev",
      "mfa_enabled": true,
      "admin": false,
      "credential_age_days": 30,
      "permissions": ["s3:GetObject", "s3:PutObject"],
      "groups": ["developers"],
      "last_login": "2026-08-28"
    }
  ]
}
```

`username`, `mfa_enabled`, `admin`, `credential_age_days` and `permissions`
are required. `groups` and `last_login` are optional.

## CSV report

`--csv FILE` writes one row per finding with columns:
`username, overall_severity, check, title, severity, detail, recommendation, groups`.

## Tests

```
python -m unittest -v
```

Covers each security check (including severity escalation and priority
between overlapping permission problems), input validation, file-level
error handling, CSV export, and a few sanity checks against the bundled
sample data.
