"""
IAM Security Risk Analyzer
==========================

Loads a JSON file of synthetic (fake) user accounts and checks each user
for a small set of well understood IAM risks:

    1. MFA disabled
    2. Administrator access
    3. Stale credentials (older than 90 days)
    4. Wildcard or obviously excessive permissions

Every finding is classified with a severity and comes with a plain
remediation recommendation. Results are printed to the console and can
optionally be written to a CSV report.

The data in users.json is entirely made up. There are no real
credentials or personal details anywhere in this project.

Usage:
    python analyzer.py [path-to-json] [--csv report.csv]

Examples:
    python analyzer.py
    python analyzer.py users.json
    python analyzer.py users.json --csv findings.csv
"""

import argparse
import csv
import json
import sys


# ---------------------------------------------------------------------------
# Tunable thresholds
# ---------------------------------------------------------------------------

# If a permission list has more entries than this, we treat it as
# "obviously excessive". The number is a simple, arguable choice, not a
# hard rule - it's easy to adjust and easy to explain.
EXCESSIVE_PERMISSION_COUNT = 10

# Credentials older than this many days are considered stale.
MAX_CREDENTIAL_AGE_DAYS = 90

# Credentials older than this are treated as a more serious problem.
VERY_OLD_CREDENTIAL_AGE_DAYS = 180


# ---------------------------------------------------------------------------
# Severity model
# ---------------------------------------------------------------------------

# Ordered from most to least serious. The order is used for sorting output
# and for working out an account's overall risk level.
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def severity_rank(severity):
    """Lower number = more serious. Unknown severities sort last."""
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(SEVERITY_ORDER)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

class InputError(Exception):
    """Raised when the input file cannot be used at all."""


class UserRecordError(Exception):
    """Raised when a single user record is malformed and must be skipped."""


def load_raw_data(path):
    """
    Read and parse the JSON file.

    Raises InputError with a readable message for the common failure
    cases: file missing, not readable, not valid JSON, wrong shape.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        raise InputError("Could not find data file: {}".format(path))
    except IsADirectoryError:
        raise InputError("Expected a file but got a directory: {}".format(path))
    except PermissionError:
        raise InputError("Not allowed to read data file: {}".format(path))
    except UnicodeDecodeError:
        raise InputError("Data file is not valid UTF-8 text: {}".format(path))
    except json.JSONDecodeError as error:
        raise InputError(
            "Data file is not valid JSON ({}): {}".format(error, path)
        )

    if not isinstance(data, dict):
        raise InputError(
            "Top level of the JSON file must be an object with a "
            "\"users\" key."
        )
    if "users" not in data:
        raise InputError("JSON file is missing the required \"users\" key.")
    if not isinstance(data["users"], list):
        raise InputError("\"users\" must be a list of user objects.")

    return data["users"]


def validate_user(record, index):
    """
    Check one raw user record and return a normalised dict.

    Raises UserRecordError (naming the position in the file) if a required
    field is missing or has the wrong type. Optional fields are filled in
    with safe defaults.
    """
    where = "user #{}".format(index + 1)

    if not isinstance(record, dict):
        raise UserRecordError("{} is not a JSON object".format(where))

    username = record.get("username")
    if not isinstance(username, str) or not username.strip():
        raise UserRecordError("{} has a missing or empty username".format(where))
    where = "user '{}'".format(username)

    for field in ("mfa_enabled", "admin"):
        if not isinstance(record.get(field), bool):
            raise UserRecordError(
                "{} is missing boolean field '{}'".format(where, field)
            )

    age = record.get("credential_age_days")
    # bool is a subclass of int, so exclude it explicitly.
    if isinstance(age, bool) or not isinstance(age, (int, float)) or age < 0:
        raise UserRecordError(
            "{} has an invalid 'credential_age_days' (need a number >= 0)".format(
                where
            )
        )

    permissions = record.get("permissions")
    if not isinstance(permissions, list) or not all(
        isinstance(item, str) for item in permissions
    ):
        raise UserRecordError(
            "{} has an invalid 'permissions' (need a list of strings)".format(
                where
            )
        )

    return {
        "username": username,
        "mfa_enabled": record["mfa_enabled"],
        "admin": record["admin"],
        "credential_age_days": age,
        "permissions": permissions,
        "groups": record.get("groups", []),
        "last_login": record.get("last_login", ""),
    }


# ---------------------------------------------------------------------------
# Security checks
#
# Each check returns either None (no problem) or a "finding" dict with:
#   check     - short stable identifier
#   title     - human readable summary
#   severity  - one of SEVERITY_ORDER
#   detail    - specifics for this account
#   recommendation - what to do about it
# ---------------------------------------------------------------------------

def check_mfa_disabled(user):
    if user["mfa_enabled"]:
        return None
    return {
        "check": "mfa_disabled",
        "title": "MFA disabled",
        "severity": "HIGH",
        "detail": "Account can authenticate with a single factor.",
        "recommendation": (
            "Require and enrol a multi-factor authentication device for "
            "this account, and enforce MFA with a policy so access is "
            "blocked until it is set up."
        ),
    }


def check_admin_access(user):
    if not user["admin"]:
        return None
    # Admin plus no MFA is a materially worse position than admin alone.
    severity = "CRITICAL" if not user["mfa_enabled"] else "HIGH"
    return {
        "check": "admin_access",
        "title": "Administrator access",
        "severity": severity,
        "detail": "Account is flagged as an administrator.",
        "recommendation": (
            "Confirm this account still needs administrator rights. Prefer "
            "scoped roles over standing admin, grant elevated access "
            "just-in-time, and make sure MFA is enforced."
        ),
    }


def check_old_credentials(user):
    age = user["credential_age_days"]
    if age <= MAX_CREDENTIAL_AGE_DAYS:
        return None
    severity = "MEDIUM"
    if age > VERY_OLD_CREDENTIAL_AGE_DAYS:
        severity = "HIGH"
    return {
        "check": "stale_credentials",
        "title": "Stale credentials",
        "severity": severity,
        "detail": "Credentials are {} days old (limit {}).".format(
            _format_number(age), MAX_CREDENTIAL_AGE_DAYS
        ),
        "recommendation": (
            "Rotate the access key or password now and set up automatic "
            "rotation on a 90 day cycle. Remove unused keys entirely."
        ),
    }


def check_excessive_permissions(user):
    permissions = user["permissions"]

    full_wildcard = [p for p in permissions if p.strip() == "*"]
    service_wildcard = [
        p for p in permissions if "*" in p and p.strip() != "*"
    ]

    if full_wildcard:
        return {
            "check": "wildcard_permissions",
            "title": "Full wildcard permission",
            "severity": "CRITICAL",
            "detail": "Grants '*' - every action on every resource.",
            "recommendation": (
                "Replace the '*' grant with an explicit list of the actions "
                "this account actually uses. Start from deny-by-default and "
                "add permissions from real usage data."
            ),
        }

    if service_wildcard:
        return {
            "check": "wildcard_permissions",
            "title": "Service-wide wildcard permission",
            "severity": "HIGH",
            "detail": "Grants service-wide access: {}.".format(
                ", ".join(sorted(service_wildcard))
            ),
            "recommendation": (
                "Narrow each 'service:*' grant to the specific actions in "
                "use (for example 's3:GetObject' instead of 's3:*') and "
                "scope them to named resources."
            ),
        }

    if len(permissions) > EXCESSIVE_PERMISSION_COUNT:
        return {
            "check": "excessive_permissions",
            "title": "Excessive permission count",
            "severity": "MEDIUM",
            "detail": "Account holds {} individual permissions (limit {}).".format(
                len(permissions), EXCESSIVE_PERMISSION_COUNT
            ),
            "recommendation": (
                "Review the permission set against what the account has "
                "actually used recently and remove everything unused. "
                "Consider splitting responsibilities across separate roles."
            ),
        }

    return None


ALL_CHECKS = (
    check_mfa_disabled,
    check_admin_access,
    check_old_credentials,
    check_excessive_permissions,
)


def _format_number(value):
    """Show whole numbers without a trailing '.0'."""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze_user(user):
    """Run every check on one validated user and return a list of findings."""
    findings = []
    for check in ALL_CHECKS:
        result = check(user)
        if result is not None:
            findings.append(result)
    findings.sort(key=lambda f: severity_rank(f["severity"]))
    return findings


def analyze_users(raw_users):
    """
    Validate and analyse a list of raw user records.

    Returns (results, warnings) where results is a list of
    {"user": <validated user>, "findings": [...]} and warnings is a list
    of strings describing records that had to be skipped.
    """
    results = []
    warnings = []
    for index, record in enumerate(raw_users):
        try:
            user = validate_user(record, index)
        except UserRecordError as error:
            warnings.append("Skipped {}".format(error))
            continue
        results.append({"user": user, "findings": analyze_user(user)})
    return results, warnings


def overall_severity(findings):
    """The most serious severity among a user's findings, or None."""
    if not findings:
        return None
    return min((f["severity"] for f in findings), key=severity_rank)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_report(results, warnings, path):
    print("IAM Security Risk Analyzer")
    print("Analyzed {} valid user account(s) from {}".format(len(results), path))
    if warnings:
        print()
        for warning in warnings:
            print("WARNING: {}".format(warning))
        print("({} record(s) skipped)".format(len(warnings)))
    print("-" * 60)

    severity_totals = {name: 0 for name in SEVERITY_ORDER}
    flagged_users = 0

    for entry in results:
        user = entry["user"]
        findings = entry["findings"]
        if not findings:
            continue

        flagged_users += 1
        print(
            "User: {}  [overall: {}]".format(
                user["username"], overall_severity(findings)
            )
        )
        for finding in findings:
            severity_totals[finding["severity"]] += 1
            print("  [{}] {}".format(finding["severity"], finding["title"]))
            print("      {}".format(finding["detail"]))
            print("      Fix: {}".format(finding["recommendation"]))
        print()

    print("-" * 60)
    print(
        "{} of {} user(s) have at least one finding.".format(
            flagged_users, len(results)
        )
    )
    totals_text = ", ".join(
        "{} {}".format(severity_totals[name], name) for name in SEVERITY_ORDER
    )
    print("Findings by severity: {}".format(totals_text))


CSV_COLUMNS = [
    "username",
    "overall_severity",
    "check",
    "title",
    "severity",
    "detail",
    "recommendation",
    "groups",
]


def write_csv(results, csv_path):
    """Write one row per finding to csv_path. Returns the row count."""
    rows = 0
    try:
        with open(csv_path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            for entry in results:
                user = entry["user"]
                overall = overall_severity(entry["findings"]) or ""
                for finding in entry["findings"]:
                    writer.writerow(
                        {
                            "username": user["username"],
                            "overall_severity": overall,
                            "check": finding["check"],
                            "title": finding["title"],
                            "severity": finding["severity"],
                            "detail": finding["detail"],
                            "recommendation": finding["recommendation"],
                            "groups": ";".join(user["groups"]),
                        }
                    )
                    rows += 1
    except (PermissionError, FileNotFoundError, IsADirectoryError) as error:
        raise InputError(
            "Could not write CSV report to {}: {}".format(csv_path, error)
        )
    return rows


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Analyze synthetic IAM user data for common risks."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="users.json",
        help="Path to the JSON input file (default: users.json).",
    )
    parser.add_argument(
        "--csv",
        metavar="FILE",
        help="Also write a CSV report of all findings to FILE.",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)

    try:
        raw_users = load_raw_data(args.path)
    except InputError as error:
        print("ERROR: {}".format(error), file=sys.stderr)
        return 1

    results, warnings = analyze_users(raw_users)
    print_report(results, warnings, args.path)

    if args.csv:
        try:
            rows = write_csv(results, args.csv)
        except InputError as error:
            print("ERROR: {}".format(error), file=sys.stderr)
            return 1
        print("Wrote {} finding row(s) to {}".format(rows, args.csv))

    return 0


if __name__ == "__main__":
    sys.exit(main())
