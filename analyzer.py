"""
IAM Security Risk Analyzer - first working version.

Loads a JSON file of synthetic (fake) user accounts and checks each user
for four specific IAM risks:

    1. MFA disabled
    2. Administrator access
    3. Credentials older than 90 days
    4. Wildcard or obviously excessive permissions

The data in users.json is entirely made up. There are no real
credentials or personal details anywhere in this project.
"""

import json
import sys

# If a permission list has more entries than this, we treat it as
# "obviously excessive". The number is a simple, arguable choice, not
# a hard rule - it's easy to adjust and easy to explain.
EXCESSIVE_PERMISSION_COUNT = 10

# Credentials older than this many days are considered stale.
MAX_CREDENTIAL_AGE_DAYS = 90


def load_users(path):
    """Read the JSON file and return the list of user dictionaries."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["users"]


def has_mfa_disabled(user):
    """Risk 1: the account does not have MFA turned on."""
    return user["mfa_enabled"] is False


def has_admin_access(user):
    """Risk 2: the account is marked as an administrator."""
    return user["admin"] is True


def has_old_credentials(user):
    """Risk 3: the credential age is greater than 90 days."""
    return user["credential_age_days"] > MAX_CREDENTIAL_AGE_DAYS


def has_excessive_permissions(user):
    """
    Risk 4: the account has a wildcard permission (like "*" or "iam:*")
    or simply has too many permissions to be reasonable.
    """
    permissions = user["permissions"]

    for permission in permissions:
        if "*" in permission:
            return True

    if len(permissions) > EXCESSIVE_PERMISSION_COUNT:
        return True

    return False


def analyze_user(user):
    """Run all four checks on one user and return a list of risk strings."""
    risks = []

    if has_mfa_disabled(user):
        risks.append("MFA disabled")

    if has_admin_access(user):
        risks.append("Administrator access")

    if has_old_credentials(user):
        risks.append(
            "Credentials older than 90 days "
            "({} days)".format(user["credential_age_days"])
        )

    if has_excessive_permissions(user):
        risks.append("Wildcard or excessive permissions")

    return risks


def main():
    # Allow an optional path argument, otherwise default to users.json.
    path = sys.argv[1] if len(sys.argv) > 1 else "users.json"

    try:
        users = load_users(path)
    except FileNotFoundError:
        print("Could not find data file: {}".format(path))
        sys.exit(1)
    except (json.JSONDecodeError, KeyError) as error:
        print("Data file is not in the expected format: {}".format(error))
        sys.exit(1)

    print("IAM Security Risk Analyzer")
    print("Loaded {} user account(s) from {}".format(len(users), path))
    print("-" * 50)

    flagged_users = 0

    for user in users:
        risks = analyze_user(user)

        if not risks:
            continue

        flagged_users += 1
        print("User: {}".format(user["username"]))
        for risk in risks:
            print("  - {}".format(risk))
        print()

    print("-" * 50)
    print(
        "{} of {} user(s) have at least one risk.".format(
            flagged_users, len(users)
        )
    )


if __name__ == "__main__":
    main()
