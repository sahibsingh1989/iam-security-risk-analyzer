"""
Tests for the IAM Security Risk Analyzer.

Run with:
    python -m unittest -v
"""

import csv
import json
import os
import shutil
import tempfile
import unittest

import analyzer


def make_user(**overrides):
    """A valid, low-risk user record; override individual fields per test."""
    user = {
        "username": "test.user",
        "mfa_enabled": True,
        "admin": False,
        "credential_age_days": 10,
        "permissions": ["s3:GetObject"],
        "groups": ["testers"],
        "last_login": "2026-09-01",
    }
    user.update(overrides)
    return user


class MfaCheckTests(unittest.TestCase):
    def test_flags_when_mfa_disabled(self):
        finding = analyzer.check_mfa_disabled(make_user(mfa_enabled=False))
        self.assertIsNotNone(finding)
        self.assertEqual(finding["severity"], "HIGH")
        self.assertTrue(finding["recommendation"])

    def test_clean_when_mfa_enabled(self):
        self.assertIsNone(analyzer.check_mfa_disabled(make_user(mfa_enabled=True)))


class AdminCheckTests(unittest.TestCase):
    def test_no_finding_for_non_admin(self):
        self.assertIsNone(analyzer.check_admin_access(make_user(admin=False)))

    def test_admin_with_mfa_is_high(self):
        finding = analyzer.check_admin_access(
            make_user(admin=True, mfa_enabled=True)
        )
        self.assertEqual(finding["severity"], "HIGH")

    def test_admin_without_mfa_is_critical(self):
        finding = analyzer.check_admin_access(
            make_user(admin=True, mfa_enabled=False)
        )
        self.assertEqual(finding["severity"], "CRITICAL")


class CredentialAgeCheckTests(unittest.TestCase):
    def test_within_limit_is_clean(self):
        self.assertIsNone(
            analyzer.check_old_credentials(make_user(credential_age_days=90))
        )

    def test_moderately_old_is_medium(self):
        finding = analyzer.check_old_credentials(
            make_user(credential_age_days=120)
        )
        self.assertEqual(finding["severity"], "MEDIUM")

    def test_very_old_is_high(self):
        finding = analyzer.check_old_credentials(
            make_user(credential_age_days=400)
        )
        self.assertEqual(finding["severity"], "HIGH")
        self.assertIn("400", finding["detail"])


class PermissionCheckTests(unittest.TestCase):
    def test_full_wildcard_is_critical(self):
        finding = analyzer.check_excessive_permissions(
            make_user(permissions=["*"])
        )
        self.assertEqual(finding["severity"], "CRITICAL")
        self.assertEqual(finding["check"], "wildcard_permissions")

    def test_service_wildcard_is_high(self):
        finding = analyzer.check_excessive_permissions(
            make_user(permissions=["s3:GetObject", "iam:*"])
        )
        self.assertEqual(finding["severity"], "HIGH")
        self.assertIn("iam:*", finding["detail"])

    def test_too_many_permissions_is_medium(self):
        finding = analyzer.check_excessive_permissions(
            make_user(permissions=["svc:Action{}".format(i) for i in range(11)])
        )
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertEqual(finding["check"], "excessive_permissions")

    def test_reasonable_permissions_are_clean(self):
        self.assertIsNone(
            analyzer.check_excessive_permissions(
                make_user(permissions=["s3:GetObject", "s3:PutObject"])
            )
        )

    def test_full_wildcard_takes_priority_over_count(self):
        perms = ["*"] + ["svc:Action{}".format(i) for i in range(20)]
        finding = analyzer.check_excessive_permissions(
            make_user(permissions=perms)
        )
        self.assertEqual(finding["severity"], "CRITICAL")


class ValidationTests(unittest.TestCase):
    def test_valid_record_is_normalised_with_defaults(self):
        user = analyzer.validate_user(
            {
                "username": "a",
                "mfa_enabled": True,
                "admin": False,
                "credential_age_days": 5,
                "permissions": [],
            },
            0,
        )
        self.assertEqual(user["groups"], [])
        self.assertEqual(user["last_login"], "")

    def test_missing_username_is_rejected(self):
        with self.assertRaises(analyzer.UserRecordError):
            analyzer.validate_user({"mfa_enabled": True, "admin": False}, 0)

    def test_non_boolean_mfa_is_rejected(self):
        with self.assertRaises(analyzer.UserRecordError):
            analyzer.validate_user(
                make_user(mfa_enabled="yes"), 0
            )

    def test_boolean_is_not_accepted_as_credential_age(self):
        with self.assertRaises(analyzer.UserRecordError):
            analyzer.validate_user(make_user(credential_age_days=True), 0)

    def test_negative_credential_age_is_rejected(self):
        with self.assertRaises(analyzer.UserRecordError):
            analyzer.validate_user(make_user(credential_age_days=-1), 0)

    def test_permissions_must_be_list_of_strings(self):
        with self.assertRaises(analyzer.UserRecordError):
            analyzer.validate_user(make_user(permissions=[1, 2, 3]), 0)


class LoadRawDataTests(unittest.TestCase):
    def _write(self, text):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        )
        handle.write(text)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_missing_file_raises_input_error(self):
        with self.assertRaises(analyzer.InputError):
            analyzer.load_raw_data("does-not-exist-12345.json")

    def test_invalid_json_raises_input_error(self):
        path = self._write("{ not json")
        with self.assertRaises(analyzer.InputError):
            analyzer.load_raw_data(path)

    def test_missing_users_key_raises_input_error(self):
        path = self._write('{"accounts": []}')
        with self.assertRaises(analyzer.InputError):
            analyzer.load_raw_data(path)

    def test_users_not_a_list_raises_input_error(self):
        path = self._write('{"users": {}}')
        with self.assertRaises(analyzer.InputError):
            analyzer.load_raw_data(path)

    def test_valid_file_returns_list(self):
        path = self._write('{"users": [{"username": "x"}]}')
        self.assertEqual(analyzer.load_raw_data(path), [{"username": "x"}])


class AnalyzeUsersTests(unittest.TestCase):
    def test_bad_record_is_skipped_with_warning(self):
        raw = [
            make_user(username="good.user", mfa_enabled=False),
            {"username": "bad.user"},  # missing required fields
        ]
        results, warnings = analyzer.analyze_users(raw)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["user"]["username"], "good.user")
        self.assertEqual(len(warnings), 1)
        self.assertIn("bad.user", warnings[0])

    def test_findings_sorted_by_severity(self):
        raw = [make_user(admin=True, mfa_enabled=False, permissions=["*"],
                         credential_age_days=400)]
        results, _ = analyzer.analyze_users(raw)
        severities = [f["severity"] for f in results[0]["findings"]]
        self.assertEqual(
            severities, sorted(severities, key=analyzer.severity_rank)
        )

    def test_overall_severity_is_most_serious(self):
        findings = [
            {"severity": "LOW"},
            {"severity": "CRITICAL"},
            {"severity": "MEDIUM"},
        ]
        self.assertEqual(analyzer.overall_severity(findings), "CRITICAL")
        self.assertIsNone(analyzer.overall_severity([]))


class CsvExportTests(unittest.TestCase):
    def test_csv_has_header_and_one_row_per_finding(self):
        raw = [
            make_user(username="u1", mfa_enabled=False, admin=True),  # 2 findings
            make_user(username="u2"),  # 0 findings
        ]
        results, _ = analyzer.analyze_users(raw)

        out_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out_dir, ignore_errors=True)
        csv_path = os.path.join(out_dir, "report.csv")

        rows_written = analyzer.write_csv(results, csv_path)
        self.assertEqual(rows_written, 2)

        with open(csv_path, encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 2)
        self.assertEqual(set(rows[0].keys()), set(analyzer.CSV_COLUMNS))
        self.assertTrue(all(row["username"] == "u1" for row in rows))
        self.assertTrue(all(row["recommendation"] for row in rows))

    def test_write_csv_to_bad_path_raises_input_error(self):
        results, _ = analyzer.analyze_users([make_user(mfa_enabled=False)])
        bad_path = os.path.join("no-such-dir-xyz", "report.csv")
        with self.assertRaises(analyzer.InputError):
            analyzer.write_csv(results, bad_path)


class BundledDataTests(unittest.TestCase):
    """Sanity checks against the sample users.json shipped with the project."""

    @classmethod
    def setUpClass(cls):
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "users.json"), encoding="utf-8") as handle:
            cls.raw = json.load(handle)["users"]

    def test_sample_data_is_valid(self):
        results, warnings = analyzer.analyze_users(self.raw)
        self.assertEqual(warnings, [])
        self.assertEqual(len(results), 8)

    def test_dave_legacy_is_critical_with_all_four_checks(self):
        results, _ = analyzer.analyze_users(self.raw)
        dave = next(
            r for r in results if r["user"]["username"] == "dave.legacy"
        )
        self.assertEqual(analyzer.overall_severity(dave["findings"]), "CRITICAL")
        self.assertEqual(len(dave["findings"]), 4)

    def test_heidi_intern_has_no_findings(self):
        results, _ = analyzer.analyze_users(self.raw)
        heidi = next(
            r for r in results if r["user"]["username"] == "heidi.intern"
        )
        self.assertEqual(heidi["findings"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
