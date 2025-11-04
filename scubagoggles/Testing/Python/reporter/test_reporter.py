"""
test_reporter tests the Reporter class.
"""
from pathlib import Path
import re
import pytest

import scubagoggles as scubagoggles_pkg
from scubagoggles.reporter.reporter import Reporter
from scubagoggles.version import Version

class TestReporter:
    """Unit tests for the Reporter class."""
    def _reporter_factory(self, **overrides) -> Reporter:
        defaults = {
            "product": "gmail",
            "tenant_id": "ABCDEFG",
            "tenant_name": "Cool Example Org",
            "tenant_domain": "example.org",
            "main_report_name": "Baseline Reports",
            "prod_to_fullname": {"gmail": "Gmail"},
            "product_policies": [],
            "successful_calls": set(),
            "unsuccessful_calls": set(),
            "missing_policies": set(),
            "dns_logs": {},
            "omissions": {},
            "annotations": {},
            "progress_bar": None,
        }
        params = {**defaults, **overrides}
        return Reporter(**params)

    def test_create_html_table_empty(self):
        """
        Tests Reporter.create_html_table() with an empty list of rows.
        """
        reporter = self._reporter_factory()
        assert reporter.create_html_table([]) == ""

    def test_create_html_table_tenant_info(self):
        """
        Tests Reporter.create_html_table() with tenant data.
        """
        rows = [
            {
                "Customer Name": "Cool Example Org",
                "Customer Domain": "example.org",
                "Customer ID": "ABCDEFG",
                "Report Date": "10/10/2025 13:08:59 Pacific Daylight Time",
                "Baseline Version": "0.6",
                "Tool Version": "v0.6.0",
            }
        ]

        reporter = self._reporter_factory()
        html = reporter.create_html_table(rows)
        assert html.startswith("<table")
        assert "<thead>" in html and "<tbody>" in html
        assert html.count("<th>") == 6
        assert html.count("<td>") == 6

        headers = re.findall(r"<th>(.*?)</th>", html, flags=re.S)
        assert headers == [
            "Customer Name",
            "Customer Domain",
            "Customer ID",
            "Report Date",
            "Baseline Version",
            "Tool Version",
        ]

        # Check if cell values are correct
        assert "Cool Example Org" in html
        assert "example.org" in html
        assert "ABCDEFG" in html
        assert "10/10/2025 13:08:59 Pacific Daylight Time" in html
        assert "0.6" in html
        assert "v0.6.0" in html


    def test_create_html_table_control_info(self):
        """
        Tests Reporter.create_html_table() with control table data.
        """
        rows = [
            {
                "Control ID": "GWS.GMAIL.1.1v0.6",
                "Requirement": "Mail Delegation SHOULD be disabled.",
                "Result": "Warning",
                "Criticality": "Should",
                "Details": (
                    "The following OUs are non-compliant:\n"
                    "<ul>\n"
                    "  <li>Terry Hahn's OU: Mail delegation is enabled</li>\n"
                    "</ul>"
                ),
            }
        ]

        reporter = self._reporter_factory()
        html = reporter.create_html_table(rows)

        assert html.startswith("<table")
        assert "<thead>" in html and "<tbody>" in html
        assert html.count("<th>") == 5
        assert html.count("<td>") == 5

        headers = re.findall(r"<th>(.*?)</th>", html, flags=re.S)
        assert headers == [
            "Control ID",
            "Requirement",
            "Result",
            "Criticality",
            "Details"
        ]

        # Check if cell values are correct
        assert "GWS.GMAIL.1.1v0.6" in html
        assert "Mail Delegation SHOULD be disabled." in html
        assert "Warning" in html
        assert "Should" in html
        assert "The following OUs are non-compliant:" in html
        assert "Terry Hahn's OU: Mail delegation is enabled" in html

    def test_build_front_page_html(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """
        Tests Reporter._build_front_page_html() with test data for fragments,
        tenant_info, report_uuid, and darkmode enabled.
        """
        tmp = tmp_path
        (tmp / "FrontPageReport").mkdir(parents=True)
        (tmp / "styles").mkdir(parents=True)
        (tmp / "scripts").mkdir(parents=True)
        (tmp / "templates").mkdir(parents=True)

        pkg_root = Path(scubagoggles_pkg.__file__).resolve().parent
        front_page_html = (
            pkg_root / "reporter" / "FrontPageReport" / "FrontPageReportTemplate.html"
        ).read_text(encoding="utf-8")
        (tmp / "FrontPageReport" / "FrontPageReportTemplate.html").write_text(
            front_page_html, encoding="utf-8"
        )

        dark_mode_toggle_html = (
            pkg_root / "reporter" / "templates" / "DarkModeToggleTemplate.html"
        ).read_text(encoding="utf-8")
        (tmp / "templates" / "DarkModeToggleTemplate.html").write_text(
            dark_mode_toggle_html, encoding="utf-8"
        )

        (tmp / "styles" / "FrontPageStyle.css").write_text("main {}\n footer {}", encoding="utf-8")
        (tmp / "styles" / "main.css").write_text(":root {}", encoding="utf-8")
        (tmp / "scripts" / "main.js").write_text("const testVar = 0;", encoding="utf-8")

        # Patch the actual Reporter class attribute for _reporter_path,
        # otherwise the local instance returned by _reporter_factory() won't use the temp files.
        monkeypatch.setattr(Reporter, "_reporter_path", tmp, raising=True)

        fragments = [
            "<table><tr><td>First</td></tr></table>",
            "<table><tr><td>Second</td></tr></table>",
        ]
        tenant_info = {
            "topLevelOU": "Cool Example Org",
            "domain": "example.org",
            "ID": "ABCDEFG"
        }
        report_uuid = "123e4567-e89b-12d3-a456-426614174000"

        reporter = self._reporter_factory()
        html = reporter.build_front_page_html(
            fragments,
            tenant_info,
            report_uuid,
            darkmode="true",
        )

        assert Version.current in html

        assert "{{" not in html and "}}" not in html
        assert "<style>" in html and "</style>" in html
        assert "main {}" in html and "footer {}" in html
        assert ":root {}" in html
        assert "<script>" in html and "</script>" in html
        assert "const testVar = 0;" in html

        assert "sgr_settings" in html and "data-darkmode=\"true\"" in html

        assert "First" in html and "Second" in html
        assert report_uuid in html

        assert all(th in html for th in ["Customer Name", "Customer Domain", "Customer ID"])
        assert all(td in html for td in ["Cool Example Org", "example.org", "ABCDEFG"])

    def test_is_control_omitted_returns_true_for_omitted_controls(self):
        """
        Tests Reporter._is_control_omitted() returns True for omitted controls
        with a valid expiration date in the future.
        """
        gmail_1_1 = "GWS.GMAIL.1.1v0.6"
        gmail_1_2 = "GWS.GMAIL.1.2v0.6"
        omissions = {
            gmail_1_1: {
                "rationale": "Accepting risk for now, will reevaluate at a later date.",
                "expiration": "2035-12-31",
            },
            gmail_1_2: {
                "rationale": "Accepting risk for now, will reevaluate at a later date.",
                "expiration": "2035-12-31",
            },
        }
        reporter = self._reporter_factory(omissions=omissions)

        # pylint: disable=protected-access
        assert reporter._is_control_omitted(gmail_1_1) is True
        # pylint: disable=protected-access
        assert reporter._is_control_omitted(gmail_1_2) is True

    def test_is_control_omitted_returns_false_for_controls_with_past_expiration(self):
        """
        Tests Reporter._is_control_omitted() returns False for controls
        with a past expiration date.
        """
        gmail_1_1 = "GWS.GMAIL.1.1v0.6"
        gmail_1_2 = "GWS.GMAIL.1.2v0.6"
        omissions = {
            gmail_1_1: {
                "rationale": "Accepting risk for now, will reevaluate at a later date.",
                "expiration": "2020-12-31",
            },
            gmail_1_2: {
                "rationale": "Accepting risk for now, will reevaluate at a later date.",
                "expiration": "2020-12-31",
            },
        }
        reporter = self._reporter_factory(omissions=omissions)

        assert reporter._is_control_omitted(gmail_1_1) is False
        assert reporter._is_control_omitted(gmail_1_2) is False

    def test_get_omission_rationale_returns_expected_html_tag(self):
        """
        Tests Reporter._get_omission_rationale() returns the expected HTML tag
        for a given policy.
        """
        policy = "GWS.GMAIL.1.1v0.6"
        omissions = {
            policy: {
                "rationale": "Accepting risk for now, will reevaluate at a later date.",
                "expiration": "2035-12-31",
            },
        }

        reporter = self._reporter_factory(omissions=omissions)

        # pylint: disable=protected-access
        html = reporter._get_omission_rationale(policy)

        assert isinstance(html, str)
        assert re.search(
            r"<(?P<tag>\w+)(?:\s[^>]*)?>User justification</(?P=tag)>",
            html,
        ), "Expected an HTML tag wrapping 'User justification'"
        assert omissions[policy]["rationale"] in html

    def test_get_omission_rationale_raises_runtime_error_if_no_omission_found(self):
        """
        Tests Reporter._get_omission_rationale() raises a RuntimeError if no
        omission is found for the given policy.
        """
        reporter = self._reporter_factory(omissions={})

        with pytest.raises(RuntimeError):
            # pylint: disable=protected-access
            reporter._get_omission_rationale("GWS.GMAIL.1.1v0.6")

    def test_get_omission_rationale_user_justification_not_provided(
        self,
        monkeypatch: pytest.MonkeyPatch
    ):
        """
        Tests Reporter._get_omission_rationale() raises a warning if no
        rationale is provided.
        """
        omissions = {
            "GWS.GMAIL.1.1v0.6": {
                "rationale": "",
                "expiration": "2035-12-31",
            },
        }

        reporter = self._reporter_factory(omissions=omissions)

        warnings = []
        monkeypatch.setattr(reporter, "_warn", warnings.append)

        # pylint: disable=protected-access
        html = reporter._get_omission_rationale("GWS.GMAIL.1.1v0.6")

        assert warnings, "Expected a warning to be logged for missing rationale"
        assert warnings[0] == (
            "Config file indicates omitting gws.gmail.1.1v0.6, but no rationale provided."
        )

        assert isinstance(html, str)
        assert re.search(
            r"<(?P<tag>\w+)(?:\s[^>]*)?>User justification not provided</(?P=tag)>",
            html,
        ), "Expected a HTML tag wrapping 'User justification not provided'"

    def test_get_annotation_comment_valid(self):
        """
        Tests Reporter._get_annotation_comment() returns the expected comment
        for a given policy.
        """
        annotations = {
            "GWS.GMAIL.1.1v0.6": {
                "incorrectresult": True,
                "comment": "This control is incorrectly marked as non-compliant.",
            },
        }

        reporter = self._reporter_factory(annotations=annotations)

        # pylint: disable=protected-access
        comment = reporter._get_annotation_comment("GWS.GMAIL.1.1v0.6")

        assert isinstance(comment, str)
        assert "This control is incorrectly marked as non-compliant." in comment

    def test_get_annotation_comment_invalid(self):
        """
        Tests Reporter._get_annotation_comment() returns None for cases
        where the annotated policies are declared incorrectly in the config file.
        """
        policy = "GWS.GMAIL.1.1v0.6"

        # If no policy id found in annotations object
        reporter = self._reporter_factory(annotations={})
        # pylint: disable=protected-access
        assert reporter._get_annotation_comment(policy) is None

        # If the policy id is not assigned a value
        reporter = self._reporter_factory(annotations={policy: None})
        # pylint: disable=protected-access
        assert reporter._get_annotation_comment(policy) is None

        # If no comment is specified
        reporter = self._reporter_factory(annotations={policy: {"incorrectresult": True}})
        # pylint: disable=protected-access
        assert reporter._get_annotation_comment(policy) is None

        # If the comment is None
        reporter = self._reporter_factory(annotations={policy: {"comment": None}})
        # pylint: disable=protected-access
        assert reporter._get_annotation_comment(policy) is None

        # If the comment is an empty string
        reporter = self._reporter_factory(annotations={policy: {"comment": ""}})
        # pylint: disable=protected-access
        assert reporter._get_annotation_comment(policy) is None

    def test_get_remediation_date_valid(self):
        """
        Tests Reporter._get_remediation_date() returns the expected date
        for a given policy.
        """
        policy = "GWS.GMAIL.1.1v0.6"
        annotations = {
            policy: {
                "remediationdate": "2035-12-31",
            }
        }

        reporter = self._reporter_factory(annotations=annotations)
        # pylint: disable=protected-access
        remediation_date = reporter._get_remediation_date(policy)
        assert remediation_date == "2035-12-31"

    def test_get_remediation_date_invalid(self):
        """
        Tests Reporter._get_remediation_date() returns None for cases
        where the remediation date is not properly specified.

        This method simply pulls the remediation date from a policy if it exists.
        Its not handling validation to check invalid date formats like YYYY-MM-DD
        or things like delimiting by / instead of -, e.g. 12/31/2035 vs. 12-31-2035.
        """
        policy = "GWS.GMAIL.1.1v0.6"

        # If no policy id found in annotations object
        reporter = self._reporter_factory(annotations={})
        # pylint: disable=protected-access
        assert reporter._get_remediation_date(policy) is None

        # If the policy id is not assigned a value
        reporter = self._reporter_factory(annotations={policy: None})
        # pylint: disable=protected-access
        assert reporter._get_remediation_date(policy) is None

        # If no remediation date is specified
        reporter = self._reporter_factory(annotations={policy: {"incorrectresult": True}})
        # pylint: disable=protected-access
        assert reporter._get_remediation_date(policy) is None

        # If the remediation date is None
        reporter = self._reporter_factory(annotations={policy: {"remediationdate": None}})
        # pylint: disable=protected-access
        assert reporter._get_remediation_date(policy) is None

        # If the remediation date is an empty string
        reporter = self._reporter_factory(annotations={policy: {"remediationdate": ""}})
        # pylint: disable=protected-access
        assert reporter._get_remediation_date(policy) is None

    def test_is_control_marked_incorrect_valid(self):
        """
        Tests Reporter._is_control_marked_incorrect() returns True for cases
        where the control is marked as incorrect.
        """
        policy = "GWS.GMAIL.1.1v0.6"
        annotations = {
            policy: {
                "comment": "This control is incorrectly marked as non-compliant.",
                "incorrectresult": True,
            }
        }

        reporter = self._reporter_factory(annotations=annotations)
        # pylint: disable=protected-access
        assert reporter._is_control_marked_incorrect(policy) is True

    def test_is_control_marked_incorrect_invalid(self):
        """
        Tests Reporter._is_control_marked_incorrect() returns False for invalid cases
        or when incorrectresult is set to false.
        """
        policy = "GWS.GMAIL.1.1v0.6"

        # If no policy id found in annotations object
        reporter = self._reporter_factory(annotations={})
        # pylint: disable=protected-access
        assert reporter._is_control_marked_incorrect(policy) is False

        # If the policy id is not assigned a value
        reporter = self._reporter_factory(annotations={policy: {}})
        # pylint: disable=protected-access
        assert reporter._is_control_marked_incorrect(policy) is False

        # If no incorrectresult is specified
        reporter = self._reporter_factory(annotations={policy: {"comment": "Some comment"}})
        # pylint: disable=protected-access
        assert reporter._is_control_marked_incorrect(policy) is False

        # If incorrectresult is set to False
        reporter = self._reporter_factory(annotations={policy: {"incorrectresult": False}})
        # pylint: disable=protected-access
        assert reporter._is_control_marked_incorrect(policy) is False

    def test_transform_rego_output_to_individual_reports(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch
    ):
        """
        Tests Reporter.rego_json_to_ind_reports() with sample rego output data.
        """
        tmp = tmp_path
        (tmp / "IndividualReport").mkdir(parents=True)
        (tmp / "styles").mkdir(parents=True)
        (tmp / "scripts").mkdir(parents=True)
        (tmp / "templates").mkdir(parents=True)

        pkg_root = Path(scubagoggles_pkg.__file__).resolve().parent
        individual_report_template = (
            pkg_root / "reporter" / "IndividualReport" / "IndividualReportTemplate.html"
        ).read_text(encoding="utf-8")
        (tmp / "IndividualReport" / "IndividualReportTemplate.html").write_text(
            individual_report_template, encoding="utf-8"
        )

        dark_mode_toggle_template = (
            pkg_root / "reporter" / "templates" / "DarkModeToggleTemplate.html"
        ).read_text(encoding="utf-8")
        (tmp / "templates" / "DarkModeToggleTemplate.html").write_text(
            dark_mode_toggle_template, encoding="utf-8"
        )

        (tmp / "styles" / "main.css").write_text(":root {}", encoding="utf-8")
        (tmp / "scripts" / "main.js").write_text("const testVar = 0;", encoding="utf-8")

        # Patch the actual Reporter class attribute for _reporter_path,
        # otherwise the local instance returned by _reporter_factory() won't use the temp files.
        monkeypatch.setattr(Reporter, "_reporter_path", tmp, raising=True)

        reporter = self._reporter_factory(
            product = "gmail",
            product_policies = [
                {
                    "GroupName": "Mail Delegation",
                    "GroupNumber": "1",
                    "Controls": [
                        {
                            "Id": "GWS.GMAIL.1.1v0.6",
                            "Value": "Mail Delegation SHOULD be disabled.",
                        }
                    ],
                }
            ],
        )

        test_results = [
            {
                "PolicyId": "GWS.GMAIL.1.1v0.6",
                "Prerequisites": [
                    "policy/gmail_mail_delegation.enableMailDelegation",
                    "policy/gmail_service_status.serviceState"
                ],
                "Criticality": "Should",
                "ReportDetails": (
                    "The following OUs are non-compliant:\n"
                    "<ul>\n"
                    "  <li>Terry Hahn's OU: Mail delegation is enabled</li>\n"
                    "</ul>"
                ),
                "ActualValue": { "NonCompliantOUs": ["Terry Hahn's OU"] },
                "RequirementMet": False,
                "NoSuchEvent": False,
            }
        ]

        out_dir = tmp_path / "GWSBaselineConformance"
        (out_dir / "IndividualReports").mkdir(parents=True)

        report_stats, json_data = reporter.rego_json_to_ind_reports(
            test_results,
            out_dir,
            darkmode="true",
        )

        # Check JSON output
        expected_stats = {
            "Manual": 0,
            "Passes": 0,
            "Errors": 0,
            "Failures": 0,
            "Warnings": 1,
            "Omit": 0,
            "IncorrectResults": 0,
        }
        assert report_stats == expected_stats

        assert isinstance(json_data, list) and len(json_data) == 1
        group = json_data[0]
        assert group["GroupName"] == "Mail Delegation"
        assert group["GroupNumber"] == "1"
        assert group["GroupReferenceURL"].startswith("https://github.com/cisagov/")
        expected_suffix = "scubagoggles/baselines/gmail.md#1-mail-delegation"
        assert group["GroupReferenceURL"].endswith(expected_suffix)
        assert group["Controls"] == [
            {
                "Control ID": "GWS.GMAIL.1.1v0.6",
                "Requirement": "Mail Delegation SHOULD be disabled.",
                "Result": "Warning",
                "Criticality": "Should",
                "Details": (
                    "The following OUs are non-compliant:\n"
                    "<ul>\n"
                    "  <li>Terry Hahn's OU: Mail delegation is enabled</li>\n"
                    "</ul>"
                ),
                "OmittedEvaluationResult": "N/A",
                "OmittedEvaluationDetails": "N/A",
                "IncorrectResult": "N/A",
                "IncorrectDetails": "N/A",
            }
        ]
