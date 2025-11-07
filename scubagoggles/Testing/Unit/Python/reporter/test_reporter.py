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
    def _reporter(self, **overrides) -> Reporter:
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

    @pytest.mark.parametrize(
        "table_data",
        [
            [],
            [
                {
                    "Customer Name": "Cool Example Org",
                    "Customer Domain": "example.org",
                    "Customer ID": "ABCDEFG",
                    "Report Date": "10/10/2025 13:08:59 Pacific Daylight Time",
                    "Baseline Version": "0.6",
                    "Tool Version": "v0.6.0",
                }
            ],
            [
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
                },
                {
                    "Control ID": "GWS.GMAIL.2.1v0.6",
                    "Requirement": "DKIM SHOULD be enabled for all domains.",
                    "Result": "Warning",
                    "Criticality": "Should",
                    "Details": (
                        "The following OUs are non-compliant:\n"
                        "<ul>\n"
                        "  <li>Terry Hahn's OU: DKIM is not enabled</li>\n"
                        "</ul>"
                    ),
                },
            ],
        ],
    )
    def test_create_html_table(self, table_data):
        """
        Tests Reporter.create_html_table() for these cases:
            - empty list to indicate no table
            - tenant info table
            - control info table
        """
        reporter = self._reporter()
        html = reporter.create_html_table(table_data)

        if not table_data:
            assert html == ""
            return

        assert html.startswith("<table")
        assert "<thead>" in html and "<tbody>" in html

        expected_headers = list(table_data[0].keys())
        assert html.count("<th>") == len(expected_headers)
        assert html.count("<td>") == len(table_data) * len(expected_headers)

        headers = re.findall(r"<th>(.*?)</th>", html, flags=re.S)
        assert headers == expected_headers

        for table in table_data:
            assert list(table.keys()) == expected_headers

            for value in table.values():
                assert str(value) in html

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
        # otherwise the local instance returned by _reporter() won't use the temp files.
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

        reporter = self._reporter()
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

    @pytest.mark.parametrize(
        ("omissions", "expected"),
        [
            (
                {
                    "GWS.GMAIL.1.1v0.6": {
                        "rationale": "Accepting risk",
                        "expiration": "2035-12-31"
                    },
                },
                True,
            ),
            (
                {
                    "GWS.GMAIL.1.1v0.6": {
                        "rationale": "Accepting risk",
                        "expiration": "2020-12-31"
                    },
                },
                False,
            ),
        ],
    )
    # pylint: disable=protected-access
    def test_is_control_omitted(self, omissions, expected):
        """
        Tests if Reporter._is_control_omitted() returns True/false
        for different expiration dates.
        """
        reporter = self._reporter(omissions=omissions)
        for policy in omissions:
            assert reporter._is_control_omitted(policy) is expected

    @pytest.mark.parametrize(
        "cases",
        [
            {
                "omissions": {
                    "GWS.GMAIL.1.1v0.6": {
                        "rationale": "Accepting risk for now, will reevaluate at a later date.",
                        "expiration": "2035-12-31",
                    }
                },
                "pattern": r"<(?P<tag>\w+)(?:\s[^>]*)?>User justification</(?P=tag)>",
                "expects_warning": False,
                "expected_error": None,
            },
            {
                "omissions": {},
                "pattern": None,
                "expects_warning": False,
                "expected_error": RuntimeError,
            },
            {
                "omissions": {
                    "GWS.GMAIL.1.1v0.6": {
                        "rationale": "",
                        "expiration": "2035-12-31",
                    }
                },
                "pattern": r"<(?P<tag>\w+)(?:\s[^>]*)?>User justification not provided</(?P=tag)>",
                "expects_warning": True,
                "expected_error": None,
            },
        ],
    )
    # pylint: disable=protected-access
    def test_get_omission_rationale(
            self,
            monkeypatch: pytest.MonkeyPatch,
            cases
    ):
        """
        Tests if Reporter._get_omission_rationale() returns the expected HTML tag
        for a given policy and if runtime errors are thrown correctly.
        """
        omissions = cases["omissions"]
        pattern = cases["pattern"]
        expects_warning = cases["expects_warning"]
        expected_error = cases["expected_error"]

        reporter = self._reporter(omissions=omissions)
        warnings = []
        monkeypatch.setattr(reporter, "_warn", warnings.append)

        for policy in omissions:
            if expected_error:
                with pytest.raises(expected_error):
                    reporter._get_omission_rationale(policy)
                return

            html = reporter._get_omission_rationale(policy)
            assert isinstance(html, str)

            if expects_warning:
                assert warnings, "Expected a warning to be logged for missing rationale"
            else:
                assert not warnings, "Did not expect any warnings to be logged"

            if pattern:
                assert re.search(
                    pattern, html
                ), f"Expected an HTML tag wrapping the rationale for policy {policy}"

            rationale = omissions[policy]["rationale"]
            if rationale:
                assert rationale in html

    @pytest.mark.parametrize(
        ("annotations", "expected"),
        [
            (
                {
                    "GWS.GMAIL.1.1v0.6": {
                        "incorrectresult": True,
                        "comment": "This control is incorrectly marked as non-compliant.",
                    }
                },
                "This control is incorrectly marked as non-compliant.",
            ),
            ({}, None),
            ({"GWS.GMAIL.1.1v0.6": None}, None),
            ({"GWS.GMAIL.1.1v0.6": {"incorrectresult": True}}, None),
            ({"GWS.GMAIL.1.1v0.6": {"comment": None}}, None),
            ({"GWS.GMAIL.1.1v0.6": {"comment": ""}}, None),
        ],
    )
    # pylint: disable=protected-access
    def test_get_annotation_comment(self, annotations, expected):
        """
        Tests if Reporter._get_annotation_comment() handles these cases:
            - returns the expected comment for a given policy
            - returns None for cases where the annotated policies are
              declared incorrectly in the config file.
            - returns None when no comment is specified.
        """
        reporter = self._reporter(annotations=annotations)

        for policy in annotations:
            comment = reporter._get_annotation_comment(policy)
            if expected is None:
                assert comment is None
            else:
                assert isinstance(comment, str)
                assert expected is comment

    @pytest.mark.parametrize(
        ("annotations", "expected"),
        [
            (
                {
                    "GWS.GMAIL.1.1v0.6": {
                        "remediationdate": "2035-12-31"
                    }
                },
                "2035-12-31",
            ),
            ({}, None),
            ({"GWS.GMAIL.1.1v0.6": None}, None),
            ({"GWS.GMAIL.1.1v0.6": {"incorrectresult": True}}, None),
            ({"GWS.GMAIL.1.1v0.6": {"remediationdate": None}}, None),
            ({"GWS.GMAIL.1.1v0.6": {"remediationdate": ""}}, None),
        ],
    )
    # pylint: disable=protected-access
    def test_get_remediation_date(self, annotations, expected):
        """
        Tests if Reporter._get_remediation_date() handles these cases:
            - returns the expected date for a given policy
            - returns None for cases where the remediation date is 
              not properly specified.

        This method simply pulls the remediation date from a policy if it exists.
        Its not handling validation to check invalid date formats like YYYY-MM-DD
        or things like delimiting by / instead of -, e.g. 12/31/2035 vs. 12-31-2035.
        """
        reporter = self._reporter(annotations=annotations)

        for policy in annotations:
            remediation_date = reporter._get_remediation_date(policy)
            if expected is None:
                assert remediation_date is None
            else:
                assert isinstance(remediation_date, str)
                assert expected is remediation_date

    @pytest.mark.parametrize(
        ("annotations", "expected"),
        [
            (
                {
                    "GWS.GMAIL.1.1v0.6": {
                        "comment": "This control is incorrectly marked as non-compliant.",
                        "incorrectresult": True,
                    }
                },
                True,
            ),
            ({}, False),
            ({"GWS.GMAIL.1.1v0.6": {}}, False),
            ({"GWS.GMAIL.1.1v0.6": {"comment": "Some comment"}}, False),
            ({"GWS.GMAIL.1.1v0.6": {"incorrectresult": False}}, False),
        ],
    )
    # pylint: disable=protected-access
    def test_is_control_marked_incorrect(self, annotations, expected):
        """
        Tests if Reporter_is_control_marked_incorrect() handles these cases:
            - returns True for cases where the control is marked as incorrect
            - returns False for invalid cases or when incorrectResult
              is set to false.
        """
        reporter = self._reporter(annotations=annotations)

        for policy in annotations:
            is_incorrect = reporter._is_control_marked_incorrect(policy)
            assert is_incorrect is expected

    def test_rego_json_to_ind_reports(
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
        # otherwise the local instance returned by _reporter() won't use the temp files.
        monkeypatch.setattr(Reporter, "_reporter_path", tmp, raising=True)

        reporter = self._reporter(
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
