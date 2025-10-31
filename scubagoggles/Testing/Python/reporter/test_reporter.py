from pathlib import Path
import re
import pytest

import scubagoggles as scubagoggles_pkg
from scubagoggles.reporter.reporter import Reporter
from scubagoggles.version import Version

class TestReporter:
    """Unit tests for the Reporter class."""
    def _reporter_factory(
        self,
        product: str = "gmail",
        tenant_id: str = "ABCDEFG",
        tenant_name: str = "Cool Example Org",
        tenant_domain: str = "example.org",
        main_report_name: str = "Baseline Reports",
        prod_to_fullname: dict = {
            "gmail": "Gmail"
        },
        product_policies: list = [],
        successful_calls: set = {},
        unsuccessful_calls: set = {},
        missing_policies: set = {},
        dns_logs: dict = {},
        omissions: dict = {},
        annotations: dict = {},
        progress_bar=None,
    ) -> Reporter:
        return Reporter(
            product,
            tenant_id,
            tenant_name,
            tenant_domain,
            main_report_name,
            prod_to_fullname,
            product_policies,
            successful_calls,
            unsuccessful_calls,
            missing_policies,
            dns_logs,
            omissions,
            annotations,
            progress_bar
        )

    def test_create_html_table_empty(self):
        assert Reporter.create_html_table([]) == ""

    def test_create_html_table_tenant_info(self):
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

        html = Reporter.create_html_table(rows)
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

        html = Reporter.create_html_table(rows)

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
        tmp = tmp_path
        (tmp / "FrontPageReport").mkdir(parents=True)
        (tmp / "styles").mkdir(parents=True)
        (tmp / "scripts").mkdir(parents=True)
        (tmp / "templates").mkdir(parents=True)

        pkg_root = Path(scubagoggles_pkg.__file__).resolve().parent
        front_page_template = pkg_root / "reporter" / "FrontPageReport" / "FrontPageReportTemplate.html"
        front_page_html = front_page_template.read_text(encoding="utf-8")
        (tmp / "FrontPageReport" / "FrontPageReportTemplate.html").write_text(front_page_html, encoding="utf-8")

        dark_mode_toggle_template = pkg_root / "reporter" / "templates" / "DarkModeToggleTemplate.html"
        dark_mode_toggle_html = dark_mode_toggle_template.read_text(encoding="utf-8")
        (tmp / "templates" / "DarkModeToggleTemplate.html").write_text(dark_mode_toggle_html, encoding="utf-8")

        (tmp / "styles" / "FrontPageStyle.css").write_text("main {}\n footer {}", encoding="utf-8")
        (tmp / "styles" / "main.css").write_text(":root {}", encoding="utf-8")
        (tmp / "scripts" / "main.js").write_text("const testVar = 0;", encoding="utf-8")

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

        html = Reporter.build_front_page_html(
            fragments,
            tenant_info,
            report_uuid,
            darkmode="on",
        )

        assert Version.current in html

        assert "{{" not in html and "}}" not in html
        assert "<style>" in html and "</style>" in html
        assert "main {}" in html and "footer {}" in html
        assert ":root {}" in html
        assert "<script>" in html and "</script>" in html
        assert "const testVar = 0;" in html

        assert "sgr_settings" in html and "data-darkmode=\"on\"" in html

        assert "First" in html and "Second" in html
        assert report_uuid in html

        assert all(th in html for th in ["Customer Name", "Customer Domain", "Customer ID"])
        assert all(td in html for td in ["Cool Example Org", "example.org", "ABCDEFG"])
        
    def test_is_control_omitted_returns_true_for_omitted_controls(self):
        omissions = {
            "GWS.GMAIL.1.1v0.6": {
                "rationale": "Accepting risk for now, will reevaluate at a later date.",
                "expiration": "2035-12-31",
            },
            "GWS.GMAIL.1.2v0.6": {
                "rationale": "Accepting risk for now, will reevaluate at a later date.",
                "expiration": "2035-12-31",
            },
        }
        reporter = self._reporter_factory(omissions=omissions)

        assert reporter._is_control_omitted("GWS.GMAIL.1.1v0.6") is True
        assert reporter._is_control_omitted("GWS.GMAIL.1.2v0.6") is True

    def test_is_control_omitted_returns_false_for_controls_with_past_expiration(self):
        omissions = {
            "GWS.GMAIL.1.1v0.6": {
                "rationale": "Accepting risk for now, will reevaluate at a later date.",
                "expiration": "2020-12-31",
            },
            "GWS.GMAIL.1.2v0.6": {
                "rationale": "Accepting risk for now, will reevaluate at a later date.",
                "expiration": "2020-12-31",
            },
        }
        reporter = self._reporter_factory(omissions=omissions)

        assert reporter._is_control_omitted("GWS.GMAIL.1.1v0.6") is False
        assert reporter._is_control_omitted("GWS.GMAIL.1.2v0.6") is False
        




