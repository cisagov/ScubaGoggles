import re
from scubagoggles.reporter.reporter import Reporter

class TestReporter:
    """Unit tests for the Reporter class."""
    def test_create_html_table_empty(self):
        assert Reporter.create_html_table([]) == ""

def test_create_html_table_tenant_info():
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


def test_create_html_table_control_info():
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
