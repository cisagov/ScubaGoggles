"""Unit tests for the ScubaGoggles report diff functionality."""

import argparse
import csv
import json
import re

import pytest

from scubagoggles.diff import (CLASSIFICATIONS,
                               CSV_FIELDS,
                               DIFF_REPORT_CSS,
                               Control,
                               _csv_safe,
                               _result_text_class,
                               _row_color,
                               compare,
                               result_category,
                               result_diff,
                               classify_pair,
                               run_diff,
                               split_version,
                               write_csv,
                               write_html)
from scubagoggles.main import get_diff_args

# Before result, after result, and the expected classification.
RESULT_DIFF_CASES = [
    # Landing on Fail
    ("Pass", "Fail", "NewFail"),
    ("Warning", "Fail", "NewFail"),
    ("Omitted", "Fail", "NewFail"),
    ("Incorrect result", "Fail", "NewFail"),
    ("Error", "Fail", "NewFail"),
    # Landing on Pass
    ("Fail", "Pass", "NewPass"),
    ("Warning", "Pass", "NewPass"),
    ("Omitted", "Pass", "NewPass"),
    ("Incorrect result", "Pass", "NewPass"),
    ("Error", "Pass", "NewPass"),
    ("Error - Test results missing", "Pass", "NewPass"),
    # Landing on Warning
    ("Pass", "Warning", "NewWarning"),
    ("Fail", "Warning", "NewWarning"),
    ("Omitted", "Warning", "NewWarning"),
    ("Incorrect result", "Warning", "NewWarning"),
    ("Error", "Warning", "NewWarning"),
    # Manual check becoming automated
    ("N/A", "Pass", "NewAutomatedCheck"),
    ("N/A", "Fail", "NewAutomatedCheck"),
    ("N/A", "Warning", "NewAutomatedCheck"),
    # Automated check becoming manual
    ("Pass", "N/A", "NewManualCheck"),
    ("Fail", "N/A", "NewManualCheck"),
    ("Warning", "N/A", "NewManualCheck"),
    ("Incorrect result", "N/A", "NewManualCheck"),
    ("Error", "N/A", "NewManualCheck"),
    # Remaining changes into or out of Omitted
    ("Pass", "Omitted", "NewOmission"),
    ("N/A", "Omitted", "NewOmission"),
    ("Omitted", "N/A", "NewOmission"),
    ("Incorrect result", "Omitted", "NewOmission"),
    ("Omitted", "SomeFutureResult", "NewOmission"),
    # Newly marked incorrect
    ("Pass", "Incorrect result", "NewIncorrectResult"),
    ("Fail", "Incorrect result", "NewIncorrectResult"),
    ("Omitted", "Incorrect result", "NewIncorrectResult"),
    # Errored keys off the after result, even when it is unchanged
    ("Pass", "Error", "Errored"),
    ("Pass", "Error - Test results missing", "Errored"),
    ("Error", "Error", "Errored"),
    # Unchanged
    ("Pass", "Pass", "Unchanged"),
    ("N/A", "N/A", "Unchanged"),
    ("Omitted", "Omitted", "Unchanged"),
    ("Incorrect result", "Incorrect result", "Unchanged"),
    ("pass", "Pass", "Unchanged"),
    # Other
    ("Other1", "Other2", "Other"),
    ("SomeFutureResult", "Pass", "Other"),
    ("", "Pass", "Other"),
    # "No events found": a log-based check that is already automated but has
    # no log event to assess yet
    ("No events found", "Pass", "NewPass"),
    ("No events found", "Fail", "NewFail"),
    ("No events found", "Warning", "NewWarning"),
    ("No events found", "N/A", "NewManualCheck"),
    ("N/A", "No events found", "NewLogBasedCheck"),
    ("Pass", "No events found", "NoLogEvents"),
    ("Fail", "No events found", "NoLogEvents"),
    ("Warning", "No events found", "NoLogEvents"),
    ("Error", "No events found", "NoLogEvents"),
    ("Error - Test results missing", "No events found", "NoLogEvents"),
    ("Omitted", "No events found", "NoLogEvents"),
    ("Incorrect result", "No events found", "NoLogEvents"),
    ("SomeFutureResult", "No events found", "NoLogEvents"),
    ("No events found", "Omitted", "NewOmission"),
    ("No events found", "Error", "Errored"),
    ("No events found", "No events found", "Unchanged"),
]

def report(controls):
    """Build a minimal ScubaGoggles report for testing."""
    return {
        "MetaData": {"Tool": "ScubaGoggles", "ToolVersion": "1.0.0"},
        "Results": {
            "commoncontrols": [
                {
                    "GroupName": "Test",
                    "GroupNumber": "1",
                    "Controls": controls,
                }
            ]
        },
    }


def control(control_id, result, **fields):
    """Build a minimal control for testing; fields override the defaults."""
    data = {
        "Control ID": control_id,
        "Requirement": "Requirement",
        "Result": result,
        "Criticality": "Shall",
        "Details": "details",
        "OriginalResult": result,
        "Comments": [],
        "ResolutionDate": None,
    }
    data.update(fields)
    return data


def records_by_id(result):
    """Map each diff record's control ID to the record, across products."""
    return {
        record["Control ID (After)"] or record["Control ID (Before)"]: record
        for records in result["Diff"].values()
        for record in records
    }


class TestDiff:
    """Test the report diff behavior."""

    @pytest.mark.parametrize(
        ("result", "expected"),
        [
            ("Pass", "Pass"),
            ("Fail", "Fail"),
            ("Warning", "Warning"),
            ("N/A", "NA"),
            ("No events found", "NoEvents"),
            ("Omitted", "Omitted"),
            ("Incorrect result", "Incorrect"),
            ("Error", "Error"),
            ("Error - Test results missing", "Error"),
            (" pass ", "Pass"),
            ("INCORRECT RESULT", "Incorrect"),
            ("SomeFutureResult", "Other"),
            ("", "Other"),
            (None, "Other"),
        ],
    )
    def test_result_category(self, result, expected):
        """Map open-ended Result strings to comparison categories."""
        assert result_category(result) == expected

    @pytest.mark.parametrize(("before", "after", "expected"), RESULT_DIFF_CASES)
    def test_result_diff(self, before, after, expected):
        """Classify every before/after result change."""
        assert result_diff(before, after) == expected

    def test_classify_pair(self):
        """ Classify Control Pair Changes """
        # template used for creating mock control instances for test cases
        control_template_dict = {
            "product":"",
            "group_name":"",
            "group_number":"",
            "control_id":"",
            "result":"",
            "criticality":"",
            "requirement":"",
            "details":"",
            "original_result":""
        }
        # Instance 1
        c_dict_1 = control_template_dict.copy()
        c_dict_1["control_id"] = "GWS.COMMONCONTROLS.1.1v1"
        c_dict_1["result"] = "Pass"
        c_1 = Control(**c_dict_1)
        # Instance 2
        c_dict_2 = control_template_dict.copy()
        c_dict_2["control_id"] = "GWS.COMMONCONTROLS.1.1v2"
        c_dict_2["result"] = "Fail"
        c_2 = Control(**c_dict_2)
        # Instance 3 (error result)
        c_dict_3 = c_dict_2.copy()
        c_dict_3["result"] = "Error"
        c_3 = Control(**c_dict_3)
        # Test cases:
        # test new/removed policy functionality
        assert classify_pair(None, c_1) == "NewPolicy"
        # test version changes are returned before other result
        # classifications from result_diff
        assert classify_pair(c_1, c_2) == "PolicyVersionUpdate"
        # No policy version detected, nor any errors, so result is unchanged
        assert classify_pair(c_1, c_1) == "Unchanged"
        # test Error change result takes precedence before version change
        assert classify_pair(c_1, c_3) == "Errored"


    def test_split_version_unmatched_control_id(self):
        """Control IDs without a version suffix are returned unchanged."""
        assert split_version("GWSUNMATCHEDPOLICY") == (
            "GWSUNMATCHEDPOLICY",
            None,
        )

    def test_split_version_is_case_insensitive(self):
        """Split version suffixes regardless of case."""
        assert split_version("GWS.COMMONCONTROLS.1.1v2") == (
            "GWS.COMMONCONTROLS.1.1",
            2,
        )
        assert split_version("GWS.COMMONCONTROLS.1.1V3") == (
            "GWS.COMMONCONTROLS.1.1",
            3,
        )

    def test_compare_new_removed_changed_and_version_update(self):
        """Classify new, removed, changed, and version-updated controls."""
        before = report(
            [
                control("GWS.COMMONCONTROLS.1.1v1", "Pass"),
                control("GWS.COMMONCONTROLS.1.2v1", "Fail"),
                control("GWS.COMMONCONTROLS.1.3v1", "Pass"),
            ]
        )
        after = report(
            [
                control("GWS.COMMONCONTROLS.1.1v2", "Fail"),
                control("GWS.COMMONCONTROLS.1.3v1", "Fail"),
                control("GWS.COMMONCONTROLS.1.4v1", "Pass"),
            ]
        )
        result = compare(before, after)
        classifications = {
            control_id: record["Classification"]
            for control_id, record in records_by_id(result).items()
        }
        assert classifications["GWS.COMMONCONTROLS.1.1v2"] == "PolicyVersionUpdate"
        assert classifications["GWS.COMMONCONTROLS.1.2v1"] == "RemovedPolicy"
        assert classifications["GWS.COMMONCONTROLS.1.3v1"] == "NewFail"
        assert classifications["GWS.COMMONCONTROLS.1.4v1"] == "NewPolicy"

    def test_compare_schema(self):
        """Emit the versioned, per-product diff schema."""
        before = report([control("GWS.COMMONCONTROLS.1.1v1", "Pass")])
        before["MetaData"].update({"ReportUUID": "before-uuid",
                                   "TimestampZulu": "2026-01-01T00:00:00.000Z",
                                   "TenantId": "not-copied"})
        after = report([control("GWS.COMMONCONTROLS.1.1v1", "Fail")])

        result = compare(before, after)

        assert list(result) == ["SchemaVersion", "MetaData", "Summary", "Diff"]
        assert result["SchemaVersion"] == "1.0"
        metadata = result["MetaData"]
        assert metadata["Tool"] == "ScubaGoggles"
        assert metadata["ToolVersion"]
        assert metadata["TimestampZulu"].endswith("Z")
        assert metadata["Before"] == {"ReportUUID": "before-uuid",
                                      "TimestampZulu": "2026-01-01T00:00:00.000Z",
                                      "ToolVersion": "1.0.0"}
        assert list(result["Diff"]) == ["commoncontrols"]
        assert list(result["Diff"]["commoncontrols"][0]) == [
            "Control ID (Before)",
            "Control ID (After)",
            "Requirement",
            "GroupName",
            "GroupNumber",
            "ResultBefore",
            "ResultAfter",
            "Classification",
            "CriticalityBefore",
            "CriticalityAfter",
            "DetailsAfter",
        ]

    def test_compare_summary_counts_only_present_classifications(self):
        """Summary counts follow the classification order and skip zeros."""
        before = report([
            control("GWS.COMMONCONTROLS.1.1v1", "Pass"),
            control("GWS.COMMONCONTROLS.1.2v1", "Fail"),
            control("GWS.COMMONCONTROLS.1.3v1", "Pass"),
        ])
        after = report([
            control("GWS.COMMONCONTROLS.1.1v1", "Pass"),
            control("GWS.COMMONCONTROLS.1.2v1", "Pass"),
            control("GWS.COMMONCONTROLS.1.3v1", "Fail"),
        ])

        summary = compare(before, after)["Summary"]

        assert summary == {"commoncontrols": {"Unchanged": 1, "NewPass": 1, "NewFail": 1}}
        assert list(summary["commoncontrols"]) == ["NewFail", "NewPass", "Unchanged"]

    def test_compare_products_only_in_one_report(self):
        """List products present in only one report and drop empty ones."""
        before = report([control("GWS.COMMONCONTROLS.1.1v1", "Pass")])
        before["Results"]["drive"] = [
            {"GroupName": "D", "GroupNumber": "1",
             "Controls": [control("GWS.DRIVE.1.1v1", "Pass")]}
        ]
        after = report([control("GWS.COMMONCONTROLS.1.1v1", "Pass")])
        after["Results"]["calendar"] = []

        result = compare(before, after)

        assert result["MetaData"]["ProductsOnlyInBefore"] == ["drive"]
        assert result["MetaData"]["ProductsOnlyInAfter"] == ["calendar"]
        assert list(result["Diff"]) == ["commoncontrols", "drive"]
        assert result["Diff"]["drive"][0]["Classification"] == "RemovedPolicy"

    def test_compare_orders_controls_numerically(self):
        """Order group and policy numbers numerically, not as text."""
        ids = ["GWS.COMMONCONTROLS.10.1v1",
               "GWS.COMMONCONTROLS.2.1v1",
               "GWS.COMMONCONTROLS.1.10v1",
               "GWS.COMMONCONTROLS.1.2v1"]
        reports = report([control(control_id, "Pass") for control_id in ids])

        records = compare(reports, reports)["Diff"]["commoncontrols"]

        assert [record["Control ID (After)"] for record in records] == [
            "GWS.COMMONCONTROLS.1.2v1",
            "GWS.COMMONCONTROLS.1.10v1",
            "GWS.COMMONCONTROLS.2.1v1",
            "GWS.COMMONCONTROLS.10.1v1",
        ]

    def test_compare_converts_html_to_plain_text(self):
        """Store Requirement and DetailsAfter as plain text."""
        requirement = ('Disable &quot;X&quot;.<div class="badges">\n'
                       '<a href="#"><span>Automated Check</span></a></div>\n')
        details = "Requirement not met.<br><br><ul><li>OU &amp; group</li></ul>"
        reports = report([control("GWS.COMMONCONTROLS.1.1v1", "Fail",
                                  Requirement=requirement, Details=details)])

        record = compare(reports, reports)["Diff"]["commoncontrols"][0]

        assert record["Requirement"] == 'Disable "X".'
        assert record["DetailsAfter"] == "Requirement not met. OU & group"

    def test_compare_incorrect_result_fields(self):
        """Report the marking and underlying result when a side is marked."""
        before = report([
            control("GWS.COMMONCONTROLS.1.1v1", "Pass"),
            control("GWS.COMMONCONTROLS.1.2v1", "Pass"),
        ])
        after = report([
            control("GWS.COMMONCONTROLS.1.1v1", "Incorrect result", OriginalResult="Fail"),
            control("GWS.COMMONCONTROLS.1.2v1", "Fail"),
        ])

        records = records_by_id(compare(before, after))

        marked = records["GWS.COMMONCONTROLS.1.1v1"]
        assert marked["Classification"] == "NewIncorrectResult"
        assert marked["MarkedIncorrectBefore"] is False
        assert marked["MarkedIncorrectAfter"] is True
        assert marked["UnderlyingResultBefore"] == "Pass"
        assert marked["UnderlyingResultAfter"] == "Fail"
        unmarked = records["GWS.COMMONCONTROLS.1.2v1"]
        assert "MarkedIncorrectAfter" not in unmarked
        assert "UnderlyingResultAfter" not in unmarked

    def test_compare_fail_to_fail_annotations(self):
        """Compare annotations only for controls failing in both reports."""
        ids = ["GWS.COMMONCONTROLS.1.1v1",
               "GWS.COMMONCONTROLS.1.2v1",
               "GWS.COMMONCONTROLS.1.3v1"]
        before = report([control(ids[0], "Fail"),
                         control(ids[1], "Fail"),
                         control(ids[2], "Pass")])
        before["AnnotatedFailedPolicies"] = {
            ids[1]: {"Comment": "Planned", "RemediationDate": "2026-12-31"},
        }
        after = report([control(ids[0], "Fail"),
                        control(ids[1], "Fail"),
                        control(ids[2], "Fail")])
        after["AnnotatedFailedPolicies"] = {
            ids[0]: {"Comment": "New note", "RemediationDate": None},
            ids[1]: {"Comment": "Planned", "RemediationDate": "2026-12-31"},
            ids[2]: {"Comment": "Regressed", "RemediationDate": None},
        }

        records = records_by_id(compare(before, after))

        assert records[ids[0]]["AnnotationChanged"] is True
        assert records[ids[0]]["Comment"] == "New note"
        assert records[ids[1]]["AnnotationChanged"] is False
        assert records[ids[1]]["RemediationDate"] == "2026-12-31"
        assert "AnnotationChanged" not in records[ids[2]]

    def test_write_csv(self, tmp_path):
        """Write one row per control with every column on every row."""
        before = report([
            control("GWS.COMMONCONTROLS.1.1v1", "Pass"),
            control("GWS.COMMONCONTROLS.1.2v1", "Pass"),
        ])
        after = report([
            control("GWS.COMMONCONTROLS.1.1v1", "Pass"),
            control("GWS.COMMONCONTROLS.1.2v1", "Fail", Details="=HYPERLINK(1)"),
        ])
        path = tmp_path / "diff.csv"

        write_csv(compare(before, after), path)

        with path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        assert list(rows[0]) == list(CSV_FIELDS)
        assert [row["Classification"] for row in rows] == ["Unchanged", "NewFail"]
        assert rows[0]["Product"] == "commoncontrols"
        assert rows[0]["MarkedIncorrectAfter"] == ""
        assert rows[1]["DetailsAfter"] == "'=HYPERLINK(1)"

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("=1+1", "'=1+1"),
            ("+1", "'+1"),
            ("-1", "'-1"),
            ("@SUM(A1)", "'@SUM(A1)"),
            ("\tcmd", "'\tcmd"),
            ("plain", "plain"),
            ("", ""),
            (None, None),
            (True, True),
        ],
    )
    def test_csv_safe(self, value, expected):
        """Prefix values a spreadsheet would read as a formula."""
        assert _csv_safe(value) == expected

    def test_run_diff_default_file_names(self, tmp_path):
        """Write three separate outputs with the default file names."""
        before_path = tmp_path / "before.json"
        after_path = tmp_path / "after.json"
        before_path.write_text(
            json.dumps(report([control("GWS.COMMONCONTROLS.1.1v1", "Pass")])),
            encoding="utf-8",
        )
        after_path.write_text(
            json.dumps(report([control("GWS.COMMONCONTROLS.1.1v1", "Fail")])),
            encoding="utf-8",
        )
        out_dir = tmp_path / "diff"

        paths = run_diff(before_path, after_path, outputpath=out_dir, quiet=True)

        assert paths == {
            "JsonPath": out_dir / "DiffResults.json",
            "CsvPath": out_dir / "DiffResults.csv",
            "ReportPath": out_dir / "DiffReport.html",
        }
        assert json.loads(paths["JsonPath"].read_text(encoding="utf-8"))["Diff"]
        assert paths["CsvPath"].read_text(encoding="utf-8").startswith("Product,")
        assert paths["ReportPath"].read_text(encoding="utf-8").startswith("<!doctype html>")

    def test_run_diff_custom_file_names(self, tmp_path):
        """Custom base names get the matching extension appended."""
        before_path = tmp_path / "before.json"
        before_path.write_text(
            json.dumps(report([control("GWS.COMMONCONTROLS.1.1v1", "Pass")])),
            encoding="utf-8",
        )

        paths = run_diff(before_path,
                         before_path,
                         outputpath=tmp_path,
                         outjsonfilename="Q2Json",
                         outcsvfilename="Q2Csv",
                         outreportfilename="Q2Report",
                         quiet=True)

        assert paths["JsonPath"].name == "Q2Json.json"
        assert paths["CsvPath"].name == "Q2Csv.csv"
        assert paths["ReportPath"].name == "Q2Report.html"
        assert all(path.exists() for path in paths.values())

    def test_diff_cli_arguments(self):
        """The diff subcommand requires both reports and defaults the rest."""
        parser = argparse.ArgumentParser()
        get_diff_args(parser)

        args = parser.parse_args(["--beforepath", "b.json", "--afterpath", "a.json"])

        assert args.beforepath.name == "b.json"
        assert args.afterpath.name == "a.json"
        assert args.outputpath is None
        assert args.outjsonfilename == "DiffResults"
        assert args.outcsvfilename == "DiffResults"
        assert args.outputreportfilename == "DiffReport"
        assert args.darkmode == "false"
        assert args.quiet is False


class TestDiffHtmlReport:
    """Test the HTML diff report."""

    def test_classification_order(self):
        """Lay classifications out in severity tiers, Unchanged last."""
        assert CLASSIFICATIONS == (
            "Errored", "NewFail",
            "NewWarning",
            "NewIncorrectResult", "PolicyVersionUpdate", "NewOmission", "NoLogEvents", "Other",
            "NewAutomatedCheck", "NewManualCheck", "NewLogBasedCheck",
            "NewPass", "NewPolicy", "RemovedPolicy",
            "Unchanged",
        )

    @pytest.mark.parametrize(
        ("classification", "result_after", "expected"),
        [
            ("NewFail", "Fail", "red"),
            ("Errored", "Error", "red"),
            ("Errored", "Error - Test results missing", "red"),
            ("NewWarning", "Warning", "yellow"),
            ("NewPass", "Pass", "green"),
            ("NewAutomatedCheck", "Fail", "red"),
            ("PolicyVersionUpdate", "Pass", "green"),
            ("NewManualCheck", "N/A", "grey"),
            ("NoLogEvents", "No events found", "grey"),
            ("NewOmission", "Omitted", "grey"),
            ("NewIncorrectResult", "Incorrect result", "grey"),
            ("RemovedPolicy", None, "grey"),
        ],
    )
    def test_row_color_follows_result_after(self, classification, result_after, expected):
        """Color rows by the current result, not by the classification."""
        record = {"Classification": classification, "ResultAfter": result_after}
        assert _row_color(record) == expected

    def test_write_html(self, tmp_path):
        """Render the summary, filters, product tables, and row details."""
        before = report([
            control("GWS.COMMONCONTROLS.1.1v1", "Pass"),
            control("GWS.COMMONCONTROLS.1.2v1", "Pass"),
            control("GWS.COMMONCONTROLS.1.3v1", "Pass"),
        ])
        before["Results"]["drive"] = [
            {"GroupName": "D", "GroupNumber": "1",
             "Controls": [control("GWS.DRIVE.1.1v1", "Pass")]}
        ]
        after = report([
            control("GWS.COMMONCONTROLS.1.1v2", "Fail", Details="<script>x</script>"),
            control("GWS.COMMONCONTROLS.1.2v1", "Incorrect result", OriginalResult="Fail"),
            control("GWS.COMMONCONTROLS.1.3v1", "Pass"),
        ])
        path = tmp_path / "report.html"

        write_html(compare(before, after), path)
        page = path.read_text(encoding="utf-8")

        assert "<title>ScubaGoggles Diff Report</title>" in page
        # Every classification but Unchanged has a filter checkbox, in order.
        toggles = re.findall(r'class="classification-toggle" data-classification="(\w+)"', page)
        assert toggles == [name for name in CLASSIFICATIONS if name != "Unchanged"]
        assert '<td class="summary-total">3</td>' in page
        # Product sections use the product's full name.
        assert "<h2>Common Controls</h2>" in page
        assert "Products only in Before (all controls Removed Policy):</strong> " \
               "Google Drive and Docs" in page
        # Row details.
        assert "GWS.COMMONCONTROLS.1.1v1 &rarr; GWS.COMMONCONTROLS.1.1v2" in page
        assert "(underlying: Fail)" in page
        assert 'class="diff-row diff-green diff-unchanged-row" data-classification="Unchanged"' \
               in page
        assert '<td class="result-cell result-fail">Fail</td>' in page
        assert "<script>x</script>" not in page
        assert '<script id="dark-mode-flag" type="application/json">false</script>' in page

    def test_write_html_dark_mode(self, tmp_path):
        """Open the report in dark mode when asked."""
        reports = report([control("GWS.COMMONCONTROLS.1.1v1", "Pass")])
        path = tmp_path / "report.html"

        write_html(compare(reports, reports), path, darkmode=True)

        assert '<script id="dark-mode-flag" type="application/json">true</script>' \
               in path.read_text(encoding="utf-8")

    def test_products_follow_run_order(self, tmp_path):
        """List products in the order a ScubaGoggles run reports them."""
        reports = {"MetaData": {}, "Results": {}}
        for product in ("gmail", "calendar", "commoncontrols"):
            reports["Results"][product] = [
                {"GroupName": "G", "GroupNumber": "1",
                 "Controls": [control(f"GWS.{product.upper()}.1.1v1", "Pass")]}
            ]
        result = compare(reports, reports)
        path = tmp_path / "report.html"

        write_html(result, path)

        assert list(result["Diff"]) == ["calendar", "commoncontrols", "gmail"]
        assert list(result["Summary"]) == ["calendar", "commoncontrols", "gmail"]
        headings = re.findall(r"<h2>([^<]+)</h2>", path.read_text(encoding="utf-8"))
        assert headings == ["Summary", "Google Calendar", "Common Controls", "Gmail"]

    def test_legend_lists_fail_and_error_separately(self, tmp_path):
        """Give Error its own legend entry, though it shares Fail's color."""
        reports = report([control("GWS.COMMONCONTROLS.1.1v1", "Pass")])
        path = tmp_path / "report.html"

        write_html(compare(reports, reports), path)
        page = path.read_text(encoding="utf-8")

        assert '<span class="swatch diff-red"></span>Fail (Result After)</span>' in page
        assert '<span class="swatch diff-red"></span>Error (Result After)</span>' in page

    @pytest.mark.parametrize(
        ("result", "expected"),
        [
            ("Pass", "result-pass"),
            ("Fail", "result-fail"),
            ("Warning", "result-warning"),
            (" PASS ", "result-pass"),
            ("N/A", ""),
            ("No events found", ""),
            ("Omitted", ""),
            ("Error", ""),
            ("Incorrect result", ""),
            ("Bug", ""),
            ("", ""),
            (None, ""),
        ],
    )
    def test_result_text_class(self, result, expected):
        """Color only Pass, Fail, and Warning result text."""
        assert _result_text_class(result) == expected

    def test_write_html_result_text_colors(self, tmp_path):
        """Color both result cells so a Pass -> Fail change is visible."""
        before = report([
            control("GWS.COMMONCONTROLS.1.1v1", "Pass"),
            control("GWS.COMMONCONTROLS.1.2v1", "Pass"),
            control("GWS.COMMONCONTROLS.1.3v1", "Pass"),
            control("GWS.COMMONCONTROLS.1.4v1", "Pass"),
            control("GWS.COMMONCONTROLS.1.5v1", "Pass"),
        ])
        after = report([
            control("GWS.COMMONCONTROLS.1.1v1", "Fail"),
            control("GWS.COMMONCONTROLS.1.2v1", "Warning"),
            control("GWS.COMMONCONTROLS.1.3v1", "N/A"),
            control("GWS.COMMONCONTROLS.1.4v1", "Omitted"),
            control("GWS.COMMONCONTROLS.1.5v1", "Error"),
        ])
        path = tmp_path / "report.html"

        write_html(compare(before, after), path)
        page = path.read_text(encoding="utf-8")

        assert re.search(r'<td class="result-cell result-pass">Pass</td>\s*'
                         r'<td class="result-cell result-fail">Fail</td>', page)
        assert '<td class="result-cell result-warning">Warning</td>' in page
        for result in ("N/A", "Omitted", "Error"):
            assert f'<td class="result-cell">{result}</td>' in page
        assert not re.search(r'result-cell result-\w+">(N/A|Omitted|Error)<', page)

    def test_report_css_colors(self):
        """Define result text colors and table lines for both themes."""
        css = DIFF_REPORT_CSS.read_text(encoding="utf-8")

        for variable in ("--result-pass-color", "--result-fail-color",
                         "--result-warning-color", "--table-border-color"):
            # Once under :root (light) and once under html[data-theme='dark'].
            assert css.count(f"{variable}:") == 2, variable
        assert re.search(r"html\[data-theme='dark'\][\s\S]*--result-pass-color", css)
        assert re.search(r"--table-border-color:\s*black;", css)
        assert re.search(r"--table-border-color:\s*#7b7b7b;", css)
        assert re.search(r"th, td \{[\s\S]*?border: 1px solid var\(--table-border-color\);",
                         css)
