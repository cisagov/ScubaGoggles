"""Unit tests for the ScubaGoggles report diff functionality."""

import argparse
import json

from scubagoggles.diff import (Control,
                               compare,
                               result_diff,
                               classify_pair,
                               run_diff,
                               split_version)
from scubagoggles.main import get_diff_args

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


def control(control_id, result):
    """Build a minimal control for testing."""
    return {
        "Control ID": control_id,
        "Requirement": "Requirement",
        "Result": result,
        "Criticality": "Shall",
        "Details": "details",
        "OriginalResult": result,
        "Comments": [],
        "ResolutionDate": None,
    }


class TestDiff:
    """Test the report diff behavior."""

    def test_result_diff(self):
        """Classify result changes."""
        assert result_diff("Pass", "Fail") == "NewFail"
        assert result_diff("Fail", "Pass") == "NewPass"
        assert result_diff("Pass", "N/A") == "NewManualCheck"
        assert result_diff("Pass", "Omitted") == "NewOmission"
        assert result_diff("Pass", "Error") == "Errored"
        assert result_diff("Other1", "Other2") == "Other"
        assert result_diff("Error", "N/A") == "NewManualCheck"

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
            "comments":tuple(),
            "resolution_date":None,
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
            r["Control ID (After)"] or r["Control ID (Before)"]: r["Classification"]
            for r in result["Records"]
        }
        assert classifications["GWS.COMMONCONTROLS.1.1v2"] == "PolicyVersionUpdate"
        assert classifications["GWS.COMMONCONTROLS.1.2v1"] == "RemovedPolicy"
        assert classifications["GWS.COMMONCONTROLS.1.3v1"] == "NewFail"
        assert classifications["GWS.COMMONCONTROLS.1.4v1"] == "NewPolicy"

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
        assert json.loads(paths["JsonPath"].read_text(encoding="utf-8"))["Records"]
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
        assert args.quiet is False
