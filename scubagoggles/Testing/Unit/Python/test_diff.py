"""Unit tests for the ScubaGoggles report diff functionality."""

from scubagoggles.diff import compare, result_diff, split_version


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
