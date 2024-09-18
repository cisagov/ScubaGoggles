"""
smoke_test.py declares a SmokeTest class for ScubaGoggles automation testing.
"""

import subprocess
import os
import pytest
from smoke_test_utils import (
    get_output_path,
    prepend_file_protocol,
    get_required_entries,
    verify_all_outputs_exist,
    verify_output_type,
    run_selenium,
    verify_scubaresults,
)

SAMPLE_REPORT = "sample-report"
SCUBA_RESULTS = "ScubaResults.json"
BASELINE_REPORTS = "BaselineReports.html"

class SmokeTest:
    """
    Pytest class to encapsulate the following test cases:

    - Generate the correct output files (BaselineReports.html, ScubaResults.json, etc)
    - Check the content of html files, verify href attributes are correct, etc
    - Check if ScubaResults.json contains errors in the summary. If errors exist, then
      either API calls or functions produced exceptions which need to be handled
    """
    def test_scubagoggles_output(self, subjectemail):
        """
        Test if the `scubagoggles gws` command generates correct output for all baselines.
        
        Args:
            subjectemail: The email address of a user for the service account
        """
        try:
            command: str = f"scubagoggles gws --subjectemail {subjectemail} --quiet"
            subprocess.run(command, shell=True, check=True)
            output_path: str = get_output_path()
            output: list = verify_output_type(output_path, [])
            required_entries = get_required_entries(os.path.join(os.getcwd(), SAMPLE_REPORT), [])
            verify_all_outputs_exist(output, required_entries)
        except (OSError, ValueError, Exception) as e:
            pytest.fail(f"An error occurred, {e}")

    def test_scubaresults(self):
        """
        Determine if ScubaResults.json contains API errors or exceptions.
        """
        try:
            output_path: str = get_output_path()
            scubaresults_path: str = os.path.join(output_path, SCUBA_RESULTS)
            with open(scubaresults_path, encoding="utf-8") as jsonfile:
                verify_scubaresults(jsonfile)
        except (ValueError, Exception) as e:
            pytest.fail(f"An error occurred, {e}")

    def test_scubagoggles_report(self, browser, customerdomain):
        """
        Test if the generated baseline reports are correct,
        i.e. BaselineReports.html, CalendarReport.html, ChatReport.html
        """
        try:
            output_path: str = get_output_path()
            report_path: str = prepend_file_protocol(os.path.join(output_path, BASELINE_REPORTS))
            browser.get(report_path)
            run_selenium(browser, customerdomain)
        except (ValueError, AssertionError, Exception) as e:
            browser.quit()
            pytest.fail(f"An error occurred, {e}")
