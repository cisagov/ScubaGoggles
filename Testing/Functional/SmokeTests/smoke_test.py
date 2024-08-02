"""
smoke_test.py is a test script to verify `scubagoggles gws` output.

It checks for the following cases:
- Generate the correct output files (BaselineReports.html, ScubaResults.json, etc)
- Check the content of html files, verify href attributes are correct, etc
- Check if ScubaResults.json contains errors in the summary. If errors exist, then 
  either API calls or functions produced exceptions which need to be handled
"""

import pytest
import subprocess
import os
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
    def test_scubagoggles_output(self, subjectemail):
        try:
            command: str = f"scubagoggles gws --subjectemail {subjectemail} --quiet"
            subprocess.run(command, shell=True)
            output_path: str = get_output_path()
            output: list = verify_output_type(output_path, [])
            required_entries = get_required_entries(os.path.join(os.getcwd(), SAMPLE_REPORT), [])
            verify_all_outputs_exist(output, required_entries)
        except (OSError, ValueError, Exception) as e:
            pytest.fail(f"An error occurred, {e}")
    
    def test_scubaresults(self):
        try:
            output_path: str = get_output_path()
            scubaresults_path: str = os.path.join(output_path, SCUBA_RESULTS)
            with open(scubaresults_path) as jsonfile:
                verify_scubaresults(jsonfile)
        except ValueError as e:
            pytest.fail(f"{scubaresults_path} contains invalid json, {e}")
        except Exception as e:
            pytest.fail(f"An error occurred, {e}")

    def test_scubagoggles_report(self, browser, domain):
        try:
            output_path: str = get_output_path()
            report_path: str = prepend_file_protocol(os.path.join(output_path, BASELINE_REPORTS))
            browser.get(report_path)
            run_selenium(browser, domain)
        except (ValueError, Exception) as e:
            browser.quit()
            pytest.fail(f"An error occurred, {e}")