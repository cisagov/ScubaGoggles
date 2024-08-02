"""
smoke_test.py is a test script to verify `scubagoggles gws`.

It checks for the following cases:
- Generate the correct output files (BaselineReports.html, ScubaResults.json, etc)
- Check the content of html files, verify href attributes are correct, etc
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
)
class SmokeTest:
    def test_scubagoggles_output(self, subjectemail):
        try:
            command: str = f"scubagoggles gws --subjectemail {subjectemail} --quiet"
            subprocess.run(command, shell=True)
            output_path: str = get_output_path()
            output: list[str] = verify_output_type(output_path, [])
            required_entries = get_required_entries(os.path.join(os.getcwd(), "sample-report"), [])
            verify_all_outputs_exist(output, required_entries)
        except (OSError, ValueError, Exception) as e:
            pytest.fail(f"An error occurred, {e}")

    def test_scubagoggles_report(self, browser, domain):
        try:
            output_path: str = get_output_path()
            report_path: str = prepend_file_protocol(os.path.join(output_path, "BaselineReports.html"))
            browser.get(report_path)
            run_selenium(browser, domain)
        except (ValueError, Exception) as e:
            browser.quit()
            pytest.fail(f"An error occurred, {e}")