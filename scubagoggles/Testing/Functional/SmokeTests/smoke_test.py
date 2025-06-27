"""
smoke_test.py declares a SmokeTest class for ScubaGoggles automation testing.
"""

import subprocess

import pytest

from smoke_test_utils import (get_output_path,
                              get_required_entries,
                              run_selenium,
                              sample_report_dir,
                              top_report_url,
                              verify_all_outputs_exist,
                              verify_output_type,
                              verify_scubaresults)


class SmokeTest:
    """
    Pytest class to encapsulate the following test cases:

    - Generate the correct output files (BaselineReports.html,
      ScubaResults.json, etc)
    - Check the content of html files, verify href attributes are
      correct, etc
    - Check if ScubaResults.json contains errors in the summary. If errors
      exist, then either API calls or functions produced exceptions which
      need to be handled
    """

    @staticmethod
    def test_scubagoggles_output(subjectemail: str):
        """
        Test if the `scubagoggles gws` command generates correct output for
        all baselines.

        Args:
            subjectemail: The email address of a user for the service account.
            If None (or the empty string), the user's OAuth credentials are
            used instead.
        """

        svc_account_option = (f' --subjectemail {subjectemail}' if subjectemail
                              else '')
        command = f'scubagoggles gws{svc_account_option} --quiet '

        try:
            subprocess.run(command, shell=True, check=True)
            output_path = get_output_path()
            output: list = verify_output_type(output_path, [])
            report_dir = sample_report_dir()
            required_entries = get_required_entries(report_dir, [])
            verify_all_outputs_exist(output, required_entries)
        except (OSError, ValueError, Exception) as e:
            pytest.fail(f'An error occurred, {e}')

    @staticmethod
    def test_scubaresults():
        """
        Determine if ScubaResults.json contains API errors or exceptions.
        """
        try:
            output_path = get_output_path()
            verify_scubaresults(output_path)
        except (ValueError, Exception) as e:
            pytest.fail(f'An error occurred, {e}')

    @staticmethod
    def test_scubagoggles_report(browser, customerdomain):
        """
        Test if the generated baseline reports are correct,
        i.e. BaselineReports.html, CalendarReport.html, ChatReport.html
        """
        try:
            output_path = get_output_path()
            report_path: str = top_report_url(output_path)
            browser.get(report_path)
            run_selenium(browser, customerdomain)
        except (ValueError, AssertionError, Exception) as e:
            browser.quit()
            pytest.fail(f'An error occurred, {e}')
