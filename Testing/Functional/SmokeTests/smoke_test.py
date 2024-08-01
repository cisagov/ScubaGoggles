"""
smoke_test.py is a test script to verify `scubagoggles gws`
generates the correct outputs (i.e., directories, files).
"""

import pytest
import subprocess
import os
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions
from smoke_test_utils import get_output_path, verify_all_outputs_exist, verify_output_type

class SmokeTest:
    def test_scubagoggles_output(self, subjectemail):
        try:
            command: str = f"scubagoggles gws --subjectemail {subjectemail} --quiet"
            subprocess.run(command, shell=True)

            output_path: str = get_output_path()
            contents: list[str] = verify_output_type(output_path, [])
            verify_all_outputs_exist(contents)
        except (OSError, ValueError, Exception) as e:
            pytest.fail(f"An error occurred, {e}")

    def test_scubagoggles_report(self, browser, domain):
        try:
            output_path: str = get_output_path()
            browser.get("file://" + os.path.join(output_path, "BaselineReports.html"))

            h1 = browser.find_element(By.TAG_NAME, "h1").text
            assert h1 == "SCuBA GWS Security Baseline Conformance Reports"

            # verify domain is present in agency table
            agency_table = browser.find_element(By.TAG_NAME, "table")
            tbody = agency_table.find_element(By.TAG_NAME, "tbody")
            rows = tbody.find_elements(By.TAG_NAME, "tr")
            assert len(rows) == 2
            assert rows[1].find_elements(By.TAG_NAME, "td")[0].text == domain

            baseline_names = [
                "Google Calendar", 
                "Google Chat", 
                "Google Classroom", 
                "Common Controls", 
                "Google Drive and Docs",
                "Gmail",
                "Groups for Business",
                "Google Meet",
                "Rules",
                "Google Sites"
            ]

            for i in range(10): 
                reports_table = browser.find_elements(By.TAG_NAME, "table")[1]
                tbody = reports_table.find_element(By.TAG_NAME, "tbody")
                rows = tbody.find_elements(By.TAG_NAME, "tr")
                td = rows[i].find_elements(By.TAG_NAME, "td")[0]
                assert td.text in baseline_names

                individual_report_anchor = td.find_element(By.TAG_NAME, "a")
                href = individual_report_anchor.get_attribute("href")
                individual_report_anchor.click()
                current_url = browser.current_url
                assert href == current_url

                browser.back()
                WebDriverWait(browser, 10).until(
                    expected_conditions.presence_of_element_located(
                        (By.TAG_NAME, "body")
                    )
                )
                
            # Navigation to detailed reports 

            # Check links work

            # Verify tables are populated


        except Exception as e:
            pytest.fail(f"An error occurred, {e}")