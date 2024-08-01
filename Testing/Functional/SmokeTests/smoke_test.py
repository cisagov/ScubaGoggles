"""
smoke_test.py is a test script to verify `scubagoggles gws`.

It checks for the following cases:
- Generate the correct output files (BaselineReports.html, ScubaResults.json, etc)
- Check the content of html files, verify href attributes are correct, etc
"""

import pytest
import subprocess
import os
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions
from smoke_test_utils import (
    get_output_path, 
    prepend_file_protocol, 
    verify_all_outputs_exist, 
    verify_output_type,
)
from scubagoggles.orchestrator import gws_products

class SmokeTest:
    def test_scubagoggles_output(self, subjectemail):
        try:
            command: str = f"scubagoggles gws --subjectemail {subjectemail} --quiet"
            subprocess.run(command, shell=True)

            output_path: str = get_output_path()
            output: list[str] = verify_output_type(output_path, [])
            verify_all_outputs_exist(output)
        except (OSError, ValueError, Exception) as e:
            pytest.fail(f"An error occurred, {e}")

    def test_scubagoggles_report(self, browser, domain):
        try:
            output_path: str = get_output_path()
            report_path: str = prepend_file_protocol(os.path.join(output_path, "BaselineReports.html"))
            browser.get(report_path)

            h1 = browser.find_element(By.TAG_NAME, "h1").text
            assert h1 == "SCuBA GWS Security Baseline Conformance Reports"

            products = {
                product: { "title": f"{product} Baseline Report" }
                for product in gws_products()["prod_to_fullname"].values()
            }

            print(products)

            # Before entering loop check that we actually display 10 rows in table

            for i in range(10): 
                # verify domain is present in agency table
                tenant_table = browser.find_element(By.TAG_NAME, "table")
                tbody = tenant_table.find_element(By.TAG_NAME, "tbody")
                rows = tbody.find_elements(By.TAG_NAME, "tr")
                assert len(rows) == 2
                assert rows[1].find_elements(By.TAG_NAME, "td")[0].text == domain

                reports_table = browser.find_elements(By.TAG_NAME, "table")[1]
                tbody = reports_table.find_element(By.TAG_NAME, "tbody")
                rows = tbody.find_elements(By.TAG_NAME, "tr")
                td = rows[i].find_elements(By.TAG_NAME, "td")[0]
                product = td.text
                assert product in products

                individual_report_anchor = td.find_element(By.TAG_NAME, "a")
                href = individual_report_anchor.get_attribute("href")
                individual_report_anchor.click()
                current_url = browser.current_url
                assert href == current_url

                # Check at the individual report level
                tenant_table = browser.find_element(By.TAG_NAME, "table")
                tbody = tenant_table.find_element(By.TAG_NAME, "tbody")
                rows = tbody.find_elements(By.TAG_NAME, "tr")
                assert len(rows) == 2
                assert rows[1].find_elements(By.TAG_NAME, "td")[0].text == domain

                h1 = browser.find_element(By.TAG_NAME, "h1").text
                print(products[product])
                print(products[product]["title"])
                assert h1 == products[product]["title"]
                
                policy_tables = browser.find_elements(By.TAG_NAME, "table")
                for table in policy_tables[1:]:
                    # Verify policy table headers are correct 
                    headers = (
                        table.find_element(By.TAG_NAME, "thead")
                        .find_elements(By.TAG_NAME, "tr")[0]
                        .find_elements(By.TAG_NAME, "th")
                    )
                    assert len(headers) == 5
                    assert headers[0].text == "Control ID"
                    assert headers[1].text == "Requirement" or "Rule Name"
                    assert headers[2].text == "Result"
                    assert headers[3].text == "Criticality"
                    assert headers[4].text == "Details" or "Rule Description"

                    # Verify policy table rows are populated
                    tbody = table.find_element(By.TAG_NAME, "tbody")
                    rows = tbody.find_elements(By.TAG_NAME, "tr")
                    assert len(rows) > 0

                browser.back()
                WebDriverWait(browser, 10).until(
                    expected_conditions.presence_of_element_located(
                        (By.TAG_NAME, "body")
                    )
                )
        except Exception as e:
            browser.quit()
            pytest.fail(f"An error occurred, {e}")