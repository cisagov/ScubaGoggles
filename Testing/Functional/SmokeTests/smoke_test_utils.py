import pytest
import os
import json
from scubagoggles.orchestrator import gws_products
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions

def get_output_path() -> str:
    directories: list[str] = [d for d in os.listdir() if os.path.isdir(d) and d.startswith("GWSBaselineConformance")]
    directories.sort(key=lambda d: os.path.getctime(d), reverse=True)
    return os.path.join(os.getcwd(), directories[0])

def prepend_file_protocol(path: str) -> str:
    if not path.startswith("file://"):
        path = "file://" + path
    return path

def verify_output_type(output_path: str, output: list[str]) -> list[str]:
    entries: list[str] = os.listdir(output_path)
    for entry in entries:
        output.append(entry)
        # Check if entry is a valid directory or file
        # If a valid directory, then recurse
        child_path: str = os.path.join(output_path, entry)
        if os.path.isdir(child_path):
            assert True
            verify_output_type(child_path, output)
        elif os.path.isfile(child_path):
            # Check for valid json
            if child_path.endswith(".json"):
                try:
                    with open(child_path) as jsonfile:
                        json.load(jsonfile)
                except ValueError as e:
                    raise ValueError(f"{child_path} contains invalid json, {e}")
            assert True
        else:
            raise OSError(f"Entry is not a directory or file (symlink, etc.)")
    return output

required_entries = [
    "BaselineReports.html", 
    "IndividualReports", 
    "ScubaResults.json",
    "TestResults.json",
    "images",
    "CalendarReport.html",
    "ChatReport.html",
    "ClassroomReport.html",
    "CommoncontrolsReport.html",
    "DriveReport.html",
    "GmailReport.html",
    "GroupsReport.html",
    "MeetReport.html",
    "RulesReport.html",
    "SitesReport.html",
    "cisa_logo.png",
    "triangle-exclamation-solid.svg"
]

def verify_all_outputs_exist(output: list[str]):
    for required_entry in required_entries:
        if required_entry in output:
            assert True
        else:
            raise ValueError(f"{required_entry} was not found in the generated report")

def run_selenium(browser, domain):
    h1 = browser.find_element(By.TAG_NAME, "h1").text
    assert h1 == "SCuBA GWS Security Baseline Conformance Reports"

    products = {
        product: { "title": f"{product} Baseline Report" }
        for product in gws_products()["prod_to_fullname"].values()
    }
    print(products)

    # Before entering loop check that we actually display 10 rows in table
    reports_table = get_reports_table(browser)

    if len(reports_table) == 10:
        for i in range(len(reports_table)): 
            # Verify domain is present in agency table
            tenant_table = get_tenant_table(browser)
            assert len(tenant_table) == 2
            customer_domain = tenant_table[1].find_elements(By.TAG_NAME, "td")[0].text
            assert customer_domain == domain

            reports_table = get_reports_table(browser)[i]
            baseline_report = reports_table.find_elements(By.TAG_NAME, "td")[0]
            product = baseline_report.text
            assert product in products

            individual_report_anchor = baseline_report.find_element(By.TAG_NAME, "a")
            href = individual_report_anchor.get_attribute("href")
            individual_report_anchor.click()
            current_url = browser.current_url
            assert href == current_url

            # Check at the individual report level
            tenant_table = get_tenant_table(browser)
            assert len(tenant_table) == 2
            assert tenant_table[1].find_elements(By.TAG_NAME, "td")[0].text == domain

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
    else:
        raise ValueError(f"Expected the reports table to have a length of 10")

def get_tenant_table(browser):
    return (
        browser.find_element(By.TAG_NAME, "table")
        .find_element(By.TAG_NAME, "tbody")
        .find_elements(By.TAG_NAME, "tr")
    )

def get_reports_table(browser):
    return (
        browser.find_elements(By.TAG_NAME, "table")[1]
        .find_element(By.TAG_NAME, "tbody")
        .find_elements(By.TAG_NAME, "tr")
    )