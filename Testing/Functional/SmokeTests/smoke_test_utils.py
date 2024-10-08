"""
Helper methods for running the functional smoke tests. 
"""

import os
import json
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions
from scubagoggles.orchestrator import Orchestrator
from scubagoggles.utils import get_package_version

OUTPUT_DIRECTORY = "GWSBaselineConformance"
BASELINE_REPORT_H1 = "SCuBA GWS Secure Configuration Baseline Reports"
CISA_GOV_URL = "https://www.cisa.gov/scuba"
SCUBAGOGGLES_BASELINES_URL = "https://github.com/cisagov/ScubaGoggles/tree/main/baselines"

def get_output_path() -> str:
    """
    Get the latest output directory created by `scubagoggles gws`.
    The default name is "GWSBaselineConformance_<timestamp>.

    Returns:
        str: The path to the latest output directory
    """
    directories: list = [
        d for d in os.listdir()
        if os.path.isdir(d) and d.startswith(OUTPUT_DIRECTORY)
    ]
    directories.sort(key=os.path.getctime, reverse=True)
    return os.path.join(os.getcwd(), directories[0])

def prepend_file_protocol(path: str) -> str:
    """
    Prepends "file://", which is used to locate files on a local filesystem.

    Returns:
        str: Path to a file with the local filesystem prepended
    """
    if not path.startswith("file://"):
        path = "file://" + path
    return path

def verify_output_type(output_path: str, output: list) -> list:
    """
    Checks if the output generated from `scubagoggles` creates the correct output.
    Validate files/directories and catch invalid json. 

    Args:
        output_path: The output path, i.e. "GWSBaselineConformance_<timestamp>"
        output: Initialized as an empty list
        
    Returns:
        list: All output file and directory names
    """
    entries: list = os.listdir(output_path)
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
                    with open(child_path, encoding="utf-8") as jsonfile:
                        json.load(jsonfile)
                except ValueError as e:
                    raise ValueError(f"{child_path} contains invalid json") from e
            assert True
        else:
            raise OSError("Entry is not a directory or file (symlink, etc.)")
    return output

def get_required_entries(sample_report, required_entries) -> list:
    """
    From the "sample-report" directory, add all file and directory names
    into a list "required_entries". All entries must be present
    for smoke tests to pass.

    Args:
        sample_report: Path where "sample-report" is located in the project
        required_entries: Initialized as an empty list
        
    Returns:
        list: All required file and directory names
    """
    with os.scandir(sample_report) as entries:
        for entry in entries:
            required_entries.append(entry.name)
            if entry.is_dir():
                get_required_entries(entry.path, required_entries)
    return required_entries

def verify_all_outputs_exist(output: list, required_entries: list):
    """
    Verify all files and directories are created after running `scubagoggles gws`.

    Args:
        output: a list of all files and directories generated by `scubagoggles gws`
        required_entries: a list of all required file and directory names
    """
    for required_entry in required_entries:
        if required_entry in output:
            assert True
        else:
            raise ValueError(f"{required_entry} was not found in the generated report")

def verify_scubaresults(jsonfile):
    """
    Verify "ScubaResults.json" is valid, and check if any errors
    are displayed in the reports.

    Args:
        jsonfile: Path to a json file
    """
    scubaresults = json.load(jsonfile)
    summaries = scubaresults["Summary"]
    for product, summary in summaries.items():
        if summary["Errors"] != 0:
            raise ValueError(f"{product} contains errors in the report")

def run_selenium(browser, customerdomain):
    """
    Run Selenium tests against the generated reports.

    Args:
        browser: A Selenium WebDriver instance
        customerdomain: The customer domain
    """
    verify_navigation_links(browser)
    h1 = browser.find_element(By.TAG_NAME, "h1").text
    assert h1 == BASELINE_REPORT_H1

    gws_products = Orchestrator.gws_products()
    products = {
        product: { "title": f"{product} Baseline Report" }
        for product in gws_products["prod_to_fullname"].values()
    }

    # Before entering loop check that we actually display 10 rows in table
    reports_table = get_reports_table(browser)

    if len(reports_table) == 10:
        for i in range(len(reports_table)):

            # Check if customerdomain is present in agency table
            # Skip tool version if assessing the parent report
            verify_tenant_table(browser, customerdomain, True)

            reports_table = get_reports_table(browser)[i]
            baseline_report = reports_table.find_elements(By.TAG_NAME, "td")[0]
            product = baseline_report.text
            assert product in products

            individual_report_anchor = baseline_report.find_element(By.TAG_NAME, "a")
            individual_report_anchor_href = individual_report_anchor.get_attribute("href")
            individual_report_anchor.click()
            current_url = browser.current_url()
            assert individual_report_anchor_href == current_url

            # Check at the individual report level
            verify_navigation_links(browser)
            h1 = browser.find_element(By.TAG_NAME, "h1").text
            assert h1 == products[product]["title"]

            # Check if customerdomain and tool version are present in individual report
            verify_tenant_table(browser, customerdomain, False)

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
                assert headers[1].text in "Requirements" or headers[1].text in "Rule Name"
                assert headers[2].text == "Result"
                assert headers[3].text == "Criticality"
                assert headers[4].text in "Details" or headers[4].text in "Rule Description"

                # Verify policy table rows are populated
                tbody = table.find_element(By.TAG_NAME, "tbody")
                rows = tbody.find_elements(By.TAG_NAME, "tr")
                assert len(rows) > 0

            parent_report_anchor = (
                browser.find_element(By.TAG_NAME, "header")
                .find_element(By.TAG_NAME, "a")
            )
            parent_report_anchor_href = parent_report_anchor.get_attribute("href")
            parent_report_anchor.click()
            current_url = browser.current_url()
            assert parent_report_anchor_href == current_url

            WebDriverWait(browser, 10).until(
                expected_conditions.presence_of_element_located(
                    (By.TAG_NAME, "body")
                )
            )
    else:
        raise ValueError("Expected the reports table to have a length of 10")

def verify_navigation_links(browser):
    """
    For each baseline report, check that the navigation links display correctly.

    Args:
        browser: A Selenium WebDriver instance
    """
    links = (
        browser.find_element(By.CLASS_NAME, "links")
        .find_elements(By.TAG_NAME, "a")
    )
    if len(links) == 2:
        assert links[0].get_attribute("href") == CISA_GOV_URL
        assert links[1].get_attribute("href") == SCUBAGOGGLES_BASELINES_URL

def get_reports_table(browser):
    """
    Get the reports table element from the DOM.
    (Table in BaselineReports.html with list of baselines and pass/fail/warning of each)

    Args:
        browser: A Selenium WebDriver instance
    """
    return (
        browser.find_elements(By.TAG_NAME, "table")[1]
        .find_element(By.TAG_NAME, "tbody")
        .find_elements(By.TAG_NAME, "tr")
    )

def verify_tenant_table(browser, customerdomain, parent):
    """
    Get the tenant table rows elements from the DOM.
    (Table at the top of each report with customer domain, baseline/tool version)

    Args:
        browser: A Selenium WebDriver instance
        customerdomain: The customer domain
        parent: boolean to determine parent/individual reports
    """
    tenant_table_rows = (
        browser.find_element(By.TAG_NAME, "table")
        .find_element(By.TAG_NAME, "tbody")
        .find_elements(By.TAG_NAME, "tr")
    )
    assert len(tenant_table_rows) == 2
    domain = tenant_table_rows[1].find_elements(By.TAG_NAME, "td")[0].text
    assert domain == customerdomain

    if not parent:
        # Check for correct tool version, e.g. 0.2.0
        version = get_package_version("scubagoggles")
        tool_version = tenant_table_rows[1].find_elements(By.TAG_NAME, "td")[3].text
        assert version == tool_version

        # Baseline version should also be checked in this method
        # Add as an additional todo
