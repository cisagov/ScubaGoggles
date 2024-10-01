"""
reporter.py creates the report html page

Currently, utilizes pandas to generate the HTML table fragments
"""
import os
import time
import warnings
from datetime import datetime
import pandas as pd
from scubagoggles.utils import rel_abs_path
from scubagoggles.scuba_constants import API_LINKS


# Eight instance attributes is reasonable in this case.
# pylint: disable-next=too-many-instance-attributes
class Reporter:

    """The Reporter class generates the HTML files containing the conformance
    reports.
    """

    _github_url = 'https://github.com/cisagov/scubagoggles'

    def __init__(self,
                 product: str,
                 tenant_domain: str,
                 main_report_name: str,
                 prod_to_fullname: dict,
                 product_policies: list,
                 successful_calls: set,
                 unsuccessful_calls: set,
                 omissions: dict):

        """Reporter class initialization

        :param product: name of product being tested
        :param tenant_domain: The primary domain of the GWS org
        :param main_report_name: Name of the main report HTML file.
        :param prod_to_fullname: mapping of the product full names
        :param product_policies: list of dictionaries containing policies
            read from the baseline markdown
        :param successful_calls: set with the set of successful calls
        :param unsuccessful_calls: set with the set of unsuccessful calls
        :param omissions: dict with the omissions specified in the config
            file (empty dict if none omitted)
        """

        self._product = product
        self._tenant_domain = tenant_domain
        self._main_report_name = main_report_name
        self._product_policies = product_policies
        self._successful_calls = successful_calls
        self._unsuccessful_calls = unsuccessful_calls
        self._full_name = prod_to_fullname[product]
        self._omissions = {
            # Lowercase all the keys for case-insensitive comparisons
            key.lower(): value for key, value in omissions.items()
        }

    @staticmethod
    def _get_test_result(requirement_met: bool, criticality: str, no_such_events: bool) -> str:
        '''
        Checks the Rego to see if the baseline passed or failed and indicates the criticality
        of the baseline.

        :param requirement_met: a boolean value indicating if the requirement passed or failed.
        :param criticality: a string value indicating the criticality of the failed baseline,
            values: should, may, 3rd Party, Not-Implemented
        :param no_such_events: boolean whether there are no such events
        '''

        # If there were no log events for the test, the state of "requirement_met"
        # doesn't matter - it's a test requiring a manual check (i.e., "no events
        # found").

        criticality = criticality.lower()

        if '3rd party' in criticality or 'not-implemented' in criticality:
            result = 'N/A'
        elif no_such_events:
            result = 'No events found'
        elif requirement_met:
            result = 'Pass'
        elif criticality in ('should', 'may'):
            result = 'Warning'
        else:
            result = 'Fail'

        return result

    @staticmethod
    def create_html_table(table_data: list) -> str:
        '''
        Creates an HTML Table for the results of the Rego Scan

        :param table_data: list object of results of Rego Scan
        '''
        table_html = pd.DataFrame(table_data).to_html(border = 0, index = False,
        escape=False, render_links=True)
        table_html = table_html.replace(' style="text-align: right;"', '')
        table_html = table_html.replace(' class="dataframe"', '')
        return table_html

    @staticmethod
    def build_front_page_html(fragments: list, tenant_info: dict) -> str:
        '''
        Builds the Front Page Report using the HTML Report Template

        :param fragments: list object containing each baseline
        :param tenant_info: list object containing each baseline
        '''
        reporter_path = str(rel_abs_path(__file__,"./"))
        with open(os.path.join(reporter_path, './FrontPageReport/FrontPageReportTemplate.html'),
        mode='r', encoding='UTF-8') as file:
            html = file.read()

        table = "".join(fragments)

        with open(os.path.join(reporter_path,'./styles/main.css'),
                  encoding='UTF-8') as file:
            css = file.read()
        html = html.replace('{{MAIN_CSS}}', f"<style>{css}</style>")

        front_page_path = os.path.join(reporter_path, './styles/FrontPageStyle.css')
        with open(front_page_path, mode='r', encoding='UTF-8') as file:
            css = file.read()
        html = html.replace('{{FRONT_CSS}}', f"<style>{css}</style>")

        html = html.replace('{{TABLE}}', table)

        now = datetime.now()
        report_date = now.strftime("%m/%d/%Y %H:%M:%S") + " " + time.tzname[time.daylight]

        meta_data = f"\
            <table style = \"text-align:center;\"> \
                <colgroup><col/><col/><col/><col/></colgroup> \
                <tr><th>Customer Domain</th><th>Report Date</th></tr> \
                <tr><td>{tenant_info['domain']}</td><td>{report_date}</td></tr> \
            </table>"
        html = html.replace('{{TENANT_DETAILS}}', meta_data)
        return html

    def _is_control_omitted(self, control_id : str) -> bool:
        '''
        Determine if the supplied control was marked for omission in the
        config file and if the expiration date has passed, if applicable.
        :param control_id: the control ID, e.g., GWS.GMAIL.1.1v1. Case-
            insensitive.
        '''
        # Lowercase for case-insensitive comparison
        control_id = control_id.lower()
        if control_id in self._omissions:
            # The config indicates the control should be omitted
            if self._omissions[control_id] is None:
                # If a user doesn't provide either a rationale or expiration
                # date, the control ID will be in the omissions dict but it
                # will map to None.
                return True
            if 'expiration' not in self._omissions[control_id]:
                return True
            # An expiration date for the omission expiration was
            # provided. Evaluate the date to see if the control should
            # still be omitted.
            raw_date = self._omissions[control_id]['expiration']
            if raw_date is None or raw_date == "":
                # If the expiration date is left blank or an empty string,
                # omit the policy
                return True
            try:
                expiration_date = datetime.strptime(raw_date, '%Y-%m-%d')
            except ValueError:
                # Malformed date, don't omit the policy
                warning = f"Config file indicates omitting {control_id}, " \
                    f"but the provided expiration date, {raw_date}, is " \
                    "malformed. The expected format is yyyy-mm-dd. Control" \
                    " will not be omitted."
                warnings.warn(warning, RuntimeWarning)
                return False
            now = datetime.now()
            if expiration_date > now:
                # The expiration date is in the future, omit the policy
                return True
            # The expiration date is passed, don't omit the policy
            warning = f"Config file indicates omitting {control_id}, but " \
                f"the provided expiration date, {raw_date}, has passed. " \
                "Control will not be omitted."
            warnings.warn(warning, RuntimeWarning)
        return False

    def _get_omission_rationale(self, control_id : str) -> str:
        '''
        Return the rationale indicated in the config file for the indicated
        control, if provided. If not, return a string warning the user that
        no rationale was provided.
        :param control_id: the control ID, e.g., GWS.GMAIL.1.1v1. Case-
            insensitive.
        '''
        # Lowercase for case-insensitive comparison
        control_id = control_id.lower()
        if control_id not in self._omissions:
            raise RuntimeError(f"{control_id} not omitted in config file, " \
                "cannot fetch rationale")
        # If any of the following conditions is true, no rationale was
        # provided
        no_rationale = \
            (self._omissions[control_id] is None) or \
            ('rationale' not in self._omissions[control_id]) or \
            (self._omissions[control_id]['rationale'] is None) or \
            (self._omissions[control_id]['rationale'] == "")
        if no_rationale:
            warning = f"Config file indicates omitting {control_id}, but " \
                "no rationale provided."
            warnings.warn(warning, RuntimeWarning)
            return "Rationale not provided."
        return self._omissions[control_id]['rationale']

    def _build_report_html(self, fragments: list) -> str:
        '''
        Adds data into HTML Template and formats the page accordingly

        :param fragments: list object containing each baseline
        '''
        reporter_path = str(rel_abs_path(__file__,"./"))
        with open(os.path.join(reporter_path, './IndividualReport/IndividualReportTemplate.html'),
        mode='r', encoding='UTF-8') as file:
            html = file.read()

        with open(os.path.join(reporter_path, './styles/main.css'),
                  encoding='UTF-8') as file:
            css = file.read()
        html = html.replace('{{MAIN_CSS}}', f"<style>{css}</style>")

        with open(os.path.join(reporter_path, 'scripts/main.js'),
                  encoding='UTF-8') as file:
            javascript = file.read()
        html = html.replace('{{MAIN_JS}}', f"<script>{javascript}</script>")

        title = self._full_name + " Baseline Report"
        html = html.replace('{{TITLE}}', title)

        # this block of code is for adding
        # warning notifications to any of the baseline reports
        classroom_notification = "<p>Note: Google Classroom is not available by default in GWS"\
        " but as an additional Google Service.</p>"
        no_warning = "<p><br/></p>"

        if self._full_name == 'Google Classroom':
            html = html.replace('{{WARNING_NOTIFICATION}}', classroom_notification)
        else:
            html = html.replace('{{WARNING_NOTIFICATION}}', no_warning)

        # Relative path back to the front page
        home_page = f'../{self._main_report_name}.html'
        html = html.replace('{{HOMELINK}}', home_page)

        now = datetime.now()

        report_date = now.strftime("%m/%d/%Y %H:%M:%S") + " " + time.tzname[time.daylight]
        baseline_version = "0.3"
        tool_version = "0.3.0"
        meta_data = f"\
            <table style = \"text-align:center;\"> \
                <colgroup><col/><col/><col/></colgroup> \
                <tr><th>Customer Domain </th><th>Report Date</th><th>Baseline Version</th><th>Tool Version</th></tr> \
                <tr><td>{self._tenant_domain}</td><td>{report_date}</td><td>{baseline_version}</td><td>{tool_version}</td></tr> \
            </table>"

        html = html.replace('{{METADATA}}', meta_data)

        collected = "".join(fragments)

        html = html.replace('{{TABLES}}', collected)
        return html

    def _get_failed_prereqs(self, test: dict) -> set:
        '''
        Given the output of a specific Rego test and the set of successful and unsuccessful
        calls, determine the set of prerequisites that were not met.
        :param test: a dictionary representing the output of a Rego test
        '''
        if 'Prerequisites' not in test:
            # If Prerequisites is not defined, assume the test just depends on the
            # reports API.
            prereqs = {"reports/v1/activities/list"}
        else:
            prereqs = set(test['Prerequisites'])

        # A call is failed if it is either missing from the successful_calls set
        # or present in the unsuccessful_calls
        failed_prereqs = set().union(
            prereqs.difference(self._successful_calls),
            prereqs.intersection(self._unsuccessful_calls)
        )

        return failed_prereqs

    @staticmethod
    def _get_failed_details(failed_prereqs: set) -> str:
        '''
        Create the string used for the Details column of the report when one
        or more of the API calls/functions failed.

        :param failed_prereqs: A set of strings with the API calls/function prerequisites
            that were not met for a given test.
        '''

        failed_apis = [API_LINKS[api] for api in failed_prereqs if api in API_LINKS]
        failed_functions = [call for call in failed_prereqs if call not in API_LINKS]
        failed_details = ""
        if len(failed_apis) > 0:
            links = ', '.join(failed_apis)
            failed_details += f"This test depends on the following API call(s) " \
                f"which did not execute successfully: {links}. "
        if len(failed_functions) > 0:
            failed_details += f"This test depends on the following function(s) " \
                f"which did not execute successfully: {', '.join(failed_functions)}. "
        failed_details += "See terminal output for more details."
        return failed_details

    @staticmethod
    def _get_summary_category(result: str) -> str:
        '''Map the string result returned from get_test_result to the appropriate summary category.

        :param result: The result, e.g., "Warning"
        '''

        if result in {"No events found", "N/A"}:
            return "Manual"
        if result == "Warning":
            return "Warnings"
        if result == "Fail":
            return "Failures"
        if result == "Pass":
            return "Passes"
        raise ValueError(f"Unexpected result, {result}", RuntimeWarning)

    def _handle_rules_omission(self, control_id : str, tests : list):
        '''Process the test results for the rules report if the rules control
        was omitted.

        :control_id: The control ID for the rules control.
        :tests: A list of test result dictionaries.
        '''
        table_data = []
        for test in tests:
            if 'Not-Implemented' in test['Criticality']:
                # The easiest way to identify the common controls "rules"
                # results that belong to the Common Controls report is they're
                # marked as Not-Implemented. This if excludes them from the
                # rules report.
                continue
            rationale = self._get_omission_rationale(control_id)
            table_data.append({
                'Control ID': control_id,
                'Rule Name': test['Requirement'],
                'Result': 'Omitted',
                'Criticality': test['Criticality'],
                'Rule Description': f'N/A; test omitted by user. {rationale}'
            })
        return table_data

    def rego_json_to_ind_reports(self, test_results: list, out_path: str) -> list:
        '''
        Transforms the Rego JSON output into individual HTML and JSON reports

        :param test_results: list of dictionaries with results of Rego test,
            deserialized from JSON data.
        :param out_path: output path where HTML should be saved
        '''

        product_capitalized = self._product.capitalize()
        product_upper = ('DRIVEDOCS' if self._product == 'drive'
                         else self._product.upper())
        ind_report_name = product_capitalized + "Report"
        fragments = []
        json_data = []
        tool_version = '0.3.0'
        github_url = self._github_url
        report_stats = {
            "Manual": 0,
            "Passes": 0,
            "Errors": 0,
            "Failures": 0,
            "Warnings": 0,
            "Omit": 0
        }

        for baseline_group in self._product_policies:
            table_data = []
            results_data = {}
            for control in baseline_group['Controls']:
                tests = [test for test in test_results if test['PolicyId'] == control['Id']]
                if len(tests) == 0:
                    # Handle the case where Rego doesn't output anything for a given control
                    report_stats['Errors'] += 1
                    issues_link = f'<a href="{github_url}/issues" target="_blank">GitHub</a>'
                    table_data.append({
                        'Control ID': control['Id'],
                        'Requirement': control['Value'],
                        'Result': "Error - Test results missing",
                        'Criticality': "-",
                        'Details': f'Report issue on {issues_link}'})
                    warnings.warn(f"No test results found for Control Id {control['Id']}",
                        RuntimeWarning)
                    continue
                if self._is_control_omitted(control['Id']):
                    # Handle the case where the control was omitted
                    if product_capitalized == "Rules":
                        # Rules is a special case
                        rules_data = self._handle_rules_omission(control['Id'], tests)
                        table_data.extend(rules_data)
                        report_stats['Omit'] += len(rules_data)
                        continue
                    report_stats['Omit'] += 1
                    rationale = self._get_omission_rationale(control['Id'])
                    table_data.append({
                        'Control ID': control['Id'],
                        'Requirement': control['Value'],
                        'Result': "Omitted",
                        'Criticality': tests[0]['Criticality'],
                        'Details': f'Test omitted by user. {rationale}'
                    })
                    continue
                for test in tests:
                    failed_prereqs = self._get_failed_prereqs(test)
                    if len(failed_prereqs) > 0:
                        report_stats["Errors"] += 1
                        failed_details = self._get_failed_details(failed_prereqs)
                        table_data.append({
                            'Control ID': control['Id'],
                            'Requirement': control['Value'],
                            'Result': "Error",
                            'Criticality': test['Criticality'],
                            'Details': failed_details})
                        continue
                    result = self._get_test_result(test['RequirementMet'],
                                                    test['Criticality'],
                                                    test['NoSuchEvent'])

                    details = test['ReportDetails']

                    if result == "No events found":
                        warning_icon = "<object data='./images/"\
                            "triangle-exclamation-solid.svg'\
                            width='15'\
                            height='15'>\
                            </object>"
                        details = warning_icon + " " + test['ReportDetails']
                    # As rules doesn't have its own baseline, Rules and Common Controls
                    # need to be handled specially
                    if product_capitalized == "Rules":
                        if 'Not-Implemented' in test['Criticality']:
                            # The easiest way to identify the GWS.COMMONCONTROLS.13.1v1
                            # results that belong to the Common Controls report is they're
                            # marked as Not-Implemented. This if excludes them from the
                            # rules report.
                            continue
                        report_stats[self._get_summary_category(result)] += 1
                        table_data.append({
                            'Control ID': control['Id'],
                            'Rule Name': test['Requirement'],
                            'Result': result,
                            'Criticality': test['Criticality'],
                            'Rule Description': test['ReportDetails']})
                    elif product_capitalized == "Commoncontrols" \
                        and baseline_group['GroupName'] == 'System-defined Rules' \
                        and 'Not-Implemented' not in test['Criticality']:
                        # The easiest way to identify the System-defined Rules
                        # results that belong to the Common Controls report is they're
                        # marked as Not-Implemented. This if excludes the full results
                        # from the Common Controls report.
                        continue
                    else:
                        report_stats[self._get_summary_category(result)] += 1
                        table_data.append({
                            'Control ID': control['Id'],
                            'Requirement': control['Value'],
                            'Result': result,
                            'Criticality': test['Criticality'],
                            'Details': details})
            markdown_group_name = "-".join(baseline_group['GroupName'].split())
            md_basename = "commoncontrols" if self._product == "rules" else self._product
            group_reference_url = f'{github_url}/blob/v{tool_version}/baselines/'\
            f'{md_basename}.md#'\
            f'{baseline_group["GroupNumber"]}-{markdown_group_name}'
            group_reference_url_spacing = "%20".join(group_reference_url.split())
            markdown_link = fr'<a href="{group_reference_url_spacing}" target="_blank"\>'\
            f'{baseline_group["GroupName"]}</a>'
            fragments.append(f"<h2>{product_upper}-{baseline_group['GroupNumber']} \
            {markdown_link}</h2>")
            fragments.append(self.create_html_table(table_data))
            results_data.update({"GroupName": baseline_group['GroupName']})
            results_data.update({"GroupNumber": baseline_group['GroupNumber']})
            results_data.update({"GroupReferenceURL":group_reference_url_spacing})
            results_data.update({"Controls": table_data})
            json_data.append(results_data)
        html = self._build_report_html(fragments)
        with open(f"{out_path}/IndividualReports/{ind_report_name}.html",
                mode='w', encoding='UTF-8') as html_file:
            html_file.write(html)
        return [report_stats, json_data]
