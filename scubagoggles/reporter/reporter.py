"""
reporter.py creates the report html page
"""
import io
import logging
import time
import warnings
import json

from datetime import datetime
from html import escape
from pathlib import Path

from scubagoggles.scuba_constants import API_LINKS
from scubagoggles.version import Version

log = logging.getLogger(__name__)


# Nine instance attributes is reasonable in this case.
# pylint: disable=too-many-instance-attributes

class Reporter:

    """The Reporter class generates the HTML files containing the conformance
    reports.
    """

    _github_url = 'https://github.com/cisagov/scubagoggles'

    _reporter_path = Path(__file__).parent

    # pylint: disable-next=too-many-positional-arguments
    def __init__(self,
                 product: str,
                 tenant_id: str,
                 tenant_name: str,
                 tenant_domain: str,
                 main_report_name: str,
                 prod_to_fullname: dict,
                 product_policies: list,
                 successful_calls: set,
                 unsuccessful_calls: set,
                 omissions: dict,
                 progress_bar=None):
        """Reporter class initialization

        :param product: name of product being tested
        :param tenant_id: Unique ID of GWS Customer
        :param tenant_name: Customer name
        :param tenant_domain: The primary domain of the GWS org
        :param main_report_name: Name of the main report HTML file.
        :param prod_to_fullname: mapping of the product full names
        :param product_policies: list of dictionaries containing policies
            read from the baseline markdown
        :param successful_calls: set with the set of successful calls
        :param unsuccessful_calls: set with the set of unsuccessful calls
        :param omissions: dict with the omissions specified in the config
            file (empty dict if none omitted)
        :param progress_bar: Optional TQDM instance. If provided, the
            progress bar will be cleared before any warnings are printed
            while generating the report, for cleaner output.
        """

        self._product = product
        self._tenant_id = tenant_id
        self._tenant_name = tenant_name
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
        self.progress_bar = progress_bar
        self.rules_table = None

    @staticmethod
    def _get_test_result(requirement_met: bool,
                         criticality: str,
                         no_such_events: bool) -> str:
        """
        Checks the Rego to see if the baseline passed or failed and indicates
        the criticality of the baseline.

        :param requirement_met: a boolean value indicating if the requirement
            passed or failed.
        :param criticality: a string value indicating the criticality of the
            failed baseline,
            values: should, may, 3rd Party, Not-Implemented
        :param no_such_events: boolean whether there are no such events
        """

        # If there were no log events for the test, the state of
        # "requirement_met" doesn't matter - it's a test requiring a manual
        # check (i.e., "no events found").

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
        """Creates an HTML Table for the results of the Rego Scan

        :param list table_data: list of dictionaries containing the results of
            Rego scan.  Each item in the list must have the same dictionary
            structure (i.e., same keys).
        """

        table_html = ''

        if not table_data:
            return table_html

        headings = table_data[0].keys()

        with io.StringIO() as outstream:

            outstream.write('<table>\n')
            outstream.write('  <thead>\n')
            outstream.write('    <tr>\n')
            for heading in headings:
                outstream.write(f'      <th>{heading}</th>\n')
            outstream.write('    </tr>\n')
            outstream.write('  </thead>\n')

            outstream.write('  <tbody>\n')
            for record in table_data:
                outstream.write('    <tr>\n')
                for heading in headings:
                    outstream.write(f'      <td>{record[heading]}</td>\n')
                outstream.write('    </tr>\n')
            outstream.write('  </tbody>\n')

            # There's no ending newline on purpose (as that's the way it was
            # done with the previous implementation using Pandas).

            outstream.write('</table>')

            table_html = outstream.getvalue()

        return table_html

    @classmethod
    def build_front_page_html(cls,
                              fragments: list,
                              tenant_info: dict,
                              report_uuid: str) -> str:
        """
        Builds the Front Page Report using the HTML Report Template

        :param fragments: list object containing each baseline
        :param tenant_info: list object containing each baseline
        """

        template_file = (cls._reporter_path
                         / 'FrontPageReport/FrontPageReportTemplate.html')
        html = template_file.read_text(encoding='utf-8')

        table = ''.join(fragments)

        main_css_file = cls._reporter_path / 'styles/main.css'
        css = main_css_file.read_text(encoding='utf-8')
        html = html.replace('{{MAIN_CSS}}', f'<style>{css}</style>')

        front_css_file = cls._reporter_path / 'styles/FrontPageStyle.css'
        css = front_css_file.read_text(encoding='utf-8')
        html = html.replace('{{FRONT_CSS}}', f'<style>{css}</style>')
        html = html.replace('{{report_uuid}}', report_uuid)
        html = html.replace('{{TABLE}}', table)

        now = datetime.now()
        report_date = (now.strftime('%m/%d/%Y %H:%M:%S')
                       + ' ' + time.tzname[time.daylight])

        meta_data = ('<table style = "text-align:center;">'
                     '<tr><th>Customer Name</th><th>Customer Domain</th>'
                     '<th>Customer ID</th><th>Report Date</th></tr>'
                     f'<tr><td>{tenant_info["topLevelOU"]}</td><td>{tenant_info["domain"]}</td>'
                     f'<td>{tenant_info["ID"]}</td><td>{report_date}'
                     '</td></tr></table>')

        html = html.replace('{{TENANT_DETAILS}}', meta_data)
        html = html.replace('{{VERSION}}', Version.current)

        return html

    def _is_control_omitted(self, control_id: str) -> bool:
        """
        Determine if the supplied control was marked for omission in the
        config file and if the expiration date has passed, if applicable.
        :param control_id: the control ID, e.g., GWS.GMAIL.1.1v1. Case-
            insensitive.
        """
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
            if raw_date is None or raw_date == '':
                # If the expiration date is left blank or an empty string,
                # omit the policy
                return True
            try:
                expiration_date = datetime.strptime(raw_date, '%Y-%m-%d')
            except ValueError:
                # Malformed date, don't omit the policy
                warning = (f'Config file indicates omitting {control_id}, '
                           f'but the provided expiration date, {raw_date}, is '
                           'malformed. The expected format is yyyy-mm-dd. Control'
                           ' will not be omitted.')
                self._warn(warning, RuntimeWarning)
                return False
            now = datetime.now()
            if expiration_date > now:
                # The expiration date is in the future, omit the policy
                return True
            # The expiration date is passed, don't omit the policy
            warning = (f'Config file indicates omitting {control_id}, but '
                       f'the provided expiration date, {raw_date}, has passed. '
                       'Control will not be omitted.')
            self._warn(warning, RuntimeWarning)
        return False

    def _get_omission_rationale(self, control_id: str) -> str:
        """
        Return the rationale indicated in the config file for the indicated
        control, if provided. If not, return a string warning the user that
        no rationale was provided.
        :param control_id: the control ID, e.g., GWS.GMAIL.1.1v1. Case-
            insensitive.
        """
        # Lowercase for case-insensitive comparison
        control_id = control_id.lower()
        if control_id not in self._omissions:
            raise RuntimeError(f'{control_id} not omitted in config file, '
                               'cannot fetch rationale')
        # If any of the following conditions is true, no rationale was
        # provided
        no_rationale = ((self._omissions[control_id] is None) or
                        ('rationale' not in self._omissions[control_id]) or
                        (self._omissions[control_id]['rationale'] is None) or
                        (self._omissions[control_id]['rationale'] == ''))
        if no_rationale:
            warning = (f'Config file indicates omitting {control_id}, but '
                       'no rationale provided.')
            self._warn(warning, RuntimeWarning)
            return 'Rationale not provided.'
        return self._omissions[control_id]['rationale']

    def _build_report_html(self, fragments: list, rules_data : dict) -> str:
        """
        Adds data into HTML Template and formats the page accordingly

        :param fragments: list object containing each baseline
        :param rules_data: the 'actual_value' for GWS.COMMONCONTROLS.13.1 if
            present, None otherwise
        """

        template_file = (self._reporter_path
                         / 'IndividualReport/IndividualReportTemplate.html')
        html = template_file.read_text(encoding='utf-8')

        main_css_file = self._reporter_path / 'styles/main.css'
        css = main_css_file.read_text(encoding='utf-8')
        html = html.replace('{{MAIN_CSS}}', f'<style>{css}</style>')

        main_js_file = self._reporter_path / 'scripts/main.js'
        javascript = main_js_file.read_text(encoding='utf-8')
        html = html.replace('{{MAIN_JS}}', f'<script>{javascript}</script>')

        title = self._full_name + ' Baseline Report'
        html = html.replace('{{TITLE}}', title)

        # This block of code is for adding warning notifications to any of
        # the baseline reports.
        classroom_notification = ('<h4>Note: Google Classroom is not available '
                                  'by default in GWS but as an additional '
                                  'Google Service.</h4>')

        if self._full_name == 'Google Classroom':
            html = html.replace('{{WARNING_NOTIFICATION}}',
                                classroom_notification)
        else:
            html = html.replace('{{WARNING_NOTIFICATION}}', '')

        # Relative path back to the front page
        home_page = f'../{self._main_report_name}.html'
        html = html.replace('{{HOMELINK}}', home_page)

        now = datetime.now()

        report_date = (now.strftime('%m/%d/%Y %H:%M:%S')
                       + ' ' + time.tzname[time.daylight])
        meta_data = (f'<table style = "text-align:center;">'
                     '<tr><th>Customer Name</th><th>Customer Domain</th>'
                     '<th>Customer ID</th><th>Report Date</th>'
                     '<th>Baseline Version</th><th>Tool Version</th></tr>'
                     f'<tr><td>{self._tenant_name}</td><td>{self._tenant_domain}</td>'
                     f'<td>{self._tenant_id}</td><td>{report_date}</td>'
                     f'<td>{Version.suffix}</td><td>{Version.current}</td></tr>'
                     '</table>')

        html = html.replace('{{METADATA}}', meta_data)

        collected = ''.join(fragments)

        html = html.replace('{{TABLES}}', collected)
        if rules_data:
            alert_descriptions = json.loads((self._reporter_path
                         / 'IndividualReport/AlertsDescriptions.json').read_text())
            rules_html = '<hr>'
            rules_html += '<h2 id="alerts">System Defined Alerts</h2>'
            rules_html += '<p>Note: As ScubaGoggles currently relies on admin log events '
            rules_html += 'to determine alert status, ScubaGoggles will not be able to '
            rules_html += 'determine the current status of any alerts whose state has '
            rules_html += 'not changed recently.</p>'
            rules_table = []
            for rule in rules_data['enabled_rules']:
                rules_table.append({
                    'Alert Name': rule,
                    'Description': alert_descriptions[rule],
                    'Status': 'Enabled'
                })
            for rule in rules_data['disabled_rules']:
                rules_table.append({
                    'Alert Name': rule,
                    'Description': alert_descriptions[rule],
                    'Status': 'Disabled'
                })
            for rule in rules_data['unknown']:
                rules_table.append({
                    'Alert Name': rule,
                    'Description': alert_descriptions[rule],
                    'Status': 'Unknown'
                })
            rules_table.sort(key=lambda rule: rule['Alert Name'])
            rules_html += self.create_html_table(rules_table)
            html = html.replace('{{RULES}}', rules_html)
            # Save the rules table to the object so the orchestrator can access it
            self.rules_table = rules_table
        else:
            html = html.replace('{{RULES}}', '')
        return html

    def _get_failed_prereqs(self, test: dict) -> set:
        """
        Given the output of a specific Rego test and the set of successful
        and unsuccessful calls, determine the set of prerequisites that were
        not met.

        :param test: a dictionary representing the output of a Rego test
        """

        if 'Prerequisites' not in test:
            # If Prerequisites is not defined, assume the test just depends
            # on the reports API.
            prereqs = {'reports/v1/activities/list'}
        else:
            prereqs = set(test['Prerequisites'])

        # A call is failed if it is either missing from the successful_calls
        # set or present in the unsuccessful_calls
        failed_prereqs = set().union(
            prereqs.difference(self._successful_calls),
            prereqs.intersection(self._unsuccessful_calls)
        )

        return failed_prereqs

    @staticmethod
    def _get_failed_details(failed_prereqs: set) -> str:
        """
        Create the string used for the Details column of the report when one
        or more of the API calls/functions failed.

        :param failed_prereqs: A set of strings with the API calls/function
            prerequisites that were not met for a given test.
        """

        failed_apis = [API_LINKS[api] for api in failed_prereqs
                       if api in API_LINKS]
        failed_functions = [call for call in failed_prereqs
                            if call not in API_LINKS]
        failed_details = ''
        if len(failed_apis) > 0:
            links = ', '.join(failed_apis)
            failed_details += ('This test depends on the following API call(s) '
                               f'which did not execute successfully: {links}.')
        if len(failed_functions) > 0:
            failed_details += ('This test depends on the following '
                               'function(s) which did not execute '
                               f"successfully: {', '.join(failed_functions)}.")
        failed_details += 'See terminal output for more details.'
        return failed_details

    @staticmethod
    def _get_summary_category(result: str) -> str:
        """
        Map the string result returned from get_test_result to the
        appropriate summary category.

        :param result: The result, e.g., "Warning"
        """

        if result in {'No events found', 'N/A'}:
            return 'Manual'
        if result == 'Warning':
            return 'Warnings'
        if result == 'Fail':
            return 'Failures'
        if result == 'Pass':
            return 'Passes'
        raise ValueError(f'Unexpected result, {result}', RuntimeWarning)

    def _warn(self, *args, **kwargs):
        """
        Wrapper for the warnings.warn function, that clears and refreshes the
        progress bar if one has been provided, to keep the output clean.
        Accepts all the arguments the warnings.warn function accepts.
        """
        if self.progress_bar is not None:
            self.progress_bar.clear()
        warnings.warn(*args, **kwargs)
        if self.progress_bar is not None:
            self.progress_bar.refresh()

    def rego_json_to_ind_reports(self,
                                 test_results: list,
                                 out_path: str) -> list:
        """
        Transforms the Rego JSON output into individual HTML and JSON reports

        :param test_results: list of dictionaries with results of Rego test,
            deserialized from JSON data.
        :param out_path: output path where HTML should be saved
        """

        product = self._product
        product_capitalized = product.capitalize()
        product_upper = 'DRIVEDOCS' if product == 'drive' else product.upper()
        ind_report_name = product_capitalized + 'Report'
        fragments = []
        json_data = []
        github_url = self._github_url
        report_stats = {
            'Manual': 0,
            'Passes': 0,
            'Errors': 0,
            'Failures': 0,
            'Warnings': 0,
            'Omit': 0
        }

        rules_data = None
        for baseline_group in self._product_policies:
            table_data = []
            results_data = {}
            for control in baseline_group['Controls']:
                control_id = control['Id']
                requirement = escape(control['Value'])
                tests = [test for test in test_results
                         if test['PolicyId'] == control_id]
                if len(tests) == 0:
                    # Handle the case where Rego doesn't output anything for
                    # a given control
                    report_stats['Errors'] += 1
                    issues_link = (f'<a href="{github_url}/issues" '
                                   'target="_blank">GitHub</a>')
                    table_data.append({
                        'Control ID': control_id,
                        'Requirement': requirement,
                        'Result': 'Error - Test results missing',
                        'Criticality': '-',
                        'Details': f'Report issue on {issues_link}'})
                    log.error('No test results found for Control Id %s',
                              control_id)
                    continue
                if self._is_control_omitted(control_id):
                    # Handle the case where the control was omitted
                    report_stats['Omit'] += 1
                    rationale = self._get_omission_rationale(control_id)
                    table_data.append({
                        'Control ID': control_id,
                        'Requirement': requirement,
                        'Result': 'Omitted',
                        'Criticality': tests[0]['Criticality'],
                        'Details': f'Test omitted by user. {rationale}'
                    })
                    continue
                for test in tests:
                    failed_prereqs = self._get_failed_prereqs(test)
                    if len(failed_prereqs) > 0:
                        report_stats['Errors'] += 1
                        failed_details = self._get_failed_details(
                            failed_prereqs)
                        table_data.append({'Control ID': control_id,
                                           'Requirement': requirement,
                                           'Result': 'Error',
                                           'Criticality': test['Criticality'],
                                           'Details': failed_details})
                        continue

                    if control_id.startswith('GWS.COMMONCONTROLS.13.1'):
                        rules_data = test['ActualValue']

                    result = self._get_test_result(test['RequirementMet'],
                                                    test['Criticality'],
                                                    test['NoSuchEvent'])

                    details = test['ReportDetails']

                    if result == 'No events found':
                        warning_icon = ('<object data="./images/'
                                        'triangle-exclamation-solid.svg" '
                                        'width="15" height="15">'
                                        '</object>')
                        details = warning_icon + ' ' + test['ReportDetails']

                    report_stats[self._get_summary_category(result)] += 1
                    table_data.append({
                        'Control ID': control_id,
                        'Requirement': requirement,
                        'Result': result,
                        'Criticality': test['Criticality'],
                        'Details': details})
            markdown_group_name = '-'.join(baseline_group['GroupName'].split())
            group_reference_url = (f'{self._github_url}/blob/{Version.current}/'
                                   f'scubagoggles/baselines/{product}.md'
                                   f'#{baseline_group["GroupNumber"]}-'
                                   + markdown_group_name)
            markdown_link = (f'<a href="{group_reference_url}" '
                             'target="_blank">'
                             f'{baseline_group["GroupName"]}</a>')
            fragments.append(f'<h2>{product_upper}-'
                             f'{baseline_group["GroupNumber"]} '
                             f'{markdown_link}</h2>')
            fragments.append(self.create_html_table(table_data))
            results_data.update({'GroupName': baseline_group['GroupName']})
            results_data.update({'GroupNumber': baseline_group['GroupNumber']})
            results_data.update({'GroupReferenceURL': group_reference_url})
            results_data.update({'Controls': table_data})
            json_data.append(results_data)
        html = self._build_report_html(fragments, rules_data)
        with open(f'{out_path}/IndividualReports/{ind_report_name}.html',
                  mode='w', encoding='UTF-8') as html_file:
            html_file.write(html)
        return [report_stats, json_data]
