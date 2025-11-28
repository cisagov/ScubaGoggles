"""
reporter.py creates the report html page
"""
#Must remove pylint disable too many lines when fixing this file.
# pylint: disable=too-many-lines
import io
import logging
import time
import json
import re

from datetime import datetime, date
from html import escape
from pathlib import Path

from scubagoggles.scuba_constants import API_LINKS, ApiReference
from scubagoggles.version import Version

log = logging.getLogger(__name__)


# Nine instance attributes is reasonable in this case.
# pylint: disable=too-many-instance-attributes

class Reporter:

    """The Reporter class generates the HTML files containing the conformance
    reports.
    """

    _github_url = 'https://github.com/cisagov/scubagoggles'
    _limitations_url = f"{_github_url}/blob/main/docs/usage/Limitations.md"
    _warning_icon = ('<object data="./images/triangle-exclamation-solid.svg" '
                     'alt="Warning icon." title="Warning" width="13" height="13">'
                     '</object>')
    # "&nbsp;" just adds a bit of horizontal whitespace
    # between the warning icon and the text.
    _log_based_warning = (f'<span style="display: block;">{_warning_icon}'
                          f'&nbsp;Log-based check. See <a href="{_limitations_url}">'
                          'limitations</a>.</span>')
    # Plaintext version of the above warning
    _log_based_warning_plaintext = ('Warning: log-based check. See documentation '
                                    'in ScubaGoggles GitHub repository for '
                                    'limitations.')

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
                 missing_policies: set,
                 dns_logs: dict,
                 omissions: dict,
                 annotations: dict,
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
        :param missing_policies: set with the set of policies missing from the
            policy API output
        :param dns_logs: dictionary with the SPF, DKIM, and DMARC query logs
        :param omissions: dict with the omissions specified in the config
            file (empty dict if none omitted)
        :param annotations: dict with the annotations specified in the config
            file (empty dict if none provided)
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
        self._missing_policies = set()
        for policy in missing_policies:
            # Prepend each missing policy with "policy/" as that's how they are
            # listed in the rego
            self._missing_policies.add(f'policy/{policy}')
        self._dns_logs = dns_logs
        self._full_name = prod_to_fullname[product]
        self._omissions = {
            # Lowercase all the keys for case-insensitive comparisons
            key.lower(): value for key, value in omissions.items()
        }
        self._annotations = {
            # Lowercase all the keys for case-insensitive comparisons
            key.lower(): value for key, value in annotations.items()
        }
        self.progress_bar = progress_bar
        self.rules_table = None
        self.annotated_failed_policies = {}

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
                              report_uuid: str,
                              darkmode: str) -> str:
        """
        Builds the Front Page Report using the HTML Report Template

        :param fragments: list object containing each baseline
        :param tenant_info: list object containing each baseline
        :param darkmode: enable/disable dark mode
        """

        template_file = (cls._reporter_path
                         / 'FrontPageReport/FrontPageReportTemplate.html')
        html = template_file.read_text(encoding='utf-8')

        table = ''.join(fragments)

        main_css_file = cls._reporter_path / 'styles/main.css'

        main_js_file = cls._reporter_path / 'scripts/main.js'

        css = main_css_file.read_text(encoding='utf-8')

        javascript = main_js_file.read_text(encoding='utf-8')

        html = html.replace('{{MAIN_CSS}}', f'<style>{css}</style>')

        html = html.replace('{{MAIN_JS}}', f'<script>{javascript}</script>')

        dark_mode_toggle_template = cls._reporter_path / 'templates/DarkModeToggleTemplate.html'
        dark_mode_toggle_button = dark_mode_toggle_template.read_text(encoding='utf-8')

        html = html.replace('{{DARK_MODE_TOGGLE}}', dark_mode_toggle_button)
        html = html.replace('{{SGR_SETTINGS}}',
                            f'<span id="sgr_settings" data-darkmode="{darkmode}"></span>')

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
            if isinstance(raw_date, date):
                # If the user put the date in without quotes, it's already
                # a datetime object
                expiration_date = raw_date
            else:
                try:
                    expiration_date = datetime.strptime(raw_date, '%Y-%m-%d').date()
                except (ValueError, TypeError):
                    # Malformed date, don't omit the policy
                    warning = (f'Config file indicates omitting {control_id}, '
                            f'but the provided expiration date, {raw_date}, is '
                            'malformed. The expected format is yyyy-mm-dd. Control'
                            ' will not be omitted.')
                    self._warn(warning)
                    return False
            today = datetime.now().date()
            if expiration_date > today:
                # The expiration date is in the future, omit the policy
                return True
            # The expiration date is passed, don't omit the policy
            warning = (f'Config file indicates omitting {control_id}, but '
                       f'the provided expiration date, {raw_date}, has passed. '
                       'Control will not be omitted.')
            self._warn(warning)
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
            self._warn(warning)
            return ("<span class='comment-heading'>User justification not "
                    "provided</span>")
        return ("<span class='comment-heading'>User justification</span>\""
                f"{self._omissions[control_id]['rationale']}\"")

    def _is_control_marked_incorrect(self, control_id: str) -> bool:
        """
        Determine if the supplied control was marked incorrect in the config
        file.
        :param control_id: the control ID, e.g., GWS.GMAIL.1.1v1. Case-
            insensitive.
        """
        # Lowercase for case-insensitive comparison
        control_id = control_id.lower()
        if control_id in self._annotations:
            if 'incorrectresult' in self._annotations[control_id]:
                return bool(self._annotations[control_id]['incorrectresult'])
        return False

    def _get_annotation_comment(self, control_id: str) -> str:
        """
        Return the annotation comment in the config file for the indicated
        control, if provided. If not provided or is empty, return None.
        :param control_id: the control ID, e.g., GWS.GMAIL.1.1v1. Case-
            insensitive.
        """
        # Lowercase for case-insensitive comparison
        control_id = control_id.lower()
        if control_id not in self._annotations:
            return None
        # If any of the following conditions is true, no comment was
        # provided
        no_comment = ((self._annotations[control_id] is None) or
                        ('comment' not in self._annotations[control_id]) or
                        (self._annotations[control_id]['comment'] is None) or
                        (self._annotations[control_id]['comment'] == ''))
        if no_comment:
            return None
        return self._annotations[control_id]['comment']

    def _get_remediation_date(self, control_id: str) -> str:
        """
        Return the remediation date in the config file for the indicated
        control, if provided. If not provided or is empty, return None.
        :param control_id: the control ID, e.g., GWS.GMAIL.1.1v1. Case-
            insensitive.
        """
        # Lowercase for case-insensitive comparison
        control_id = control_id.lower()
        if control_id not in self._annotations:
            return None
        # If any of the following conditions is true, no date was
        # provided
        no_date = ((self._annotations[control_id] is None) or
                        ('remediationdate' not in self._annotations[control_id]) or
                        (self._annotations[control_id]['remediationdate'] is None) or
                        (self._annotations[control_id]['remediationdate'] == ''))
        if no_date:
            return None
        return self._annotations[control_id]['remediationdate']

    def _get_omission_rationale_plaintext(self, control_id: str) -> str:
        """
        Return the plain text rationale indicated in the config file for the
        indicated control, if provided. If not, return None.
        :param control_id: the control ID, e.g., GWS.GMAIL.1.1v1. Case-
            insensitive.
        """
        # Lowercase for case-insensitive comparison
        control_id = control_id.lower()
        if control_id not in self._omissions:
            return None
        # If any of the following conditions is true, no rationale was
        # provided
        no_rationale = ((self._omissions[control_id] is None) or
                        ('rationale' not in self._omissions[control_id]) or
                        (self._omissions[control_id]['rationale'] is None) or
                        (self._omissions[control_id]['rationale'] == ''))
        if no_rationale:
            return None
        return self._omissions[control_id]['rationale']

    def _get_omission_expiration_date(self, control_id: str) -> str:
        """
        Return the omission expiration date in the config file for the
        indicated control, if provided. If not provided or is empty, return None.
        :param control_id: the control ID, e.g., GWS.GMAIL.1.1v1. Case-
            insensitive.
        """
        # Lowercase for case-insensitive comparison
        control_id = control_id.lower()
        if control_id not in self._omissions:
            return None
        if self._omissions[control_id] is None:
            return None
        # If any of the following conditions is true, no date was
        # provided
        no_date = (('expiration' not in self._omissions[control_id]) or
                   (self._omissions[control_id]['expiration'] is None) or
                   (self._omissions[control_id]['expiration'] == ''))
        if no_date:
            return None
        raw_date = self._omissions[control_id]['expiration']
        if isinstance(raw_date, date):
            return raw_date.strftime('%Y-%m-%d')
        return raw_date

    def _build_comments_array(self, control_id: str) -> list:
        """
        Build an array of comments containing the omission rationale and
        annotation comment, if provided.
        :param control_id: the control ID, e.g., GWS.GMAIL.1.1v1. Case-
            insensitive.
        :return: list of strings, empty if neither was provided
        """
        comments = []
        rationale = self._get_omission_rationale_plaintext(control_id)
        if rationale:
            comments.append(rationale)
        annotation_comment = self._get_annotation_comment(control_id)
        if annotation_comment:
            comments.append(annotation_comment)
        return comments

    def _build_resolution_date(self, control_id: str) -> str:
        """
        Build the resolution date string. Returns the omission expiration date
        if present, otherwise the annotation remediation date if present,
        otherwise "N/A".
        :param control_id: the control ID, e.g., GWS.GMAIL.1.1v1. Case-
            insensitive.
        :return: string representing the resolution date or "N/A"
        """
        omission_expiration = self._get_omission_expiration_date(control_id)
        if omission_expiration:
            return omission_expiration
        remediation_date = self._get_remediation_date(control_id)
        if remediation_date:
            # Ensure it's in yyyy-mm-dd format
            if isinstance(remediation_date, date):
                return remediation_date.strftime('%Y-%m-%d')
            return remediation_date
        return None

    def _sanitize_details(self, table_data: list) -> list:
        '''
        Remove HTML elements from the 'Details' and 'OriginalDetails' columns
        of the results that aren't appropriate for JSON, e.g., icons.
        '''
        for result in table_data:
            # Sanitize Details
            details = result['Details']
            details = details.replace(self._log_based_warning,
                                      self._log_based_warning_plaintext)
            details = details.replace('<br>', '\n')

            dns_link = "<a href=\"#dns-logs\">View DNS logs</a> for more details."
            details = details.replace(dns_link, "")
            details = self._convert_html_lists_to_plaintext(details)

            result['Details'] = details

            # Sanitize OriginalDetails if present
            if 'OriginalDetails' in result:
                original_details = result['OriginalDetails']
                original_details = original_details.replace(self._log_based_warning,
                                                           self._log_based_warning_plaintext)
                original_details = original_details.replace('<br>', '\n')
                original_details = original_details.replace(dns_link, "")
                original_details = self._convert_html_lists_to_plaintext(original_details)
                result['OriginalDetails'] = original_details
        return table_data

    def _convert_html_lists_to_plaintext(self, text: str) -> str:
        """
        Convert simple HTML unordered list tags to plaintext bullets so they do
        not leak into Details or OriginalDetails.
        """
        if not isinstance(text, str):
            return text
        text = text.replace('<ul>', ' ')
        text = text.replace('</ul>', '')
        text = text.replace('<li>', '\n- ')
        text = text.replace('</li>', ' ')
        return text.strip()

    def _insert_classroom_warning(self, html: str) -> str:
        """
        Adds the warning notifcation about the classroom baseline, if
        applicable.

        :param html: The HTML string representing the report.
        """

        classroom_notification = ('<h4>Note: Google Classroom is not available '
                                  'by default in GWS but as an additional '
                                  'Google Service.</h4>')

        if self._full_name == 'Google Classroom':
            html = html.replace('{{WARNING_NOTIFICATION}}',
                                classroom_notification)
        else:
            html = html.replace('{{WARNING_NOTIFICATION}}', '')
        return html

    def _build_report_html(self, fragments: list, rules_data : dict, darkmode: str) -> str:
        """
        Adds data into HTML Template and formats the page accordingly

        :param fragments: list object containing each baseline
        :param rules_data: the 'actual_value' for GWS.COMMONCONTROLS.13.1 if
            present, None otherwise
        :param darkmode: enable/disable dark mode
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

        main_js_file = self._reporter_path / 'scripts/main.js'

        css = main_css_file.read_text(encoding='utf-8')

        javascript = main_js_file.read_text(encoding='utf-8')

        html = html.replace('{{MAIN_CSS}}', f'<style>{css}</style>')

        html = html.replace('{{MAIN_JS}}', f'<script>{javascript}</script>')

        dark_mode_toggle_template = self._reporter_path / 'templates/DarkModeToggleTemplate.html'
        dark_mode_toggle_button = dark_mode_toggle_template.read_text(encoding='utf-8')
        html = html.replace('{{DARK_MODE_TOGGLE}}', dark_mode_toggle_button)
        html = html.replace('{{SGR_SETTINGS}}',
                            f'<span id="sgr_settings" data-darkmode="{darkmode}"></span>')

        html = self._insert_classroom_warning(html)

        # Relative path back to the front page
        home_page = f'../{self._main_report_name}.html'
        html = html.replace('{{HOMELINK}}', home_page)

        now = datetime.now()

        # Before the ScubaGoggles 1.0 release, the "baseline version" to
        # display in the report metadata is the ScubaGoggles major + minor
        # version, e.g., 0.5. After the 1.0 release, just display the major
        # version.
        if Version.major == 0:
            baseline_version = f'{Version.major}.{Version.minor}'
        else:
            baseline_version = Version.major

        report_date = (now.strftime('%m/%d/%Y %H:%M:%S')
                       + ' ' + time.tzname[time.daylight])
        meta_data = (f'<table style = "text-align:center;">'
                     '<tr><th>Customer Name</th><th>Customer Domain</th>'
                     '<th>Customer ID</th><th>Report Date</th>'
                     '<th>Baseline Version</th><th>Tool Version</th></tr>'
                     f'<tr><td>{self._tenant_name}</td><td>{self._tenant_domain}</td>'
                     f'<td>{self._tenant_id}</td><td>{report_date}</td>'
                     f'<td>{baseline_version}</td><td>{Version.current}</td></tr>'
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

        if self._full_name != 'Gmail':
            html = html.replace('{{DNS_LOGS}}', '')
            return html
        log_html = "<hr><h2 id=\"dns-logs\">DNS Logs</h2>"
        log_html += ("<p>DNS queries ScubaGear made while identifying SPF, "
            "DKIM, and DMARC records. Note: if DNS queries unexepectedly "
            "return 0 txt records, it may be a sign the system-defualt "
            "resolver is unable to resolve the domain names (e.g., due to a "
            "split horizon setup).</p>") 
        for log_type in self._dns_logs:
            log_html += "<div class='dns-logs'>"
            log_html += f"<h3>{log_type.upper()}</h3>"
            logs = []
            for domain in self._dns_logs[log_type]:
                for query in domain['log']:
                    # Inserting the &#8203; tells the browser it can break these "words"
                    # where ever it needs to. There are some really long domain names
                    # and one-word txt records (e.g., DKIM records) that would really
                    # skew the table otherwise
                    qname = "&#8203;".join(query['query_name'])
                    answers = query['query_answers']
                    answers = ["&#8203;".join(answer) for answer in answers]
                    logs.append({
                        "Query Name": qname,
                        "Query Method": query['query_method'],
                        "Summary": query['query_result'],
                        "Answers": '\n'.join(answers)
                    })
            log_table = self.create_html_table(logs)
            log_table = log_table.replace("<table>", "<table class='alternating dns-table'>")
            log_html += log_table
            log_html += "</div>"
        html = html.replace('{{DNS_LOGS}}', log_html)
        return html

    def _get_failed_prereqs(self, test: dict) -> set:
        """
        Given the output of a specific Rego test and the set of successful
        and unsuccessful calls, determine the set of prerequisites that were
        not met.

        :param test: a dictionary representing the output of a Rego test
        """

        if 'Prerequisites' not in test:
            prereqs = {}
            raise RuntimeError(f'No prerequisites found for {test["PolicyId"]}')

        prereqs = test['Prerequisites']

        policy_prereqs = set()
        other_prereqs = set()
        for prereq in prereqs:
            if prereq.startswith('policy/'):
                policy_prereqs.add(prereq)
            else:
                other_prereqs.add(prereq)

        # A function/API call is failed if it is either missing from the
        # successful_calls set or present in the unsuccessful_calls
        failed_prereqs = set().union(
            other_prereqs.difference(self._successful_calls),
            other_prereqs.intersection(self._unsuccessful_calls)
        )

        # Add any missing policies to the failed prereq set
        failed_prereqs = failed_prereqs.union(
            self._missing_policies.intersection(policy_prereqs))

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
        missing_policies = [prereq for prereq in failed_prereqs
                            if prereq.startswith('policy/')]
        failed_functions = failed_prereqs.difference(failed_apis,
                                                    missing_policies)

        failed_details = ''
        if len(failed_apis) > 0:
            links = ', '.join(failed_apis)
            failed_details += ('This test depends on the following API '
                               'call(s) which did not execute successfully: '
                               f'{links}. ')

        if len(missing_policies) > 0:
            # [7:] in the following line removes the leading "policy/" from the
            # string, that's not actually part of the setting name, the Rego
            # includes that just to disambiguate the policy settings from the
            # function prereqs
            styled_policies = [f'<pre>{policy[7:]}</pre>'
                                for policy in missing_policies]
            policy_str = ''.join(styled_policies)
            is_plural = len(missing_policies) != 1
            failed_details += 'This test depends on the following '
            failed_details += 'settings ' if is_plural else 'setting '
            failed_details += 'returned by the policy API but '
            failed_details += 'are ' if is_plural else 'is '
            failed_details += f'unexpectedly missing or invalid: {policy_str} '

        if len(failed_functions) > 0:
            function_str = ', '.join(failed_functions)
            failed_details += ('This test depends on the following '
                               'function(s) which did not execute '
                               f'successfully: {function_str}. ')

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
        Wrapper for the warning function, that clears and refreshes the
        progress bar if one has been provided, to keep the output clean.
        Accepts all the arguments the warning function accepts.
        """
        if self.progress_bar is not None:
            self.progress_bar.clear()
        log.warning(*args, **kwargs)
        if self.progress_bar is not None:
            self.progress_bar.refresh()

    def _add_annotation(self, control_id: str, result: str, details: str):
        """
        Adds the annotation provided by the user in the config file to the
        result details if applicable.

        :param control_id: The control ID, e.g., GWS.GMAIL.1.1v0.6. Case-
            insensitive.
        :param result: The test result, e.g., "Pass"
        :param details: The test result details, e.g., "Requirement met."
        """
        # Lowercase for case-insensitive comparison
        control_id = control_id.lower()
        comment = self._get_annotation_comment(control_id)
        incorrect_result = self._is_control_marked_incorrect(control_id)
        remediation_date = self._get_remediation_date(control_id)

        if incorrect_result and result in ("Pass", "Fail", "Warning"):
            if comment is None:
                # Result marked incorrect, comment not provided
                self._warn((f"Config file marks the result for {control_id} "
                           "incorrect, but no justification provided."))
                details = ("Test result marked incorrect by user. <span class="
                           "'comment-heading'>User justification not provided"
                           "</span>")
            else:
                # Result marked incorrect, comment provided
                details = ("Test result marked incorrect by user. <span class="
                           "'comment-heading'>User justification</span>\""
                           f"{comment}\"")
        elif comment is not None:
            # Not incorrect but comment provided
            details += ("<span class='comment-heading'>User comment</span>\""
                        f"{comment}\"")
            if remediation_date is not None:
                details += ("<span class='comment-heading'>Anticipated "
                            f"remediation date</span>\"{remediation_date}\"")

                if isinstance(remediation_date, date):
                    # If the user put the date in without quotes, it's already
                    # a datetime object
                    parsed_date = remediation_date
                else:
                    try:
                        parsed_date = datetime.strptime(remediation_date,
                                                        '%Y-%m-%d').date()
                    except (ValueError, TypeError):
                        # Malformed date
                        warning = ('Error parsing the remediation date for '
                                f'{control_id}, {remediation_date}. The expected '
                                'format is yyyy-mm-dd.')
                        self._warn(warning)
                        return details

                today = datetime.now().date()
                if parsed_date < today and result in ("Fail", "Warning"):
                    warning = (f'Anticipated remediation date for {control_id}, '
                            f'{remediation_date}, has passed. ')
                    self._warn(warning)
        return details

    def rego_json_to_ind_reports(self,
                                 test_results: list,
                                 out_path: str,
                                 darkmode: str) -> list:
        """
        Transforms the Rego JSON output into individual HTML and JSON reports

        :param test_results: list of dictionaries with results of Rego test,
            deserialized from JSON data.
        :param out_path: output path where HTML should be saved
        :param darkmode: enable/disable dark mode
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
            'Omit': 0,
            'IncorrectResults': 0
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
                    error_details = f'Report issue on {issues_link}'
                    table_data.append({
                        'Control ID': control_id,
                        'Requirement': requirement,
                        'Result': 'Error - Test results missing',
                        'Criticality': '-',
                        'Details': error_details,
                        'OriginalResult': 'Error - Test results missing',
                        'OriginalDetails': error_details,
                        'Comments': self._build_comments_array(control_id),
                        'ResolutionDate': self._build_resolution_date(control_id)
                    })
                    log.error('No test results found for Control Id %s',
                              control_id)
                    continue

                if self._is_control_omitted(control_id):
                    # Handle the case where the control was omitted
                    rationale = self._get_omission_rationale(control_id)

                    original_result = None
                    original_details = None

                    report_stats['Omit'] += 1

                    for test in tests:
                        result = self._get_test_result(test['RequirementMet'],
                                                        test['Criticality'],
                                                        test['NoSuchEvent'])
                        details = test['ReportDetails']
                        # Store original before annotation
                        original_result = result
                        original_details = details
                        details = self._add_annotation(control_id,
                                                       result,
                                                       details)

                    table_data.append({
                    'Control ID': control_id,
                    'Requirement': requirement,
                    'Result': 'Omitted',
                    'Criticality': tests[0]['Criticality'],
                    'Details': f'Test omitted by user. {rationale}',
                    'OriginalResult': original_result if original_result else 'N/A',
                    'OriginalDetails': original_details if original_details else 'N/A',
                    'Comments': self._build_comments_array(control_id),
                    'ResolutionDate': self._build_resolution_date(control_id)
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
                                        'Details': failed_details,
                                        'OriginalResult': 'Error',
                                        'OriginalDetails': failed_details,
                                        'Comments': self._build_comments_array(control_id),
                                        'ResolutionDate': self._build_resolution_date(control_id)})
                        continue

                    if control_id.startswith('GWS.COMMONCONTROLS.13.1'):
                        rules_data = test['ActualValue']

                    result = self._get_test_result(test['RequirementMet'],
                                                    test['Criticality'],
                                                    test['NoSuchEvent'])

                    details = test['ReportDetails']

                    reports_api_link = ApiReference.LIST_ACTIVITIES.value
                    if reports_api_link in test['Prerequisites']:
                        # If the test depends on the reports API, append a
                        # warning about the API's limitations to the details
                        # column.
                        if not details.endswith('</ul>'):
                            # If the details ends with a list (e.g., "The
                            # following OUs are non-compliant:..."), there will
                            # already be enough whitespace between the list and
                            # this warning. But if it doesn't end with a list,
                            # e.g., "Requirement met in all OUs and groups.",
                            # insert some additional whitespace for improved
                            # readability.
                            details += '<br><br>'
                        details += self._log_based_warning

                    # Append annotation if applicable
                    details_pre_annotation = details
                    details = self._add_annotation(control_id,
                                                   result,
                                                   details)


                    incorrect_result = self._is_control_marked_incorrect(control_id)
                    if result == "Fail":
                        # If the user commented on a failed control, save the
                        # comment to the failed control to comment mapping
                        self.annotated_failed_policies[control_id] = {
                            'Comment': self._get_annotation_comment(control_id),
                            'RemediationDate': self._get_remediation_date(control_id),
                            'IncorrectResult': incorrect_result
                        }

                    # Handle incorrect results
                    if incorrect_result and result in ("Pass", "Fail", "Warning"):
                        report_stats["IncorrectResults"] += 1
                        table_data.append({
                            'Control ID': control_id,
                            'Requirement': requirement,
                            'Result': 'Incorrect result',
                            'Criticality': test['Criticality'],
                            'Details': details,
                            'OriginalResult': result,
                            'OriginalDetails': details_pre_annotation,
                            'Comments': self._build_comments_array(control_id),
                            'ResolutionDate': self._build_resolution_date(control_id)})
                        continue

                    # This is the typical case, the test result is not
                    # missing, omitted, or incorrect
                    report_stats[self._get_summary_category(result)] += 1
                    table_data.append({
                        'Control ID': control_id,
                        'Requirement': requirement,
                        'Result': result,
                        'Criticality': test['Criticality'],
                        'Details': details,
                        'OriginalResult': result,
                        'OriginalDetails': details_pre_annotation,
                        'Comments': self._build_comments_array(control_id),
                        'ResolutionDate': self._build_resolution_date(control_id)})

            markdown_group_name = re.sub(r'[^\w\s-]', '-',
                                        baseline_group['GroupName'].lower())
            markdown_group_name = re.sub(r'-+', '-', markdown_group_name)
            markdown_group_name = markdown_group_name.strip('-')
            markdown_group_name = markdown_group_name.replace(' ', '-')
            group_reference_url = (f'{self._github_url}/blob/{Version.current}/'
                                f'scubagoggles/baselines/{product}.md'
                                f'#{baseline_group["GroupNumber"]}-'
                                + markdown_group_name)
            markdown_link = (f'<a class="control_group" href="{group_reference_url}" '
                             'target="_blank">'
                             f'{baseline_group["GroupName"]}</a>')
            fragments.append(f'<h2>{product_upper}-'
                             f'{baseline_group["GroupNumber"]} '
                             f'{markdown_link}</h2>')

            json_only = [
                'OriginalResult',
                'OriginalDetails',
                'Comments',
                'ResolutionDate'
            ]
            filtered_table_data = [
                {k: v for k, v in row.items()
                if k not in json_only}
                for row in table_data
            ]
            fragments.append(self.create_html_table(filtered_table_data))
            results_data.update({'GroupName': baseline_group['GroupName']})
            results_data.update({'GroupNumber': baseline_group['GroupNumber']})
            results_data.update({'GroupReferenceURL': group_reference_url})
            results_data.update({'Controls': self._sanitize_details(table_data)})
            json_data.append(results_data)
        html = self._build_report_html(fragments, rules_data, darkmode)
        with open(f'{out_path}/IndividualReports/{ind_report_name}.html',
                        mode='w', encoding='UTF-8') as html_file:
            html_file.write(html)
        return [report_stats, json_data]
