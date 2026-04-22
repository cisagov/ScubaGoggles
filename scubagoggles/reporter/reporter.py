"""
reporter.py creates the report html page
"""
# Must remove pylint disable too many lines when fixing this file.
# pylint: disable=too-many-lines

import logging
import re
from datetime import date, datetime
from html import escape
from pathlib import Path

from scubagoggles.scuba_constants import API_LINKS, ApiReference
from scubagoggles.version import Version

from . import reporter_html as rh

log = logging.getLogger(__name__)


# Nine instance attributes is reasonable in this case.
# pylint: disable=too-many-instance-attributes
class Reporter:

    """The Reporter class generates the HTML files containing the conformance
    reports.
    """

    _github_url = 'https://github.com/cisagov/scubagoggles'

    _reporter_path = Path(__file__).parent

    # Indicator definitions with colors and descriptions
    _indicator_definitions = {
        'Automated Check': {
            'color': '#5E9732',
            'text_color': 'black',
            'description': 'Automatically verified by ScubaGoggles'
        },
        'Log-Based Check': {
            'color': '#F6E8E5',
            'text_color': 'black',
            'description': 'Requires log-based verification'
        },
        'Manual': {
            'color': '#046B9A',
            'text_color': 'white',
            'description': 'Requires manual verification'
        },
        'Configurable': {
            'color': '#005288',
            'text_color': 'white',
            'description': 'Customizable via config file'
        },
        'BOD 25-01 Requirement': {
            'color': '#DC3545',
            'text_color': 'white',
            'description': 'Required by CISA BOD 25-01'
        },
        'Requires Configuration': {
            'color': '#DC3545',
            'text_color': 'white',
            'description': 'Config file required for check'
        }
    }

    # pylint: disable-next=too-many-positional-arguments
    def __init__(
        self,
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
        omit_ou: dict,
        progress_bar=None,
    ):
        """Reporter class initialization"""

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
            # Prepend each missing policy with "policy/" as that's how they are listed in the rego
            self._missing_policies.add(f"policy/{policy}")

        self._dns_logs = dns_logs
        self._full_name = prod_to_fullname[product]

        self._omissions = {key.lower(): value for key, value in omissions.items()}
        self._annotations = {key.lower(): value for key, value in annotations.items()}

        k = "sites"
        v = omit_ou
        omit_ou_d = {k: v}
        self._excludesite = {key.lower(): value for key, value in omit_ou_d.items()}

        self.progress_bar = progress_bar
        self.rules_table = None
        self.annotated_failed_policies = {}

    @staticmethod
    def _get_test_result(requirement_met: bool, criticality: str, no_such_events: bool) -> str:
        """
        Checks the Rego to see if the baseline passed or failed and indicates
        the criticality of the baseline.
        """
        criticality = criticality.lower()

        if "3rd party" in criticality or "not-implemented" in criticality:
            result = "N/A"
        elif no_such_events:
            result = "No events found"
        elif requirement_met:
            result = "Pass"
        elif criticality in ("should", "may"):
            result = "Warning"
        else:
            result = "Fail"

        return result

    def _render_indicator_badge(self, indicator: dict, github_url: str = None) -> str:
        """
        Renders a single indicator as an HTML badge, optionally wrapped in a link.

        :param indicator: Dictionary with 'name', optionally 'color', and optionally 'link' keys
        :param github_url: Base GitHub URL for converting relative links
        :return: HTML string for the badge
        """
        indicator_name = indicator.get('name', '')
        color = indicator.get('color', '#6C757D')
        link_url = indicator.get('link', None)

        # Determine text color based on background color brightness
        # Simple heuristic: if color is light (like #F6E8E5), use black text
        if color and color.upper() in ['#F6E8E5', '#FFF7D6']:
            text_color = 'black'
        elif color == '#5E9732':
            text_color  = 'black'
        else:
            text_color = 'white'

        # Get description from definitions if available
        indicator_info = self._indicator_definitions.get(
            indicator_name,
            {'description': indicator_name}
        )
        description = indicator_info.get('description', indicator_name)

        # Convert relative links to absolute GitHub URLs
        if link_url:
            if link_url.startswith('#'):
                # Anchor link - convert to GitHub baseline document link
                if github_url:
                    # Link to the baseline document on GitHub
                    # We need to determine which baseline file - use the product name
                    product = getattr(self, '_product', '')
                    if product:
                        baseline_file = f'{product}.md'
                        baseline_path = (f'{github_url}/blob/{Version.current}/'
                                       f'scubagoggles/baselines/{baseline_file}'
                                       f'{link_url}')
                        link_url = baseline_path
                    else:
                        baseline_path = (f'{github_url}/blob/{Version.current}/'
                                       f'scubagoggles/baselines/{link_url}')
                        link_url = baseline_path
            elif link_url.startswith('../'):
                # Relative path - convert to GitHub blob URL
                if github_url:
                    # Remove '../' and convert to GitHub path
                    path = link_url.replace('../', '')
                    link_url = f'{github_url}/blob/{Version.current}/{path}'

        # Create a badge with inline styling
        badge_style = (f'background-color: {color}; color: {text_color}; '
                      f'padding: 2px 8px; border-radius: 3px; '
                      f'font-size: 0.85em; margin-right: 5px; '
                      f'display: inline-block; white-space: nowrap; '
                      f'font-weight: 500;')

        if link_url:
            # Add link styling
            badge_style += ' text-decoration: none;'
            badge_html = (f'<a href="{link_url}" target="_blank" '
                         f'class="indicator-badge" '
                         f'style="{badge_style}" '
                         f'title="{description}">'
                         f'{indicator_name}</a>')
        else:
            badge_html = (f'<span class="indicator-badge" '
                         f'style="{badge_style}" '
                         f'title="{description}">'
                         f'{indicator_name}</span>')
        return badge_html

    def _render_indicators(self, indicators: list) -> str:
        """
        Renders a list of indicators as HTML badges.

        :param indicators: List of indicator dictionaries with 'name',
            optionally 'color', and optionally 'link'
        :return: HTML string containing all badges
        """
        if not indicators:
            return ''
        github_url = self._github_url
        badges = [self._render_indicator_badge(ind, github_url) for ind in indicators]
        return '<div style="margin-top: 5px;">' + ''.join(badges) + '</div>'

    def _collect_all_indicators(self) -> dict:
        """
        Collects all unique indicators from all controls across all baseline groups.

        :return: Dictionary mapping indicator names to their info (color, description)
        """
        all_indicators = {}
        for baseline_group in self._product_policies:
            for control in baseline_group['Controls']:
                indicators = control.get('Indicators', [])
                for indicator in indicators:
                    indicator_name = indicator.get('name', '')
                    if indicator_name:
                        if indicator_name not in all_indicators:
                            # Get description from definitions if available
                            indicator_info = self._indicator_definitions.get(
                                indicator_name,
                                {'description': indicator_name}
                            )
                            all_indicators[indicator_name] = {
                                'color': indicator.get('color',
                                    self._indicator_definitions.get(
                                        indicator_name, {}
                                    ).get('color', '#6C757D')),
                                'description': indicator_info.get('description', indicator_name)
                            }
        return all_indicators

    def _build_indicator_legend(self) -> str:
        """
        Builds the HTML for the indicator legend/key section based on
        indicators actually found in the report.

        :return: HTML string for the legend
        """
        all_indicators = self._collect_all_indicators()

        if not all_indicators:
            return ''

        legend_html = ('<div class="indicator-legend" style="margin: 20px 0; '
                      'margin-left: 50px; font-size: 0.9em;">')
        legend_html += ('<h3 style="margin: 0 0 10px 0; color: var(--header-color); '
                       'font-weight: bold; font-size: 0.95em; text-align: left;">'
                       'Policy Indicators:</h3>')
        legend_html += '<ul style="list-style: none; padding-left: 0; margin: 0;">'

        # Sort indicators for consistent display
        github_url = self._github_url
        for indicator_name in sorted(all_indicators.keys()):
            indicator_info = all_indicators[indicator_name]
            indicator_dict = {'name': indicator_name,
                           'color': indicator_info['color']}
            # Try to find a link for this indicator from the actual controls
            # For legend, we'll use a link to the baseline document if it's
            # a key-terminology link
            if indicator_name in ['Automated Check', 'Manual', 'Configurable']:
                # These typically link to #key-terminology in the baseline
                indicator_dict['link'] = '#key-terminology'
            badge = self._render_indicator_badge(indicator_dict, github_url)
            legend_html += (f'<li style="display: flex; align-items: center; '
                          f'gap: 8px; margin-bottom: 8px; font-size: 0.85em;">'
                          f'{badge}'
                          f'<span style="color: var(--text-color);">'
                          f'{indicator_info["description"]}</span>'
                          f'</li>')

        legend_html += '</ul></div>'
        return legend_html

    @staticmethod
    def create_html_table(table_data: list) -> str:
        """Compatibility wrapper; implementation lives in _reporter_html.py."""
        return rh.create_html_table(table_data)

    @classmethod
    def build_front_page_html(
        cls,
        fragments: list,
        tenant_info: dict,
        report_uuid: str,
        darkmode: str,
        redaction:str
    ) -> str:
        """Compatibility wrapper; implementation lives in _reporter_html.py."""
        return rh.build_front_page_html(fragments, tenant_info, report_uuid, darkmode, redaction)

    def _is_control_omitted(self, control_id: str) -> bool:
        """Determine if the supplied control was marked for omission in the config file."""
        control_id = control_id.lower()
        if control_id in self._omissions:
            if self._omissions[control_id] is None:
                return True
            if "expiration" not in self._omissions[control_id]:
                return True

            raw_date = self._omissions[control_id]["expiration"]
            if raw_date is None or raw_date == "":
                return True

            if isinstance(raw_date, date):
                expiration_date = raw_date
            else:
                try:
                    expiration_date = datetime.strptime(raw_date, "%Y-%m-%d").date()
                except (ValueError, TypeError):
                    warning = (
                        f"Config file indicates omitting {control_id}, but the provided "
                        f"expiration date, {raw_date}, is malformed. The expected format is "
                        "yyyy-mm-dd. Control will not be omitted."
                    )
                    self._warn(warning)
                    return False

            today = datetime.now().date()
            if expiration_date > today:
                return True

            warning = (
                f"Config file indicates omitting {control_id}, but the provided expiration "
                f"date, {raw_date}, has passed. Control will not be omitted."
            )
            self._warn(warning)

        return False

    def _get_omission_rationale(self, control_id: str) -> str:
        """Return omission rationale HTML snippet, warning if missing."""
        control_id = control_id.lower()
        if control_id not in self._omissions:
            raise RuntimeError(f"{control_id} not omitted in config file, cannot fetch rationale")

        no_rationale = (
            (self._omissions[control_id] is None)
            or ("rationale" not in self._omissions[control_id])
            or (self._omissions[control_id]["rationale"] is None)
            or (self._omissions[control_id]["rationale"] == "")
        )
        if no_rationale:
            warning = f"Config file indicates omitting {control_id}, but no rationale provided."
            self._warn(warning)
            return "<span class='comment-heading'>User justification not provided</span>"

        return (
            "<span class='comment-heading'>User justification</span>\""
            f"{self._omissions[control_id]['rationale']}\""
        )

    def _is_control_marked_incorrect(self, control_id: str) -> bool:
        """Determine if the supplied control was marked incorrect in the config file."""
        control_id = control_id.lower()
        if control_id in self._annotations:
            if "incorrectresult" in self._annotations[control_id]:
                return bool(self._annotations[control_id]["incorrectresult"])
        return False

    def _get_annotation_comment(self, control_id: str):
        """Return annotation comment if provided; else None."""
        control_id = control_id.lower()
        if control_id not in self._annotations:
            return None

        no_comment = (
            (self._annotations[control_id] is None)
            or ("comment" not in self._annotations[control_id])
            or (self._annotations[control_id]["comment"] is None)
            or (self._annotations[control_id]["comment"] == "")
        )
        if no_comment:
            return None
        return self._annotations[control_id]["comment"]

    def _get_remediation_date(self, control_id: str):
        """Return remediation date if provided; else None."""
        control_id = control_id.lower()
        if control_id not in self._annotations:
            return None

        no_date = (
            (self._annotations[control_id] is None)
            or ("remediationdate" not in self._annotations[control_id])
            or (self._annotations[control_id]["remediationdate"] is None)
            or (self._annotations[control_id]["remediationdate"] == "")
        )
        if no_date:
            return None
        return self._annotations[control_id]["remediationdate"]

    def _get_omission_rationale_plaintext(self, control_id: str):
        """Return plain text rationale if provided; else None."""
        control_id = control_id.lower()
        if control_id not in self._omissions:
            return None

        no_rationale = (
            (self._omissions[control_id] is None)
            or ("rationale" not in self._omissions[control_id])
            or (self._omissions[control_id]["rationale"] is None)
            or (self._omissions[control_id]["rationale"] == "")
        )
        if no_rationale:
            return None
        return self._omissions[control_id]["rationale"]

    def _get_omission_expiration_date(self, control_id: str):
        """Return omission expiration date as yyyy-mm-dd if present; else None."""
        control_id = control_id.lower()
        if control_id not in self._omissions:
            return None
        if self._omissions[control_id] is None:
            return None

        no_date = (
            ("expiration" not in self._omissions[control_id])
            or (self._omissions[control_id]["expiration"] is None)
            or (self._omissions[control_id]["expiration"] == "")
        )
        if no_date:
            return None

        raw_date = self._omissions[control_id]["expiration"]
        if isinstance(raw_date, date):
            return raw_date.strftime("%Y-%m-%d")
        return raw_date

    def _build_comments_array(self, control_id: str) -> list:
        """Build array of comments containing omission rationale and annotation comment."""
        comments = []
        rationale = self._get_omission_rationale_plaintext(control_id)
        if rationale:
            comments.append(rationale)
        annotation_comment = self._get_annotation_comment(control_id)
        if annotation_comment:
            comments.append(annotation_comment)
        return comments

    def _build_resolution_date(self, control_id: str):
        """Return omission expiration date, else remediation date, else None."""
        omission_expiration = self._get_omission_expiration_date(control_id)
        if omission_expiration:
            return omission_expiration

        remediation_date = self._get_remediation_date(control_id)
        if remediation_date:
            if isinstance(remediation_date, date):
                return remediation_date.strftime("%Y-%m-%d")
            return remediation_date

        return None

    def _sanitize_details(self, table_data: list) -> list:
        """Delegate to _reporter_html; used for JSON output sanitization."""
        return rh.sanitize_details(table_data)

    def _get_failed_prereqs(self, test: dict) -> set:
        """Determine the set of prerequisites that were not met."""
        if "Prerequisites" not in test:
            raise RuntimeError(f'No prerequisites found for {test["PolicyId"]}')

        prereqs = test["Prerequisites"]

        policy_prereqs = set()
        other_prereqs = set()
        for prereq in prereqs:
            if prereq.startswith("policy/"):
                policy_prereqs.add(prereq)
            else:
                other_prereqs.add(prereq)

        failed_prereqs = set().union(
            other_prereqs.difference(self._successful_calls),
            other_prereqs.intersection(self._unsuccessful_calls),
        )

        failed_prereqs = failed_prereqs.union(self._missing_policies.intersection(policy_prereqs))
        return failed_prereqs

    @staticmethod
    def _get_failed_details(failed_prereqs: set) -> str:
        """Build Details string when prerequisites failed."""
        failed_apis = [API_LINKS[api] for api in failed_prereqs if api in API_LINKS]
        missing_policies = [prereq for prereq in failed_prereqs if prereq.startswith("policy/")]
        failed_functions = failed_prereqs.difference(failed_apis, missing_policies)

        failed_details = ""
        if len(failed_apis) > 0:
            links = ", ".join(failed_apis)
            failed_details += (
                "This test depends on the following API call(s) which did not execute "
                f"successfully: {links}. "
            )

        if len(missing_policies) > 0:
            styled_policies = [f"<pre>{policy[7:]}</pre>" for policy in missing_policies]
            policy_str = "".join(styled_policies)
            is_plural = len(missing_policies) != 1
            failed_details += "This test depends on the following "
            failed_details += "settings " if is_plural else "setting "
            failed_details += "returned by the policy API but "
            failed_details += "are " if is_plural else "is "
            failed_details += f"unexpectedly missing or invalid: {policy_str} "

        if len(failed_functions) > 0:
            function_str = ", ".join(failed_functions)
            failed_details += (
                "This test depends on the following function(s) which did not execute "
                f"successfully: {function_str}. "
            )

        failed_details += "See terminal output for more details."
        return failed_details

    @staticmethod
    def _get_summary_category(result: str) -> str:
        """Map the string test result to the appropriate summary category."""
        if result in {"No events found", "N/A"}:
            return "Manual"
        if result == "Warning":
            return "Warnings"
        if result == "Fail":
            return "Failures"
        if result == "Pass":
            return "Passes"
        raise ValueError(f"Unexpected result, {result}", RuntimeWarning)

    def _warn(self, *args, **kwargs):
        """log.warning wrapper that clears/refreshes a progress bar if provided."""
        if self.progress_bar is not None:
            self.progress_bar.clear()
        log.warning(*args, **kwargs)
        if self.progress_bar is not None:
            self.progress_bar.refresh()

    def _add_annotation(self, control_id: str, result: str, details: str):
        """Append annotation content (comment/incorrect-result/remediation date) if applicable."""
        control_id = control_id.lower()
        comment = self._get_annotation_comment(control_id)
        incorrect_result = self._is_control_marked_incorrect(control_id)
        remediation_date = self._get_remediation_date(control_id)

        if incorrect_result and result in ("Pass", "Fail", "Warning"):
            if comment is None:
                self._warn(
                    f"Config file marks the result for {control_id} incorrect, but no justification provided."
                )
                details = (
                    "Test result marked incorrect by user. "
                    "<span class='comment-heading'>User justification not provided</span>"
                )
            else:
                details = (
                    "Test result marked incorrect by user. "
                    "<span class='comment-heading'>User justification</span>\""
                    f"{comment}\""
                )
        elif comment is not None:
            details += f"<span class='comment-heading'>User comment</span>\"{comment}\""
            if remediation_date is not None:
                details += (
                    "<span class='comment-heading'>Anticipated remediation date</span>\""
                    f"{remediation_date}\""
                )

                if isinstance(remediation_date, date):
                    parsed_date = remediation_date
                else:
                    try:
                        parsed_date = datetime.strptime(remediation_date, "%Y-%m-%d").date()
                    except (ValueError, TypeError):
                        warning = (
                            "Error parsing the remediation date for "
                            f"{control_id}, {remediation_date}. The expected format is yyyy-mm-dd."
                        )
                        self._warn(warning)
                        return details

                today = datetime.now().date()
                if parsed_date < today and result in ("Fail", "Warning"):
                    warning = (
                        f"Anticipated remediation date for {control_id}, {remediation_date}, has passed. "
                    )
                    self._warn(warning)

        return details

    def _build_report_html(self, fragments: list, rules_data: dict, darkmode: str, redaction: str) -> str:
        """
        Delegate HTML assembly to _reporter_html and capture rules_table for the orchestrator.
        """
        legend_html = rh.build_indicator_legend(self._product_policies, product=self._product)
        if legend_html:
            fragments = [legend_html] + fragments
        html, rules_table = rh.build_individual_report_html(
            fragments=fragments,
            rules_data=rules_data,
            darkmode=darkmode,
            redaction=redaction,
            dns_logs=self._dns_logs,
            full_name=self._full_name,
            main_report_name=self._main_report_name,
            tenant_name=self._tenant_name,
            tenant_domain=self._tenant_domain,
            tenant_id=self._tenant_id,
        )
        self.rules_table = rules_table
        return html

    def rego_json_to_ind_reports(self, test_results: list, out_path: str, darkmode: str, redaction: str) -> list:
        """
        Transforms the Rego JSON output into individual HTML and JSON reports
        """
        product = self._product
        product_capitalized = product.capitalize()
        product_upper = "DRIVEDOCS" if product == "drive" else product.upper()
        ind_report_name = product_capitalized + "Report"
        fragments = []
        json_data = []

        github_url = rh.GITHUB_URL

        report_stats = {
            "Manual": 0,
            "Passes": 0,
            "Errors": 0,
            "Failures": 0,
            "Warnings": 0,
            "Omit": 0,
            "IncorrectResults": 0,
        }

        rules_data = None

        for baseline_group in self._product_policies:
            table_data = []
            results_data = {}

            for control in baseline_group["Controls"]:
                control_id = control["Id"]
                requirement_text = escape(control["Value"])
                indicators_html = rh.render_indicators(control.get("Indicators", []), product=self._product)
                requirement = requirement_text + indicators_html if indicators_html else requirement_text


                tests = [test for test in test_results if test["PolicyId"] == control_id]

                if len(tests) == 0:
                    report_stats["Errors"] += 1
                    issues_link = f'<a href="{github_url}/issues" target="_blank">GitHub</a>'
                    error_details = f"Report issue on {issues_link}"
                    table_data.append(
                        {
                            "Control ID": control_id,
                            "Requirement": requirement,
                            "Result": "Error - Test results missing",
                            "Criticality": "-",
                            "Details": error_details,
                            "OriginalResult": "Error - Test results missing",
                            "OriginalDetails": error_details,
                            "Comments": self._build_comments_array(control_id),
                            "ResolutionDate": self._build_resolution_date(control_id),
                        }
                    )
                    log.error("No test results found for Control Id %s", control_id)
                    continue

                if self._is_control_omitted(control_id):
                    rationale = self._get_omission_rationale(control_id)
                    original_result = None
                    original_details = None

                    report_stats["Omit"] += 1

                    for test in tests:
                        result = self._get_test_result(
                            test["RequirementMet"],
                            test["Criticality"],
                            test["NoSuchEvent"],
                        )
                        details = test["ReportDetails"]
                        original_result = result
                        original_details = details
                        details = self._add_annotation(control_id, result, details)

                    table_data.append(
                        {
                            "Control ID": control_id,
                            "Requirement": requirement,
                            "Result": "Omitted",
                            "Criticality": tests[0]["Criticality"],
                            "Details": f"Test omitted by user. {rationale}",
                            "OriginalResult": original_result if original_result else "N/A",
                            "OriginalDetails": original_details if original_details else "N/A",
                            "Comments": self._build_comments_array(control_id),
                            "ResolutionDate": self._build_resolution_date(control_id),
                        }
                    )
                    continue

                for test in tests:
                    failed_prereqs = self._get_failed_prereqs(test)
                    if len(failed_prereqs) > 0:
                        report_stats["Errors"] += 1
                        failed_details = self._get_failed_details(failed_prereqs)
                        table_data.append(
                            {
                                "Control ID": control_id,
                                "Requirement": requirement,
                                "Result": "Error",
                                "Criticality": test["Criticality"],
                                "Details": failed_details,
                                "OriginalResult": "Error",
                                "OriginalDetails": failed_details,
                                "Comments": self._build_comments_array(control_id),
                                "ResolutionDate": self._build_resolution_date(control_id),
                            }
                        )
                        continue

                    if control_id.startswith("GWS.COMMONCONTROLS.13.1"):
                        rules_data = test["ActualValue"]

                    result = self._get_test_result(
                        test["RequirementMet"],
                        test["Criticality"],
                        test["NoSuchEvent"],
                    )

                    details = test["ReportDetails"]

                    reports_api_link = ApiReference.LIST_ACTIVITIES.value
                    if reports_api_link in test["Prerequisites"]:
                        if not details.endswith("</ul>"):
                            details += "<br><br>"
                        
                    details_pre_annotation = details
                    details = self._add_annotation(control_id, result, details)

                    incorrect_result = self._is_control_marked_incorrect(control_id)

                    if result == "Fail":
                        self.annotated_failed_policies[control_id] = {
                            "Comment": self._get_annotation_comment(control_id),
                            "RemediationDate": self._get_remediation_date(control_id),
                            "IncorrectResult": incorrect_result,
                        }

                    if incorrect_result and result in ("Pass", "Fail", "Warning"):
                        report_stats["IncorrectResults"] += 1
                        table_data.append(
                            {
                                "Control ID": control_id,
                                "Requirement": requirement,
                                "Result": "Incorrect result",
                                "Criticality": test["Criticality"],
                                "Details": details,
                                "OriginalResult": result,
                                "OriginalDetails": details_pre_annotation,
                                "Comments": self._build_comments_array(control_id),
                                "ResolutionDate": self._build_resolution_date(control_id),
                            }
                        )
                        continue

                    report_stats[self._get_summary_category(result)] += 1
                    table_data.append(
                        {
                            "Control ID": control_id,
                            "Requirement": requirement,
                            "Result": result,
                            "Criticality": test["Criticality"],
                            "Details": details,
                            "OriginalResult": result,
                            "OriginalDetails": details_pre_annotation,
                            "Comments": self._build_comments_array(control_id),
                            "ResolutionDate": self._build_resolution_date(control_id),
                        }
                    )

            markdown_group_name = re.sub(r"[^\w\s-]", "-", baseline_group["GroupName"].lower())
            markdown_group_name = re.sub(r"-+", "-", markdown_group_name)
            markdown_group_name = markdown_group_name.strip("-")
            markdown_group_name = markdown_group_name.replace(" ", "-")

            group_reference_url = (
                f"{github_url}/blob/{Version.current}/scubagoggles/baselines/{product}.md"
                f'#{baseline_group["GroupNumber"]}-' + markdown_group_name
            )
            markdown_link = (
                f'<a class="control_group" href="{group_reference_url}" target="_blank">'
                f'{baseline_group["GroupName"]}</a>'
            )

            fragments.append(f"<h2>{product_upper}-{baseline_group['GroupNumber']} {markdown_link}</h2>")

            json_only = ["OriginalResult", "OriginalDetails", "Comments", "ResolutionDate"]
            filtered_table_data = [{k: v for k, v in row.items() if k not in json_only} for row in table_data]

            fragments.append(self.create_html_table(filtered_table_data))

            results_data.update({"GroupName": baseline_group["GroupName"]})
            results_data.update({"GroupNumber": baseline_group["GroupNumber"]})
            results_data.update({"GroupReferenceURL": group_reference_url})
            results_data.update({"Controls": self._sanitize_details(table_data)})
            json_data.append(results_data)

        html = self._build_report_html(fragments, rules_data, darkmode, redaction)
        with open(
            f"{out_path}/IndividualReports/{ind_report_name}.html",
            mode="w",
            encoding="UTF-8",
        ) as html_file:
            html_file.write(html)

        return [report_stats, json_data]
