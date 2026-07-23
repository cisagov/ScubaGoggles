"""
reporter_html.py - report html page - html specific
"""
# Must remove pylint disable too many lines when fixing this file.
# pylint: disable=too-many-arguments, too-many-locals, too-many-positional-arguments
import io
import re
import time

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from scubagoggles.parsers.system_rules_parser import SYSTEM_RULES
from scubagoggles.version import Version

INDICATOR_DEFINITIONS = {
    'Automated Check': {
        'color': '#5E9732',
        'text_color': 'black',
        'description': 'Automatically verified by ScubaGoggles',
    },
    'Log-Based Check': {
        'color': '#F6E8E5',
        'text_color': 'black',
        'description': 'Requires log-based verification',
    },
    'Manual': {
        'color': '#046B9A',
        'text_color': 'white',
        'description': 'Requires manual verification',
    },
    'Configurable': {
        'color': '#005288',
        'text_color': 'white',
        'description': 'Customizable via config file',
    },
    'BOD 25-01 Requirement': {
        'color': '#DC3545',
        'text_color': 'white',
        'description': 'Required by CISA BOD 25-01',
    },
    'Requires Configuration': {
        'color': '#DC3545',
        'text_color': 'white',
        'description': 'Config file required for check',
    },
}

GITHUB_URL = 'https://github.com/cisagov/scubagoggles'
LIMITATIONS_URL = f'{GITHUB_URL}/blob/main/docs/usage/Limitations.md'

WARNING_ICON = (
    '<object data="./images/triangle-exclamation-solid.svg" '
    'alt="Warning icon." title="Warning" width="13" height="13"></object>'
)


REPORTER_PATH = Path(__file__).parent


def _inject_meta_tag(html: str) -> str:

    # If a template doesn't contain the placeholder, do nothing.
    if '{{META_TAG}}' not in html:
        return html

    meta_tag_template = REPORTER_PATH / 'templates/MetaTagTemplate.html'
    meta_tag = meta_tag_template.read_text(encoding='utf-8')
    return html.replace('{{META_TAG}}', meta_tag)


def create_html_table(table_data: list,
                      row_class_func: Callable[[dict], str] = None,
                      col_class_func: Callable[[list], str] = None) -> str:

    """Generate an HTML table string from a list of row dictionaries.

    :param list table_data: list of dictionaries, such that the keys
        correspond for each dictionary in the list.
    :param func row_class_func: [optional] function, if specified, that is
        invoked for each dictionary in the given table, and returns a CSS
        class name if a class is to be applied to the table row, or ''
        (or None) if the row has no class associated with it.
    :param func col_class_func: [optional] function, if specified, that is
        invoked for the headings (dictionary keys), and returns list (the
        same size as the number of headings) with a class name or ''
        corresponding to each heading.  The class will be applied to each
        data element for each row in the table.

    :return: HTML table.
    :rtype: str
    """

    table_html = ''
    if not table_data:
        return table_html

    headings = table_data[0].keys()
    data_classes = (col_class_func(headings) if col_class_func
                    else [''] * len(headings))
    with io.StringIO() as outstream:
        outstream.write('\n<table>\n')
        outstream.write('  <thead>\n')
        outstream.write('    <tr>\n')
        for heading in headings:
            outstream.write(f'      <th>{heading}</th>\n')
        outstream.write('    </tr>\n')
        outstream.write('  </thead>\n')

        outstream.write('  <tbody>\n')
        for record in table_data:
            class_name = row_class_func(record) if row_class_func else ''
            class_attr = f' class="{class_name}"' if class_name else ''
            outstream.write(f'    <tr{class_attr}>\n')
            for index, heading in enumerate(headings):
                class_attr = (f' class="{data_classes[index]}"'
                              if data_classes[index] else '')
                outstream.write(f'      <td{class_attr}>{record[heading]}'
                                '</td>\n')
            outstream.write('    </tr>\n')
        outstream.write('  </tbody>\n')
        outstream.write('</table>')
        table_html = outstream.getvalue()

    return table_html


def build_front_page_html(fragments: list, tenant_info: dict, report_uuid: str,
                          darkmode: str, redaction: str) -> str:

    """Build the complete HTML for the report front page.
    """

    template_file = REPORTER_PATH / 'FrontPageReport/FrontPageReportTemplate.html'
    html = template_file.read_text(encoding='utf-8')

    table = ''.join(fragments)
    html = _inject_meta_tag(html)

    dark_toggle = (
        REPORTER_PATH / 'templates/DarkModeToggleTemplate.html'
    ).read_text(encoding='utf-8')
    html = html.replace('{{DARK_MODE_TOGGLE}}', dark_toggle)
    html = html.replace(
    '{{SGR_SETTINGS}}',
    f'<span id="sgr_settings" data-darkmode="{darkmode}" data-redaction="{redaction}"></span>',
)

    html = html.replace('{{report_uuid}}', report_uuid)
    html = html.replace('{{TABLE}}', table)

    meta = _create_meta_table(tenant_info['topLevelOU'],
                              tenant_info['domain'],
                              tenant_info['ID'])

    html = html.replace('{{TENANT_DETAILS}}', meta)
    html = html.replace('{{VERSION}}', Version.current)

    return html


def sanitize_details(table_data: list) -> list:

    """Clean and normalize the Details fields in table data rows.
    """

    for result in table_data:
        details = result['Details']


        dns_link = '<a href="#dns-logs">View DNS logs</a> for more details.'
        details = details.replace(dns_link, '')
        details = convert_html_lists_to_plaintext(details)
        result['Details'] = details

        if 'OriginalDetails' in result:
            orig = result['OriginalDetails']

            orig = orig.replace(dns_link, '')
            orig = convert_html_lists_to_plaintext(orig)
            result['OriginalDetails'] = orig
    return table_data


def convert_html_lists_to_plaintext(text: str) -> str:

    """Convert simple HTML list tags in text to a plain text bullet list.
    """

    if not isinstance(text, str):
        return text
    text = text.replace('<ul>', ' ')
    text = text.replace('</ul>', '')
    text = text.replace('<li>', '\n- ')
    text = text.replace('</li>', ' ')
    return text.strip()


def insert_classroom_warning(html: str, full_name: str) -> str:

    """Insert a product-specific warning note into the HTML based on the
    control name.
    """

    classroom_note = '''Google Classroom is not available by default in GWS
        but as an additional Google Service.'''

    assuredcontrols_note = '''Assured Controls and Assured Controls Plus
        are paid add-ons with Google Workspace. This baseline is intended as
        guidance for agencies that already have these add-ons. Users that
        choose to implement this baseline should carefully consider the
        tradeoffs involved, including the potential security benefits,
        usability impacts, and increased licensing fees for the add-on
        licenses.'''

    notes = {'Assured Controls': assuredcontrols_note,
             'Google Classroom': classroom_note}

    note = re.sub(r'\n\s+', ' ', notes.get(full_name, ''))

    html = html.replace('{{WARNING_NOTIFICATION}}',
                        f'<p class="note">{note}</p>' if note else '')

    return html


def build_individual_report_html(*,
                                 fragments: list,
                                 rules_data: dict | None,
                                 darkmode: str,
                                 redaction: str,
                                 dns_logs: dict,
                                 full_name: str,
                                 main_report_name: str,
                                 tenant_name: str,
                                 tenant_domain: str,
                                 tenant_id: str,
                                 include_licenses: bool = False,
                                 license_data: list | None = None,
                                 license_collection_failed: bool = False,
                                 ) -> tuple[str, list | None]:

    """Build an individual baseline report HTML page and optional rules
    table data.
    """

    template_file = REPORTER_PATH / 'IndividualReport/IndividualReportTemplate.html'
    html = template_file.read_text(encoding='utf-8')
    html = _inject_meta_tag(html)

    html = html.replace('{{TITLE}}', full_name + ' Baseline Report')

    dark_toggle = (REPORTER_PATH / 'templates/DarkModeToggleTemplate.html'
        ).read_text(encoding='utf-8')
    html = html.replace('{{DARK_MODE_TOGGLE}}', dark_toggle)
    html = html.replace(
    '{{SGR_SETTINGS}}',
    f'<span id="sgr_settings" data-darkmode="{darkmode}" data-redaction="{redaction}"></span>',
)
    html = insert_classroom_warning(html, full_name)

    html = html.replace('{{HOMELINK}}', f'../{main_report_name}.html')

    meta = _create_meta_table(tenant_name, tenant_domain, tenant_id, True)

    html = html.replace('{{METADATA}}', meta)
    html = html.replace('{{TABLES}}', ''.join(fragments))

    if include_licenses:
        license_table = _build_license_table(
            license_data or [],
            license_collection_failed=license_collection_failed,
        )
    else:
        license_table = ''
    html = html.replace('{{LICENSES}}', license_table)

    rules_table = _build_rules_table(rules_data)
    html = html.replace('{{RULES}}', rules_table)

    if full_name != 'Gmail':
        html = html.replace('{{DNS_LOGS}}', '')
        return html, rules_table

    # DNS logs block (same logic you already have)
    log_html = '<hr><h2 id="dns-logs">DNS Logs</h2>'
    log_html += (
        '<p>DNS queries ScubaGear made while identifying SPF, DKIM, and DMARC records. '
        'Note: if DNS queries unexepectedly return 0 txt records, it may be a sign '
        'the system-defualt '
        'resolver is unable to resolve the domain names (e.g., due to a split horizon setup).</p>'
    )
    for log_type in dns_logs:
        log_html += "<div class='dns-logs'>"
        log_html += f'<h3>{log_type.upper()}</h3>'
        logs = []
        for domain in dns_logs[log_type]:
            for query in domain['log']:
                qname = '&#8203;'.join(query['query_name'])
                answers = ['&#8203;'.join(answer) for answer in query['query_answers']]
                if 'message' in domain:
                    logs.append(
                        {
                            'Query Name': qname,
                            'Query Method': query['query_method'],
                            'Summary': domain['message'],
                            'Answers': '<br>'.join(['No answers returned']),
                        }
                    )
                logs.append(
                    {
                        'Query Name': qname,
                        'Query Method': query['query_method'],
                        'Summary': query['query_result'],
                        'Answers': '<br>'.join(answers) or '<br>'.join(['No answers returned']),
                    }
                )
        log_table = create_html_table(logs).replace(
            '<table>', "<table class='alternating dns-table'>")
        log_html += log_table
        log_html += '</div>'

    html = html.replace('{{DNS_LOGS}}', log_html)
    return html, rules_table


def _build_license_table(license_data: list, *,
                         license_collection_failed: bool = False) -> str:

    """Build an HTML subscriptions table from the license data collected by
    the Enterprise License Manager API.

    :param list license_data: list of subscription dicts, each containing
        product_name, status, and assigned.
    :param bool license_collection_failed: True when the license API call did
        not complete successfully.

    :return: HTML fragment with the subscriptions table.
    :rtype: str
    """

    if not license_data:
        if license_collection_failed:
            message = 'An error occurred when collecting license information.'
        else:
            message = 'No licenses found.'
        return (
            '\n<hr>\n'
            '<h2 id="subscriptions">Tenant Licensing Information</h2>\n'
            f'<p>{message}</p>\n'
        )

    rows = [
        {
            'Product Name': sub['product_name'],
            'Status': sub['status'],
            'Assigned Licenses': sub['assigned'],
        }
        for sub in license_data
    ]

    html_table = create_html_table(rows)
    return (
        '\n<hr>\n'
        '<h2 id="subscriptions">Tenant Licensing Information</h2>\n'
        + html_table
        + '\n'
    )
def _create_meta_table(name: str,
                       domain: str,
                       ident: str,
                       include_versions: bool = False) -> str:

    """Generates the "metadata" HTML table for the reports.  The table shows
    the tenant name, domain, and customer ID, and optionally the baseline and
    tool versions.

    :param str name: tenant name.
    :param str domain: tenant domain.
    :param str ident: Google customer ID.
    :param bool include_versions: if True, the table will include the baseline
        and tool version numbers.

    :return: HTML table.
    :rtype: str
    """

    now = datetime.now()

    # The timezone name (or abbreviation) depends on whether Daylight Savings
    # is in effect.

    tz_index = 1 if time.localtime().tm_isdst > 0 else 0

    date = now.strftime('%m/%d/%Y %H:%M:%S') + f' {time.tzname[tz_index]}'

    data = [('Customer Name', name),
            ('Customer Domain', domain),
            ('Customer ID', ident),
            ('Report Date', date)]

    if include_versions:
        data += [('Baseline Version', Version.major),
                 ('Tool Version', Version.current)]

    meta = ('<table class = "meta-table">\n'
            + '  <tr>\n'
            + '\n'.join(f'    <th>{h}</th>' for h, _ in data)
            + '\n  </tr>\n  <tr>\n'
            + '\n'.join(f'    <td>{d}</td>' for _, d in data)
            + '\n  </tr>\n</table>\n')

    return meta


def _build_rules_table(rules: dict) -> str:

    """Given the rules dictionary from the Rego evaluation, an HTML
    table is created which lists each system defined rule and whether
    the rule is enabled.

    :param dict rules: dictionary with keys 'enabled_rules' and
        'disabled_rules'.  The values for each are lists of rule
        display names.

    :return: HTML table with system-defined rules.
    :rtype: str
    """

    if not rules:
        return ''

    # To create the table, we use the enabled rules returned from the
    # Rego run.  The table is populated with all rules listed in the
    # complete definition (SYSTEM_RULES), with the status determined using
    # the set of enabled rules.  The disabled rules table is not needed.

    enabled_rules = frozenset(rules['enabled_rules'])

    rules_table = [{'Alert Name': name,
                    'Description': description,
                    'Status': ('Enabled' if name in enabled_rules
                               else 'Disabled')}
                   for name, description in SYSTEM_RULES.items()]

    html_table = ('\n<hr>\n<h2 id="alerts">System Defined Alerts</h2>\n'
                  + create_html_table(rules_table, _alerts_status_class)) + '\n'

    return html_table


def _alerts_status_class(rules_row: dict) -> str:

    """Given the dictionary containing data from a row in the system alerts
    table, this method returns the CSS class associated with the row.  The
    class selected is based on the alert status.  This method is used as a
    callback for create_html_table().
    """

    css_class = 'unknown-alerts'

    match rules_row['Status'].lower():

        case 'disabled':

            css_class = 'disabled-alerts'

        case 'enabled':

            css_class = 'enabled-alerts'

    return css_class


def _indicator_text_color(bg_color: str) -> str:

    # Minimal heuristic preserved from original: light backgrounds use black text.
    if not bg_color:
        return 'white'
    return 'black' if bg_color.upper() in ['#F6E8E5', '#FFF7D6', '#5E9732'] else 'white'


def _normalize_indicator_link(link_url: str | None,
                              *,
                              product: str | None,
                              github_url: str) -> str | None:

    if not link_url:
        return None

    # Anchor links -> baseline doc anchor on GitHub
    if link_url.startswith('#') and product:
        baseline_file = f'{product}.md'
        return (
            f'{github_url}/blob/{Version.current}/scubagoggles/baselines/'
            f'{baseline_file}{link_url}')

    # ../ relative paths -> GitHub blob path
    if link_url.startswith('../'):
        path = link_url.replace('../', '')
        return f'{github_url}/blob/{Version.current}/{path}'

    return link_url


def render_indicator_badge(indicator: dict, *, product: str | None = None,
                           github_url: str = GITHUB_URL) -> str:

    """Render an HTML badge element for a policy indicator, optionally
    linking to a product-specific or GitHub URL.
    """

    indicator_name = indicator.get('name', '')
    if not indicator_name:
        return ''

    definition = INDICATOR_DEFINITIONS.get(indicator_name, {})
    color = indicator.get('color') or definition.get('color', '#6C757D')
    description = definition.get('description', indicator_name)

    text_color = _indicator_text_color(color)
    link_url = _normalize_indicator_link(
        indicator.get('link'), product=product, github_url=github_url)

    badge_style = f'background-color: {color}; color: {text_color};'

    if link_url and 'shields.io' not in link_url:
        return (
            f'<a href="{link_url}" target="_blank" class="indicator-badge" '
            f'style="{badge_style}" title="{description}">{indicator_name}</a>'
        )

    return (f'<span class="indicator-badge" style="{badge_style}" '
            f'title="{description}">{indicator_name}</span>'
    )


def render_indicators(indicators: list,
                      *,
                      product: str | None = None,
                      github_url: str = GITHUB_URL) -> str:

    """Render a list of indicators as HTML badges wrapped in a container div.
    """

    if not indicators:
        return ''
    badges = [render_indicator_badge(ind, product=product,
                                     github_url=github_url) for ind in indicators]
    badges = [b for b in badges if b]
    if not badges:
        return ''
    return '<div class="badges">\n' + '\n'.join(badges) + '</div>\n'

def _collect_all_indicators(product_policies: list) -> dict:

    """Build a mapping of unique indicator names to their color and description
    from the given product_policies structure.
    """

    all_indicators = {}
    for baseline_group in product_policies or []:
        for control in baseline_group.get('Controls', []):
            for indicator in control.get('Indicators', []) or []:
                name = indicator.get('name', '')
                if not name:
                    continue
                if name in all_indicators:
                    continue
                definition = INDICATOR_DEFINITIONS.get(name, {})
                all_indicators[name] = {
                    'color': indicator.get('color') or definition.get('color', '#6C757D'),
                    'description': definition.get('description', name),
                }
    return all_indicators

def build_indicator_legend(product_policies: list,
                           *,
                           product: str | None = None,
                           github_url: str = GITHUB_URL) -> str:

    """Build an HTML legend for all unique policy indicators found in
    product_policies.
    """

    all_indicators = _collect_all_indicators(product_policies)
    if not all_indicators:
        return ''

    legend_html = ('<div id="indicator-legend">\n'
        '  <div id="indicator-legend-label">Policy Indicators:</div>\n'
        '  <ul id="indicator-legend-list">\n')

    for name in sorted(all_indicators.keys()):
        info = all_indicators[name]
        indicator_dict = {'name': name, 'color': info['color']}

        # Same behavior as original: some legend items link to key terminology
        if name in ['Automated Check', 'Manual', 'Configurable']:
            indicator_dict['link'] = '#key-terminology'

        badge = render_indicator_badge(indicator_dict, product=product, github_url=github_url)
        legend_html += ('    <li class="indicator-legend-item">'
            f'{badge}'
            f'<span style="color: var(--text-color);">{info["description"]}</span>'
            '</li>\n')

    legend_html += '</ul>\n</div>\n'
    return legend_html
