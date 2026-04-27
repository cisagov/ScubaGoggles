import io
import time
from datetime import datetime
from pathlib import Path

from scubagoggles.parsers.system_rules_parser import SYSTEM_RULES
from scubagoggles.version import Version

INDICATOR_DEFINITIONS = {
    "Automated Check": {
        "color": "#5E9732",
        "text_color": "black",
        "description": "Automatically verified by ScubaGoggles",
    },
    "Log-Based Check": {
        "color": "#F6E8E5",
        "text_color": "black",
        "description": "Requires log-based verification",
    },
    "Manual": {
        "color": "#046B9A",
        "text_color": "white",
        "description": "Requires manual verification",
    },
    "Configurable": {
        "color": "#005288",
        "text_color": "white",
        "description": "Customizable via config file",
    },
    "BOD 25-01 Requirement": {
        "color": "#DC3545",
        "text_color": "white",
        "description": "Required by CISA BOD 25-01",
    },
    "Requires Configuration": {
        "color": "#DC3545",
        "text_color": "white",
        "description": "Config file required for check",
    },
}

GITHUB_URL = "https://github.com/cisagov/scubagoggles"
LIMITATIONS_URL = f"{GITHUB_URL}/blob/main/docs/usage/Limitations.md"

WARNING_ICON = (
    '<object data="./images/triangle-exclamation-solid.svg" '
    'alt="Warning icon." title="Warning" width="13" height="13"></object>'
)



REPORTER_PATH = Path(__file__).parent


def _inject_meta_tag(html: str) -> str:
    # If a template doesn't contain the placeholder, do nothing.
    if "{{META_TAG}}" not in html:
        return html

    meta_tag_template = REPORTER_PATH / "templates/MetaTagTemplate.html"
    meta_tag = meta_tag_template.read_text(encoding="utf-8")
    return html.replace("{{META_TAG}}", meta_tag)

def create_html_table(table_data: list) -> str:
    table_html = ""
    if not table_data:
        return table_html

    headings = table_data[0].keys()
    with io.StringIO() as outstream:
        outstream.write("<table>\n")
        outstream.write("  <thead>\n")
        outstream.write("    <tr>\n")
        for heading in headings:
            outstream.write(f"      <th>{heading}</th>\n")
        outstream.write("    </tr>\n")
        outstream.write("  </thead>\n")

        outstream.write("  <tbody>\n")
        for record in table_data:
            outstream.write("    <tr>\n")
            for heading in headings:
                outstream.write(f"      <td>{record[heading]}</td>\n")
            outstream.write("    </tr>\n")
        outstream.write("  </tbody>\n")
        outstream.write("</table>")
        table_html = outstream.getvalue()

    return table_html


def build_front_page_html(fragments: list, tenant_info: dict, report_uuid: str, darkmode: str, redaction: str) -> str:
    template_file = REPORTER_PATH / "FrontPageReport/FrontPageReportTemplate.html"
    html = template_file.read_text(encoding="utf-8")

    table = "".join(fragments)
    html = _inject_meta_tag(html)

    main_css_file = REPORTER_PATH / "styles/main.css"
    main_js_file = REPORTER_PATH / "scripts/main.js"
    html = html.replace("{{MAIN_CSS}}", f"<style>{main_css_file.read_text(encoding='utf-8')}</style>")
    html = html.replace("{{MAIN_JS}}", f"<script>{main_js_file.read_text(encoding='utf-8')}</script>")

    dark_toggle = (REPORTER_PATH / "templates/DarkModeToggleTemplate.html").read_text(encoding="utf-8")
    html = html.replace("{{DARK_MODE_TOGGLE}}", dark_toggle)
    html = html.replace(
    "{{SGR_SETTINGS}}",
    f'<span id="sgr_settings" data-darkmode="{darkmode}" data-redaction="{redaction}"></span>',
)
    front_css_file = REPORTER_PATH / "styles/FrontPageStyle.css"
    html = html.replace("{{FRONT_CSS}}", f"<style>{front_css_file.read_text(encoding='utf-8')}</style>")

    html = html.replace("{{report_uuid}}", report_uuid)
    html = html.replace("{{TABLE}}", table)

    now = datetime.now()
    report_date = now.strftime("%m/%d/%Y %H:%M:%S") + " " + time.tzname[time.daylight]
    meta = (
        '<table style = "text-align:center;">'
        "<tr><th>Customer Name</th><th>Customer Domain</th><th>Customer ID</th><th>Report Date</th></tr>"
        f'<tr><td>{tenant_info["topLevelOU"]}</td><td>{tenant_info["domain"]}</td>'
        f'<td>{tenant_info["ID"]}</td><td>{report_date}</td></tr></table>'
    )
    html = html.replace("{{TENANT_DETAILS}}", meta)
    html = html.replace("{{VERSION}}", Version.current)

    return html


def sanitize_details(table_data: list) -> list:
    for result in table_data:
        details = result["Details"]

        dns_link = '<a href="#dns-logs">View DNS logs</a> for more details.'
        details = details.replace(dns_link, "")
        details = convert_html_lists_to_plaintext(details)
        result["Details"] = details

        if "OriginalDetails" in result:
            orig = result["OriginalDetails"]

            orig = orig.replace(dns_link, "")
            orig = convert_html_lists_to_plaintext(orig)
            result["OriginalDetails"] = orig
    return table_data


def convert_html_lists_to_plaintext(text: str) -> str:
    if not isinstance(text, str):
        return text
    text = text.replace("<ul>", " ")
    text = text.replace("</ul>", "")
    text = text.replace("<li>", "\n- ")
    text = text.replace("</li>", " ")
    return text.strip()


def insert_classroom_warning(html: str, full_name: str) -> str:
    classroom_note = (
        "<h4>Note: Google Classroom is not available by default in GWS but as an additional "
        "Google Service.</h4>"
    )
    assuredcontrols_note = ('<h4>Note: Assured Controls and Assured '
                                'Controls Plus are paid add-ons with Google '
                                'Workspace. This baseline is intended as '
                                'guidance for agencies that already have '
                                'these add-ons. Users that choose to implement '
                                'this baseline should carefully consider the '
                                'tradeoffs involved, including the potential '
                                'security benefits, usability impacts, and '
                                'increased licensing fees for the add-on '
                                'licenses.</h4>')
    if full_name == 'Google Classroom':
            html = html.replace('{{WARNING_NOTIFICATION}}',
                                classroom_note)
    elif full_name == 'Assured Controls':
            html = html.replace('{{WARNING_NOTIFICATION}}',
                                assuredcontrols_note)
    else:
            html = html.replace('{{WARNING_NOTIFICATION}}', '')
    return html


def build_individual_report_html(
    *,
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
) -> tuple[str, list | None]:

    template_file = REPORTER_PATH / "IndividualReport/IndividualReportTemplate.html"
    html = template_file.read_text(encoding="utf-8")
    html = _inject_meta_tag(html)

    main_css_file = REPORTER_PATH / "styles/main.css"
    main_js_file = REPORTER_PATH / "scripts/main.js"
    html = html.replace("{{MAIN_CSS}}", f"<style>{main_css_file.read_text(encoding='utf-8')}</style>")
    html = html.replace("{{MAIN_JS}}", f"<script>{main_js_file.read_text(encoding='utf-8')}</script>")

    html = html.replace("{{TITLE}}", full_name + " Baseline Report")

    dark_toggle = (REPORTER_PATH / "templates/DarkModeToggleTemplate.html").read_text(encoding="utf-8")
    html = html.replace("{{DARK_MODE_TOGGLE}}", dark_toggle)
    html = html.replace(
    "{{SGR_SETTINGS}}",
    f'<span id="sgr_settings" data-darkmode="{darkmode}" data-redaction="{redaction}"></span>',
)
    html = insert_classroom_warning(html, full_name)

    html = html.replace("{{HOMELINK}}", f"../{main_report_name}.html")

    now = datetime.now()
    baseline_version = f"{Version.major}.{Version.minor}" if Version.major == 0 else Version.major
    report_date = now.strftime("%m/%d/%Y %H:%M:%S") + " " + time.tzname[time.daylight]
    meta = (
        '<table style = "text-align:center;">'
        "<tr><th>Customer Name</th><th>Customer Domain</th><th>Customer ID</th><th>Report Date</th>"
        "<th>Baseline Version</th><th>Tool Version</th></tr>"
        f"<tr><td>{tenant_name}</td><td>{tenant_domain}</td><td>{tenant_id}</td><td>{report_date}</td>"
        f"<td>{baseline_version}</td><td>{Version.current}</td></tr></table>"
    )
    html = html.replace("{{METADATA}}", meta)
    html = html.replace("{{TABLES}}", "".join(fragments))

    rules_table = _build_rules_table(rules_data)
    html = html.replace('{{RULES}}', rules_table)

    if full_name != "Gmail":
        html = html.replace("{{DNS_LOGS}}", "")
        return html, rules_table

    # DNS logs block (same logic you already have)
    log_html = '<hr><h2 id="dns-logs">DNS Logs</h2>'
    log_html += (
        "<p>DNS queries ScubaGear made while identifying SPF, DKIM, and DMARC records. "
        "Note: if DNS queries unexepectedly return 0 txt records, it may be a sign the system-defualt "
        "resolver is unable to resolve the domain names (e.g., due to a split horizon setup).</p>"
    )
    for log_type in dns_logs:
        log_html += "<div class='dns-logs'>"
        log_html += f"<h3>{log_type.upper()}</h3>"
        logs = []
        for domain in dns_logs[log_type]:
            for query in domain["log"]:
                qname = "&#8203;".join(query["query_name"])
                answers = ["&#8203;".join(answer) for answer in query["query_answers"]]
                logs.append(
                    {
                        "Query Name": qname,
                        "Query Method": query["query_method"],
                        "Summary": query["query_result"],
                        "Answers": '<br>'.join(answers),
                    }
                )
        log_table = create_html_table(logs).replace("<table>", "<table class='alternating dns-table'>")
        log_html += log_table
        log_html += "</div>"

    html = html.replace("{{DNS_LOGS}}", log_html)
    return html, rules_table


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
                  + create_html_table(rules_table)) + '\n'

    return html_table


def _indicator_text_color(bg_color: str) -> str:
    # Minimal heuristic preserved from original: light backgrounds use black text.
    if not bg_color:
        return "white"
    return "black" if bg_color.upper() in ["#F6E8E5", "#FFF7D6", "#5E9732"] else "white"


def _normalize_indicator_link(link_url: str | None, *, product: str | None, github_url: str) -> str | None:
    if not link_url:
        return None

    # Anchor links -> baseline doc anchor on GitHub
    if link_url.startswith("#") and product:
        baseline_file = f"{product}.md"
        return f"{github_url}/blob/{Version.current}/scubagoggles/baselines/{baseline_file}{link_url}"

    # ../ relative paths -> GitHub blob path
    if link_url.startswith("../"):
        path = link_url.replace("../", "")
        return f"{github_url}/blob/{Version.current}/{path}"

    return link_url


def render_indicator_badge(indicator: dict, *, product: str | None = None, github_url: str = GITHUB_URL) -> str:
    indicator_name = indicator.get("name", "")
    if not indicator_name:
        return ""

    definition = INDICATOR_DEFINITIONS.get(indicator_name, {})
    color = indicator.get("color") or definition.get("color", "#6C757D")
    description = definition.get("description", indicator_name)

    text_color = _indicator_text_color(color)
    link_url = _normalize_indicator_link(indicator.get("link"), product=product, github_url=github_url)

    badge_style = (
        f"background-color: {color}; color: {text_color}; "
        "padding: 2px 8px; border-radius: 3px; "
        "font-size: 0.85em; margin-right: 5px; "
        "display: inline-block; white-space: nowrap; "
        "font-weight: 500;"
    )

    if link_url:
        badge_style += " text-decoration: none;"
        return (
            f'<a href="{link_url}" target="_blank" class="indicator-badge" '
            f'style="{badge_style}" title="{description}">{indicator_name}</a>'
        )

    return f'<span class="indicator-badge" style="{badge_style}" title="{description}">{indicator_name}</span>'


def render_indicators(indicators: list, *, product: str | None = None, github_url: str = GITHUB_URL) -> str:
    if not indicators:
        return ""
    badges = [render_indicator_badge(ind, product=product, github_url=github_url) for ind in indicators]
    badges = [b for b in badges if b]
    if not badges:
        return ""
    return '<div style="margin-top: 5px;">' + "".join(badges) + "</div>"

def _collect_all_indicators(product_policies: list) -> dict:
    all_indicators = {}
    for baseline_group in product_policies or []:
        for control in baseline_group.get("Controls", []):
            for indicator in control.get("Indicators", []) or []:
                name = indicator.get("name", "")
                if not name:
                    continue
                if name in all_indicators:
                    continue
                definition = INDICATOR_DEFINITIONS.get(name, {})
                all_indicators[name] = {
                    "color": indicator.get("color") or definition.get("color", "#6C757D"),
                    "description": definition.get("description", name),
                }
    return all_indicators


def build_indicator_legend(product_policies: list, *, product: str | None = None, github_url: str = GITHUB_URL) -> str:
    all_indicators = _collect_all_indicators(product_policies)
    if not all_indicators:
        return ""

    legend_html = (
        '<div class="indicator-legend" style="margin: 20px 0; margin-left: 50px; font-size: 0.9em;">'
        '<h3 style="margin: 0 0 10px 0; color: var(--header-color); font-weight: bold; '
        'font-size: 0.95em; text-align: left;">Policy Indicators:</h3>'
        '<ul style="list-style: none; padding-left: 0; margin: 0;">'
    )

    for name in sorted(all_indicators.keys()):
        info = all_indicators[name]
        indicator_dict = {"name": name, "color": info["color"]}

        # Same behavior as original: some legend items link to key terminology
        if name in ["Automated Check", "Manual", "Configurable"]:
            indicator_dict["link"] = "#key-terminology"

        badge = render_indicator_badge(indicator_dict, product=product, github_url=github_url)
        legend_html += (
            '<li style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px; font-size: 0.85em;">'
            f"{badge}"
            f'<span style="color: var(--text-color);">{info["description"]}</span>'
            "</li>"
        )

    legend_html += "</ul></div>"
    return legend_html