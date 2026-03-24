import io
import json
import time
from datetime import datetime
from pathlib import Path

from scubagoggles.version import Version

GITHUB_URL = "https://github.com/cisagov/scubagoggles"
LIMITATIONS_URL = f"{GITHUB_URL}/blob/main/docs/usage/Limitations.md"

WARNING_ICON = (
    '<object data="./images/triangle-exclamation-solid.svg" '
    'alt="Warning icon." title="Warning" width="13" height="13"></object>'
)

LOG_BASED_WARNING = (
    f'<span style="display: block;">{WARNING_ICON}&nbsp;'
    f'Log-based check. See <a href="{LIMITATIONS_URL}">limitations</a>.</span>'
)

LOG_BASED_WARNING_PLAINTEXT = (
    "Warning: log-based check. See documentation in ScubaGoggles GitHub repository "
    "for limitations."
)

REPORTER_PATH = Path(__file__).parent


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


def build_front_page_html(fragments: list, tenant_info: dict, report_uuid: str, darkmode: str) -> str:
    template_file = REPORTER_PATH / "FrontPageReport/FrontPageReportTemplate.html"
    html = template_file.read_text(encoding="utf-8")

    table = "".join(fragments)

    main_css_file = REPORTER_PATH / "styles/main.css"
    main_js_file = REPORTER_PATH / "scripts/main.js"
    html = html.replace("{{MAIN_CSS}}", f"<style>{main_css_file.read_text(encoding='utf-8')}</style>")
    html = html.replace("{{MAIN_JS}}", f"<script>{main_js_file.read_text(encoding='utf-8')}</script>")

    dark_toggle = (REPORTER_PATH / "templates/DarkModeToggleTemplate.html").read_text(encoding="utf-8")
    html = html.replace("{{DARK_MODE_TOGGLE}}", dark_toggle)
    html = html.replace("{{SGR_SETTINGS}}", f'<span id="sgr_settings" data-darkmode="{darkmode}"></span>')

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
        details = details.replace(LOG_BASED_WARNING, LOG_BASED_WARNING_PLAINTEXT)
        details = details.replace("<br>", "\n")

        dns_link = '<a href="#dns-logs">View DNS logs</a> for more details.'
        details = details.replace(dns_link, "")
        details = convert_html_lists_to_plaintext(details)
        result["Details"] = details

        if "OriginalDetails" in result:
            orig = result["OriginalDetails"]
            orig = orig.replace(LOG_BASED_WARNING, LOG_BASED_WARNING_PLAINTEXT)
            orig = orig.replace("<br>", "\n")
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
    return html.replace("{{WARNING_NOTIFICATION}}", classroom_note if full_name == "Google Classroom" else "")


def build_individual_report_html(
    *,
    fragments: list,
    rules_data: dict | None,
    darkmode: str,
    dns_logs: dict,
    full_name: str,
    main_report_name: str,
    tenant_name: str,
    tenant_domain: str,
    tenant_id: str,
) -> tuple[str, list | None]:
    template_file = REPORTER_PATH / "IndividualReport/IndividualReportTemplate.html"
    html = template_file.read_text(encoding="utf-8")

    main_css_file = REPORTER_PATH / "styles/main.css"
    main_js_file = REPORTER_PATH / "scripts/main.js"
    html = html.replace("{{MAIN_CSS}}", f"<style>{main_css_file.read_text(encoding='utf-8')}</style>")
    html = html.replace("{{MAIN_JS}}", f"<script>{main_js_file.read_text(encoding='utf-8')}</script>")

    html = html.replace("{{TITLE}}", full_name + " Baseline Report")

    dark_toggle = (REPORTER_PATH / "templates/DarkModeToggleTemplate.html").read_text(encoding="utf-8")
    html = html.replace("{{DARK_MODE_TOGGLE}}", dark_toggle)
    html = html.replace("{{SGR_SETTINGS}}", f'<span id="sgr_settings" data-darkmode="{darkmode}"></span>')

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

    rules_table = None
    if rules_data:
        alert_descriptions = json.loads((REPORTER_PATH / "IndividualReport/AlertsDescriptions.json").read_text())
        rules_html = "<hr><h2 id=\"alerts\">System Defined Alerts</h2>"
        rules_html += (
            "<p>Note: As ScubaGoggles currently relies on admin log events to determine alert status, "
            "ScubaGoggles will not be able to determine the current status of any alerts whose state has "
            "not changed recently.</p>"
        )
        rules_table = []
        for rule in rules_data["enabled_rules"]:
            rules_table.append({"Alert Name": rule, "Description": alert_descriptions[rule], "Status": "Enabled"})
        for rule in rules_data["disabled_rules"]:
            rules_table.append({"Alert Name": rule, "Description": alert_descriptions[rule], "Status": "Disabled"})
        for rule in rules_data["unknown"]:
            rules_table.append({"Alert Name": rule, "Description": alert_descriptions[rule], "Status": "Unknown"})
        rules_table.sort(key=lambda r: r["Alert Name"])
        rules_html += create_html_table(rules_table)
        html = html.replace("{{RULES}}", rules_html)
    else:
        html = html.replace("{{RULES}}", "")

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
