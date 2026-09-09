"""Compare two saved ScubaGoggles reports."""
from __future__ import annotations

import csv
import html
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "0.1"
VERSION_RE = re.compile(r"^(?P<base>.+?)(?:v(?P<version>\d+))$", re.IGNORECASE)

CLASSIFICATIONS = (
    "NewPolicy", "RemovedPolicy", "Errored", "PolicyVersionUpdate", "Unchanged",
    "NewIncorrectResult", "NewPass", "NewFail", "NewWarning", "NewAutomatedCheck",
    "NewManualCheck", "NewOmission", "Other",
)
AUTOMATED_STATES = {"Pass", "Fail", "Warning"}
MANUAL_STATES = {"N/A", "No events found", "Omitted"}


@dataclass(frozen=True)
class Control:
    product: str
    group_name: str
    group_number: str
    control_id: str
    result: str
    criticality: str
    requirement: str
    details: str
    comments: tuple[str, ...]
    resolution_date: str | None
    original_result: str


def load_report(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to read ScubaGoggles report '{path}': {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("Results"), dict):
        raise ValueError(f"'{path}' is not a supported ScubaGoggles report: missing Results object")
    return data


def split_version(control_id: str) -> tuple[str, int | None]:
    match = VERSION_RE.match(control_id)
    if not match:
        return control_id, None
    return match.group("base"), int(match.group("version"))


def _parse_control(product: str, group: dict[str, Any], raw: dict[str, Any]) -> Control | None:
    control_id = str(raw.get("Control ID", "")).strip()
    if not control_id:
        return None
    comments = raw.get("Comments") or []
    if not isinstance(comments, list):
        comments = [comments]
    return Control(
        product=product,
        group_name=str(group.get("GroupName", "")),
        group_number=str(group.get("GroupNumber", "")),
        control_id=control_id,
        result=str(raw.get("Result", "")),
        criticality=str(raw.get("Criticality", "")),
        requirement=str(raw.get("Requirement", "")),
        details=str(raw.get("Details", "")),
        comments=tuple(str(value) for value in comments),
        resolution_date=raw.get("ResolutionDate"),
        original_result=str(raw.get("OriginalResult", raw.get("Result", ""))),
    )


def collect_controls(report: dict[str, Any]) -> dict[str, Control]:
    controls: dict[str, Control] = {}
    for product, groups in report["Results"].items():
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            for raw in group.get("Controls", []) or []:
                if not isinstance(raw, dict):
                    continue
                control = _parse_control(str(product), group, raw)
                if control is None:
                    continue
                base_id = split_version(control.control_id)[0].lower()
                key = f"{control.product.lower()}:{base_id}"
                if key in controls:
                    raise ValueError(f"Duplicate control ID in report: {control.control_id}")
                controls[key] = control
    return controls


def _is_error(result: str) -> bool:
    return result == "Error" or result.startswith("Error")


def result_diff(before: str, after: str) -> str:
    """Classify the change between two control results."""

    before = before.strip()
    after = after.strip()

    # No change.
    if before == after:
        return "Unchanged"

    # The current assessment errored. This takes precedence over the
    # previous result.
    if after == "Error":
        return "Errored"

    # An errored control recovered.
    if before == "Error":
        return {
            "Pass": "NewPass",
            "Fail": "NewFail",
            "Warning": "NewWarning",
            "N/A": "NewManualCheck",
            "Omitted": "NewOmission",
        }.get(after, "Other")

    # A control changed from manual/unassessed to an automated result.
    # This must occur before the generic Pass/Fail/Warning cases.
    if before == "N/A" and after in {"Pass", "Fail", "Warning"}:
        return "NewAutomatedCheck"

    # New omission.
    if after == "Omitted":
        return "NewOmission"

    # An omitted control is now being assessed again.
    if before == "Omitted":
        return {
            "Pass": "NewPass",
            "Fail": "NewFail",
            "Warning": "NewWarning",
            "N/A": "NewManualCheck",
        }.get(after, "Other")

    # Normal result transitions.
    result_changes = {
        "Pass": {
            "Fail": "NewFail",
            "Warning": "NewWarning",
            "N/A": "NewManualCheck",
        },
        "Fail": {
            "Pass": "NewPass",
            "Warning": "NewWarning",
            "N/A": "NewManualCheck",
        },
        "Warning": {
            "Pass": "NewPass",
            "Fail": "NewFail",
            "N/A": "NewManualCheck",
        },
    }

    return result_changes.get(before, {}).get(after, "Other")


def classify_pair(before: Control | None, after: Control | None) -> str:
    if before is None:
        return "NewPolicy"
    if after is None:
        return "RemovedPolicy"
    before_base, before_version = split_version(before.control_id)
    after_base, after_version = split_version(after.control_id)
    if before_base.lower() != after_base.lower():
        return "Other"
    if before_version is not None and after_version is not None and before_version != after_version:
        return "PolicyVersionUpdate"
    return result_diff(before.result, after.result)


def make_record(before: Control | None, after: Control | None) -> dict[str, Any]:
    classification = classify_pair(before, after)
    current = after or before
    assert current is not None
    return {
        "Product": current.product,
        "Control ID (Before)": before.control_id if before else None,
        "Control ID (After)": after.control_id if after else None,
        "GroupNumber": after.group_number if after else (before.group_number if before else None),
        "GroupName": after.group_name if after else (before.group_name if before else None),
        "Classification": classification,
        "ResultBefore": before.result if before else None,
        "ResultAfter": after.result if after else None,
        "CriticalityBefore": before.criticality if before else None,
        "CriticalityAfter": after.criticality if after else None,
        "Requirement": _strip_html(after.requirement if after else before.requirement if before else ""),
        "DetailsAfter": after.details if after else None,
        "AnnotationChanged": bool(
            before and after and (
                before.comments != after.comments or before.resolution_date != after.resolution_date
            )
        ),
        "Comments": list(after.comments) if after else [],
        "ResolutionDate": after.resolution_date if after else None,
        "UnderlyingResultBefore": before.original_result if before else None,
        "UnderlyingResultAfter": after.original_result if after else None,
    }


def _strip_html(value: str) -> str:
    value = re.sub(r"<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", html.unescape(value)).strip()


def compare(before_report: dict[str, Any], after_report: dict[str, Any]) -> dict[str, Any]:
    before = collect_controls(before_report)
    after = collect_controls(after_report)
    records = [make_record(before.get(key), after.get(key)) for key in sorted(set(before) | set(after))]
    records.sort(key=lambda record: (
        str(record["Product"]).lower(),
        str(record["GroupNumber"]),
        str(record["Control ID (After)"] or record["Control ID (Before)"]).lower(),
    ))
    summary: dict[str, dict[str, int]] = defaultdict(lambda: {name: 0 for name in CLASSIFICATIONS})
    for record in records:
        summary[str(record["Product"])][record["Classification"]] += 1
    return {
        "SchemaVersion": SCHEMA_VERSION,
        "Tool": "ScubaGogglesDiff",
        "Before": before_report.get("MetaData", {}),
        "After": after_report.get("MetaData", {}),
        "Summary": dict(summary),
        "Records": records,
    }


def write_json(result: dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_csv(result: dict[str, Any], path: Path) -> None:
    fieldnames = [
        "Product", "Control ID (Before)", "Control ID (After)", "GroupNumber", "GroupName",
        "Classification", "ResultBefore", "ResultAfter", "CriticalityBefore", "CriticalityAfter",
        "Requirement", "DetailsAfter", "AnnotationChanged", "Comments", "ResolutionDate",
        "UnderlyingResultBefore", "UnderlyingResultAfter",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in result["Records"]:
            row = dict(row)
            row["Comments"] = " | ".join(row["Comments"])
            writer.writerow(row)


def write_html(result: dict[str, Any], path: Path) -> None:
    def css_for(classification: str) -> str:
        if classification in {"NewFail", "Errored", "NewIncorrectResult"}:
            return "bad"
        if classification in {"NewPass", "NewAutomatedCheck"}:
            return "good"
        if classification == "NewWarning":
            return "warn"
        if classification == "Unchanged":
            return "unchanged"
        return "neutral"

    products = sorted(result["Summary"], key=str.lower)
    filters = "".join(
        f'<label><input type="checkbox" data-filter="{html.escape(item)}" checked> {html.escape(item)}</label>'
        for item in CLASSIFICATIONS
    )
    summary_rows = "".join(
        "<tr>"
        + f"<td>{html.escape(product)}</td>"
        + "".join(f"<td>{result['Summary'][product].get(item, 0)}</td>" for item in CLASSIFICATIONS)
        + "</tr>"
        for product in products
    )
    record_rows = []
    for record in result["Records"]:
        classification = str(record["Classification"])
        control = record["Control ID (After)"] or record["Control ID (Before)"]
        record_rows.append(
            f'<tr class="{css_for(classification)}" data-classification="{html.escape(classification)}">'
            f'<td>{html.escape(str(record["Product"]))}</td>'
            f'<td>{html.escape(str(record["GroupNumber"] or ""))} {html.escape(str(record["GroupName"] or ""))}</td>'
            f'<td><code>{html.escape(str(control))}</code></td>'
            f'<td>{html.escape(str(record["ResultBefore"] or ""))}</td>'
            f'<td>{html.escape(str(record["ResultAfter"] or ""))}</td>'
            f'<td>{html.escape(classification)}</td>'
            f'<td>{html.escape(str(record["DetailsAfter"] or ""))}</td></tr>'
        )
    document = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ScubaGoggles Report Diff</title><style>
body{{font-family:system-ui,sans-serif;margin:2rem;background:#fafafa;color:#222}}table{{border-collapse:collapse;width:100%;background:#fff}}th,td{{padding:.5rem;border:1px solid #ddd;text-align:left;vertical-align:top}}th{{background:#eee}}.controls{{padding:1rem;background:#fff;border:1px solid #ddd;margin:1rem 0;display:flex;gap:1rem;flex-wrap:wrap}}.bad{{background:#ffe6e6}}.good{{background:#e7f6e7}}.warn{{background:#fff4d6}}.unchanged{{color:#888}}.neutral{{background:#f1f1f1}}code{{white-space:nowrap}}.summary{{overflow:auto;margin-bottom:2rem}}
</style></head><body><h1>ScubaGoggles Report Diff</h1><div class="controls"><strong>Filter:</strong>{filters}<label><input id="showUnchanged" type="checkbox" checked> Show unchanged</label></div>
<h2>Summary</h2><div class="summary"><table><thead><tr><th>Product</th>{''.join(f'<th>{html.escape(c)}</th>' for c in CLASSIFICATIONS)}</tr></thead><tbody>{summary_rows}</tbody></table></div>
<h2>Controls</h2><table><thead><tr><th>Product</th><th>Group</th><th>Control</th><th>Before</th><th>After</th><th>Classification</th><th>Details</th></tr></thead><tbody id="records">{''.join(record_rows)}</tbody></table>
<script>const checks=[...document.querySelectorAll('[data-filter]')];const unchanged=document.getElementById('showUnchanged');function refresh(){{const active=new Set(checks.filter(x=>x.checked).map(x=>x.dataset.filter));document.querySelectorAll('#records tr').forEach(r=>{{const c=r.dataset.classification;r.style.display=(active.has(c)&&(unchanged.checked||c!=='Unchanged'))?'':'none';}})}}checks.forEach(x=>x.addEventListener('change',refresh));unchanged.addEventListener('change',refresh);refresh();</script></body></html>"""
    path.write_text(document, encoding="utf-8")


def run_diff(before: Path, after: Path, outputpath: Path, outjsonfilename: str, quiet: bool = False) -> None:
    result = compare(load_report(before), load_report(after))
    outputpath.mkdir(parents=True, exist_ok=True)
    json_path = outputpath / outjsonfilename
    html_path = outputpath / "DiffReport.html"
    csv_path = outputpath / "DiffResults.csv"
    write_json(result, json_path)
    write_html(result, html_path)
    write_csv(result, csv_path)
    if not quiet:
        print(f"Diff JSON: {json_path}")
        print(f"Diff HTML: {html_path}")
        print(f"Diff CSV:  {csv_path}")
