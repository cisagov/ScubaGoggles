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
    "NewPolicy",
    "RemovedPolicy",
    "Errored",
    "PolicyVersionUpdate",
    "Unchanged",
    "NewIncorrectResult",
    "NewPass",
    "NewFail",
    "NewWarning",
    "NewAutomatedCheck",
    "NewManualCheck",
    "NewOmission",
    "Other",
)
AUTOMATED_STATES = frozenset({"Pass", "Fail", "Warning"})
MANUAL_STATES = frozenset({"N/A", "No events found", "Omitted"})
AUTOMATED_TRANSITIONS = {
    "Pass": "NewPass",
    "Fail": "NewFail",
    "Warning": "NewWarning",
}


@dataclass(frozen=True)
class Control:
    """Normalized ScubaGoggles control data."""

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
    """Load and validate a ScubaGoggles report."""
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        message = f"Unable to read ScubaGoggles report '{path}': {exc}"
        raise ValueError(message) from exc
    if not isinstance(data, dict) or not isinstance(data.get("Results"), dict):
        message = f"'{path}' is not a supported ScubaGoggles report: missing Results object"
        raise ValueError(message)
    return data


def split_version(control_id: str) -> tuple[str, int | None]:
    """Return the base control ID and optional version number."""
    match = VERSION_RE.match(control_id)
    if not match:
        return control_id, None
    return match.group("base"), int(match.group("version"))


def normalize_control(
    product: str,
    group: dict[str, Any],
    control_data: dict[str, Any],
) -> Control | None:
    """Normalize a ScubaGoggles report control into a Control.

    Args:
        product: Product name containing the control, such as "Gmail".
        group: Parent control group from the ScubaGoggles report.
        control_data: Control record from the group's `Controls` collection.

    Returns:
        A normalized Control, or None when the record does not contain
        a usable control ID.
    """
    control_id = str(control_data.get("Control ID", "")).strip()
    if not control_id:
        return None

    comments = control_data.get("Comments") or []
    if not isinstance(comments, list):
        comments = [comments]

    return Control(
        product=product,
        group_name=str(group.get("GroupName", "")),
        group_number=str(group.get("GroupNumber", "")),
        control_id=control_id,
        result=str(control_data.get("Result", "")),
        criticality=str(control_data.get("Criticality", "")),
        requirement=str(control_data.get("Requirement", "")),
        details=str(control_data.get("Details", "")),
        comments=tuple(str(value) for value in comments),
        resolution_date=control_data.get("ResolutionDate"),
        original_result=str(control_data.get("OriginalResult", control_data.get("Result", ""))),
    )


def collect_controls(report: dict[str, Any]) -> dict[str, Control]:
    """Collect normalized controls keyed by product and base control ID."""
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
                control = normalize_control(str(product), group, raw)
                if control is None:
                    continue
                base_id = split_version(control.control_id)[0].lower()
                key = f"{control.product.lower()}:{base_id}"
                if key in controls:
                    raise ValueError(
                        f"Duplicate control ID in report: {control.control_id}"
                    )
                controls[key] = control
    return controls


def _is_error(result: str) -> bool:
    """Return whether a result represents an error state."""
    return result == "Error" or result.startswith("Error")


def _manual_transition(before: str, after: str) -> str | None:
    """Classify transitions involving manual or omitted results."""
    # pylint: disable=too-many-return-statements
    if before == "N/A" and after in AUTOMATED_STATES:
        return "NewAutomatedCheck"
    if before in AUTOMATED_STATES and after == "N/A":
        return "NewManualCheck"
    if after == "Omitted" and before != "Omitted":
        return "NewOmission"
    if before == "Omitted" and after != "Omitted":
        if after == "N/A":
            return "NewManualCheck"
        return AUTOMATED_TRANSITIONS.get(after)
    if before in MANUAL_STATES and after in AUTOMATED_STATES:
        return AUTOMATED_TRANSITIONS.get(after)
    return None


def _error_transition(before: str, after: str) -> str | None:
    """Classify transitions to or from an error result."""
    if _is_error(after):
        return "Errored"
    if not _is_error(before):
        return None
    if after in AUTOMATED_STATES:
        return AUTOMATED_TRANSITIONS[after]
    if after == "N/A":
        return "NewManualCheck"
    if after == "Omitted":
        return "NewOmission"
    return "Other"


def _standard_transition(before: str, after: str) -> str:
    """Classify ordinary result transitions."""
    # pylint: disable=too-many-return-statements
    if after == "Incorrect result":
        return "NewIncorrectResult"
    if before == "Incorrect result":
        if after in AUTOMATED_STATES:
            return AUTOMATED_TRANSITIONS[after]
        if after == "N/A":
            return "NewManualCheck"
        if after == "Omitted":
            return "NewOmission"
        return "Other"
    if after in AUTOMATED_STATES:
        return AUTOMATED_TRANSITIONS[after]
    return "Other"


def result_diff(before: str, after: str) -> str:
    """Classify a change between two control results."""
    if before == after:
        return "Unchanged"

    error_result = _error_transition(before, after)
    if error_result is not None:
        return error_result

    manual_result = _manual_transition(before, after)
    if manual_result is not None:
        return manual_result

    return _standard_transition(before, after)


def classify_pair(before: Control | None, after: Control | None) -> str:
    """Classify a before/after control pair."""
    if before is None:
        return "NewPolicy"
    if after is None:
        return "RemovedPolicy"

    before_base, before_version = split_version(before.control_id)
    after_base, after_version = split_version(after.control_id)
    if before_base.lower() != after_base.lower():
        return "Other"
    if (
        before_version is not None
        and after_version is not None
        and before_version != after_version
    ):
        return "PolicyVersionUpdate"
    return result_diff(before.result, after.result)


def _strip_html(value: str) -> str:
    """Strip HTML tags and normalize whitespace."""
    value = re.sub(r"<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", html.unescape(value)).strip()


def make_record(before: Control | None, after: Control | None) -> dict[str, Any]:
    """Create one normalized diff record."""
    classification = classify_pair(before, after)
    current = after or before
    assert current is not None
    requirement = after.requirement if after else before.requirement if before else ""
    before_comments = before.comments if before else ()
    after_comments = after.comments if after else ()
    annotations_changed = bool(
        before
        and after
        and (before_comments != after_comments or before.resolution_date != after.resolution_date)
    )
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
        "Requirement": _strip_html(requirement),
        "DetailsAfter": after.details if after else None,
        "AnnotationChanged": annotations_changed,
        "Comments": list(after.comments) if after else [],
        "ResolutionDate": after.resolution_date if after else None,
        "UnderlyingResultBefore": before.original_result if before else None,
        "UnderlyingResultAfter": after.original_result if after else None,
    }


def _record_sort_key(record: dict[str, Any]) -> tuple[str, str, str]:
    """Return the stable sort key for a diff record."""
    control_id = record["Control ID (After)"] or record["Control ID (Before)"]
    return (
        str(record["Product"]).lower(),
        str(record["GroupNumber"]),
        str(control_id).lower(),
    )


def compare(before_report: dict[str, Any], after_report: dict[str, Any]) -> dict[str, Any]:
    """Compare two ScubaGoggles reports."""
    before = collect_controls(before_report)
    after = collect_controls(after_report)
    keys = sorted(set(before) | set(after))
    records = [make_record(before.get(key), after.get(key)) for key in keys]
    records.sort(key=_record_sort_key)

    summary: dict[str, dict[str, int]] = defaultdict(
        lambda: {name: 0 for name in CLASSIFICATIONS}
    )
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
    """Write a diff result as JSON."""
    path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def write_csv(result: dict[str, Any], path: Path) -> None:
    """Write a diff result as CSV."""
    fieldnames = [
        "Product",
        "Control ID (Before)",
        "Control ID (After)",
        "GroupNumber",
        "GroupName",
        "Classification",
        "ResultBefore",
        "ResultAfter",
        "CriticalityBefore",
        "CriticalityAfter",
        "Requirement",
        "DetailsAfter",
        "AnnotationChanged",
        "Comments",
        "ResolutionDate",
        "UnderlyingResultBefore",
        "UnderlyingResultAfter",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in result["Records"]:
            csv_row = dict(row)
            csv_row["Comments"] = " | ".join(csv_row["Comments"])
            writer.writerow(csv_row)


def _classification_css(classification: str) -> str:
    """Map a classification to a CSS class."""
    if classification in {"NewFail", "Errored", "NewIncorrectResult"}:
        return "bad"
    if classification in {"NewPass", "NewAutomatedCheck"}:
        return "good"
    if classification == "NewWarning":
        return "warn"
    if classification == "Unchanged":
        return "unchanged"
    return "neutral"


def _html_filters() -> str:
    """Build the classification filter controls."""
    labels = []
    for classification in CLASSIFICATIONS:
        escaped = html.escape(classification)
        labels.append(
            f'<label><input type="checkbox" data-filter="{escaped}" checked>'
            f" {escaped}</label>"
        )
    return "".join(labels)


def _html_summary(result: dict[str, Any]) -> str:
    """Build the summary table body."""
    products = sorted(result["Summary"], key=str.lower)
    rows = []
    for product in products:
        cells = "".join(
            f"<td>{result['Summary'][product].get(classification, 0)}</td>"
            for classification in CLASSIFICATIONS
        )
        rows.append(f"<tr><td>{html.escape(product)}</td>{cells}</tr>")
    return "".join(rows)


def _html_record_rows(result: dict[str, Any]) -> str:
    """Build the control result table rows."""
    rows = []
    for record in result["Records"]:
        classification = str(record["Classification"])
        escaped_classification = html.escape(classification)
        control = record["Control ID (After)"] or record["Control ID (Before)"]
        rows.append(
            f'<tr class="{_classification_css(classification)}" '
            f'data-classification="{escaped_classification}">'
            f'<td>{html.escape(str(record["Product"]))}</td>'
            f'<td>{html.escape(str(record["GroupNumber"] or ""))} '
            f'{html.escape(str(record["GroupName"] or ""))}</td>'
            f'<td><code>{html.escape(str(control))}</code></td>'
            f'<td>{html.escape(str(record["ResultBefore"] or ""))}</td>'
            f'<td>{html.escape(str(record["ResultAfter"] or ""))}</td>'
            f'<td>{escaped_classification}</td>'
            f'<td>{html.escape(str(record["DetailsAfter"] or ""))}</td>'
            "</tr>"
        )
    return "".join(rows)


def write_html(result: dict[str, Any], path: Path) -> None:
    """Write a self-contained HTML diff report."""
    headers = "".join(
        f"<th>{html.escape(classification)}</th>" for classification in CLASSIFICATIONS
    )
    filters = _html_filters()
    summary_rows = _html_summary(result)
    record_rows = _html_record_rows(result)
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ScubaGoggles Report Diff</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #fafafa; color: #222; }}
table {{ border-collapse: collapse; width: 100%; background: #fff; }}
th, td {{ padding: .5rem; border: 1px solid #ddd; text-align: left; vertical-align: top; }}
th {{ background: #eee; }}
.controls {{ padding: 1rem; background: #fff; border: 1px solid #ddd; margin: 1rem 0;
             display: flex; gap: 1rem; flex-wrap: wrap; }}
.bad {{ background: #ffe6e6; }}
.good {{ background: #e7f6e7; }}
.warn {{ background: #fff4d6; }}
.unchanged {{ color: #888; }}
.neutral {{ background: #f1f1f1; }}
code {{ white-space: nowrap; }}
.summary {{ overflow: auto; margin-bottom: 2rem; }}
</style>
</head>
<body>
<h1>ScubaGoggles Report Diff</h1>
<div class="controls">
<strong>Filter:</strong>{filters}
<label><input id="showUnchanged" type="checkbox" checked> Show unchanged</label>
</div>
<h2>Summary</h2>
<div class="summary">
<table>
<thead><tr><th>Product</th>{headers}</tr></thead>
<tbody>{summary_rows}</tbody>
</table>
</div>
<h2>Controls</h2>
<table>
<thead>
<tr><th>Product</th><th>Group</th><th>Control</th><th>Before</th>
<th>After</th><th>Classification</th><th>Details</th></tr>
</thead>
<tbody id="records">{record_rows}</tbody>
</table>
<script>
const checks = [...document.querySelectorAll('[data-filter]')];
const unchanged = document.getElementById('showUnchanged');
function refresh() {{
  const active = new Set(checks.filter((item) => item.checked)
    .map((item) => item.dataset.filter));
  document.querySelectorAll('#records tr').forEach((row) => {{
    const classification = row.dataset.classification;
    row.style.display = (active.has(classification) &&
      (unchanged.checked || classification !== 'Unchanged')) ? '' : 'none';
  }});
}}
checks.forEach((item) => item.addEventListener('change', refresh));
unchanged.addEventListener('change', refresh);
refresh();
</script>
</body>
</html>
"""
    path.write_text(document, encoding="utf-8")


def run_diff(
    before: Path,
    after: Path,
    outputpath: Path,
    outjsonfilename: str,
    quiet: bool = False,
) -> None:
    """Compare two reports and write JSON, CSV, and HTML outputs."""
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
