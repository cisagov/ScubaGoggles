"""Compare two saved ScubaGoggles reports."""
from __future__ import annotations

import csv
import html
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scubagoggles.version import Version

SCHEMA_VERSION = "1.0"
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
    "NewLogBasedCheck",
    "NoLogEvents",
    "NewOmission",
    "Other",
)

# Normalized (lower-cased, trimmed) Result strings and the category each one
# is compared as. Any Result starting with "Error" (e.g., "Error - Test
# results missing") is "Error", and anything not listed is "Other".
#
# "No events found" is its own category, not "NA". It comes from a log-based
# check that is already automated but has no admin log event to assess yet.
# "NA" is a check that is manual by design. See:
# https://github.com/cisagov/ScubaGoggles/blob/main/docs/usage/Limitations.md#log-based-policy-checks
RESULT_CATEGORIES = {
    "pass": "Pass",
    "fail": "Fail",
    "warning": "Warning",
    "n/a": "NA",
    "no events found": "NoEvents",
    "omitted": "Omitted",
    "incorrect result": "Incorrect",
}

# Result categories that land on an automated result, and the classification
# for landing there.
AUTOMATED_TRANSITIONS = {
    "Pass": "NewPass",
    "Fail": "NewFail",
    "Warning": "NewWarning",
}

# Categories a control can move out of into an automated result (beyond "NA",
# which is NewAutomatedCheck) and still be classified by where it lands.
# "NoEvents" is here because a log-based check that finds a new log event was
# already automated: it is now able to report the setting's state.
LANDING_SOURCES = frozenset(
    {"Pass", "Fail", "Warning", "NoEvents", "Omitted", "Incorrect", "Error"}
)

# Categories a control can move out of into a manual check and be
# classified NewManualCheck.
MANUAL_SOURCES = frozenset(
    {"Pass", "Fail", "Warning", "NoEvents", "Incorrect", "Error"}
)


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
    original_result: str | None


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

    return Control(
        product=product,
        group_name=str(group.get("GroupName", "")),
        group_number=str(group.get("GroupNumber", "")),
        control_id=control_id,
        result=str(control_data.get("Result", "")),
        criticality=str(control_data.get("Criticality", "")),
        requirement=str(control_data.get("Requirement", "")),
        details=str(control_data.get("Details", "")),
        original_result=control_data.get("OriginalResult"),
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


def _normalize_result(result: str | None) -> str:
    """Return a Result string lower-cased and trimmed for comparison."""
    return (result or "").strip().lower()


def result_category(result: str | None) -> str:
    """Return the comparison category of an open-ended Result string.

    Args:
        result: A control's Result value, such as "Pass" or "No events found".

    Returns:
        One of "Pass", "Fail", "Warning", "NA", "NoEvents", "Omitted",
        "Incorrect", "Error", or "Other". Unrecognized values are "Other", so
        a new Result value never breaks the diff.
    """
    value = _normalize_result(result)
    if value.startswith("error"):
        return "Error"
    return RESULT_CATEGORIES.get(value, "Other")


def result_diff(before: str | None, after: str | None) -> str:
    # pylint: disable=too-many-return-statements
    """Classify a before/after result.

    Classifications are named for the state the control lands in, so any
    change ending in Pass, Fail, or Warning is NewPass, NewFail, or
    NewWarning, including changes out of Omitted, Error, a cleared
    "Incorrect result" marking, or "No events found". A change into
    "No events found" is NewLogBasedCheck when coming from N/A and
    NoLogEvents otherwise.
    """
    before_category = result_category(before)
    after_category = result_category(after)

    # Precedence order #2 (errored result): keyed off the after result only,
    # so a control that recovered from an error is classified by where it lands.
    if after_category == "Error":
        return "Errored"

    # Precedence order #4 (unchanged results)
    if (before_category == after_category
            and _normalize_result(before) == _normalize_result(after)):
        return "Unchanged"

    # Precedence order #5 (incorrect result)
    if after_category == "Incorrect":
        return "NewIncorrectResult"

    # Precedence order #6 (specific result changes)
    if after_category in AUTOMATED_TRANSITIONS:
        if before_category == "NA":
            return "NewAutomatedCheck"
        if before_category in LANDING_SOURCES:
            return AUTOMATED_TRANSITIONS[after_category]
    if after_category == "NA" and before_category in MANUAL_SOURCES:
        return "NewManualCheck"
    # Landing on "No events found": a manual-by-design check that became a
    # log-based check is NewLogBasedCheck; any other change into it (e.g., a
    # log event aging out of retention) is NoLogEvents.
    if after_category == "NoEvents":
        if before_category == "NA":
            return "NewLogBasedCheck"
        return "NoLogEvents"

    # Precedence order #7 (remaining changes into or out of Omitted)
    if "Omitted" in (before_category, after_category):
        return "NewOmission"

    # Precedence order #8 (Other)
    return "Other"


def classify_pair(before: Control | None, after: Control | None) -> str:
    """Classify a before/after control pair."""
    # Precedence order #1 (new/removed policy)
    if before is None:
        return "NewPolicy"
    if after is None:
        return "RemovedPolicy"

    # Precedence order #3 (policy version change)
    _, before_version = split_version(before.control_id)
    _, after_version = split_version(after.control_id)
    policy_version_change = None
    if (
        before_version is not None
        and after_version is not None
        and before_version != after_version
    ):
        policy_version_change = "PolicyVersionUpdate"

    # Handle classifications of Control result components
    result = result_diff(before.result, after.result)

    # Respect classiciation Precedence
    # Precedence #2
    if result == "Errored":
        return result
    # Precedence #3
    if policy_version_change is not None:
        return policy_version_change
    # remaining classifications
    return result


# CSV columns: one row per control, with every column on every row. Column
# names mirror the JSON field names, with the product in a leading column.
CSV_FIELDS = (
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
    "MarkedIncorrectBefore",
    "MarkedIncorrectAfter",
    "UnderlyingResultBefore",
    "UnderlyingResultAfter",
    "AnnotationChanged",
    "Comment",
    "RemediationDate",
)

# Leading characters a spreadsheet evaluates as the start of a formula.
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _plain_text(value: str | None) -> str:
    """Convert report HTML to plain text.

    The indicator badges block appended to a Requirement is dropped, the
    remaining tags are removed, entities are decoded, and whitespace is
    collapsed.
    """
    if not value:
        return ""
    value = re.sub(r"(?s)<div class=['\"]badges['\"].*$", "", value)
    value = re.sub(r"<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", html.unescape(value)).strip()


def _annotation(annotations: dict[str, Any], control_id: str) -> tuple[Any, Any]:
    """Return the (Comment, RemediationDate) annotated for a control."""
    entry = annotations.get(control_id)
    if not isinstance(entry, dict):
        return None, None
    return entry.get("Comment"), entry.get("RemediationDate")


def make_record(
    before: Control | None,
    after: Control | None,
    before_annotations: dict[str, Any] | None = None,
    after_annotations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create one diff record.

    Args:
        before: The control in the before report, or None if absent.
        after: The control in the after report, or None if absent.
        before_annotations: The before report's AnnotatedFailedPolicies.
        after_annotations: The after report's AnnotatedFailedPolicies.

    Returns:
        The record. When either side is marked "Incorrect result", it also
        carries MarkedIncorrectBefore/After and UnderlyingResultBefore/After.
        When the control fails in both reports, it also carries
        AnnotationChanged, Comment, and RemediationDate.
    """
    current = after or before
    assert current is not None
    record = {
        "Control ID (Before)": before.control_id if before else None,
        "Control ID (After)": after.control_id if after else None,
        "Requirement": _plain_text(current.requirement),
        "GroupName": current.group_name,
        "GroupNumber": current.group_number,
        "ResultBefore": before.result if before else None,
        "ResultAfter": after.result if after else None,
        "Classification": classify_pair(before, after),
        "CriticalityBefore": before.criticality if before else None,
        "CriticalityAfter": after.criticality if after else None,
        "DetailsAfter": _plain_text(after.details) if after else None,
    }

    # False-positive (marked incorrect) fields: the marking on each side and
    # the tool-computed result underneath it.
    before_incorrect = before is not None and result_category(before.result) == "Incorrect"
    after_incorrect = after is not None and result_category(after.result) == "Incorrect"
    if before_incorrect or after_incorrect:
        record["MarkedIncorrectBefore"] = before_incorrect
        record["MarkedIncorrectAfter"] = after_incorrect
        record["UnderlyingResultBefore"] = before.original_result if before else None
        record["UnderlyingResultAfter"] = after.original_result if after else None

    # Annotation fields, compared only for a control failing in both reports.
    if (before is not None and after is not None
            and result_category(before.result) == "Fail"
            and result_category(after.result) == "Fail"):
        before_comment, before_date = _annotation(before_annotations or {},
                                                  before.control_id)
        after_comment, after_date = _annotation(after_annotations or {},
                                                after.control_id)
        record["AnnotationChanged"] = (before_comment != after_comment
                                       or before_date != after_date)
        record["Comment"] = after_comment
        record["RemediationDate"] = after_date

    return record


def _control_sort_key(record: dict[str, Any]) -> str:
    """Return a sort key ordering control IDs numerically.

    Every run of digits in the base control ID is zero-padded, so
    GWS.GMAIL.9.1 sorts before GWS.GMAIL.10.1.
    """
    control_id = record["Control ID (After)"] or record["Control ID (Before)"]
    base_id = split_version(control_id)[0]
    return re.sub(r"\d+", lambda match: match.group().zfill(10), base_id)


def _ordered_products(products) -> list[str]:
    """Return product names in report order (alphabetical, ignoring case)."""
    return sorted(products, key=str.lower)


def _report_annotations(report: dict[str, Any]) -> dict[str, Any]:
    """Return a report's AnnotatedFailedPolicies, or an empty dict."""
    annotations = report.get("AnnotatedFailedPolicies")
    return annotations if isinstance(annotations, dict) else {}


def _run_metadata(report: dict[str, Any]) -> dict[str, Any]:
    """Return the identifying metadata of one input report."""
    metadata = report.get("MetaData")
    if not isinstance(metadata, dict):
        metadata = {}
    return {
        "ReportUUID": metadata.get("ReportUUID"),
        "TimestampZulu": metadata.get("TimestampZulu"),
        "ToolVersion": metadata.get("ToolVersion"),
    }


def compare(before_report: dict[str, Any], after_report: dict[str, Any]) -> dict[str, Any]:
    """Compare two ScubaGoggles reports.

    Returns:
        The diff: SchemaVersion, MetaData, a per-product Summary of
        classification counts, and the per-product Diff records. Products
        with no records are left out.
    """
    before = collect_controls(before_report)
    after = collect_controls(after_report)
    before_annotations = _report_annotations(before_report)
    after_annotations = _report_annotations(after_report)

    diff: dict[str, list[dict[str, Any]]] = {}
    for key in set(before) | set(after):
        current = after.get(key) or before[key]
        record = make_record(before.get(key),
                             after.get(key),
                             before_annotations,
                             after_annotations)
        diff.setdefault(current.product, []).append(record)

    ordered_diff = {}
    summary = {}
    for product in _ordered_products(diff):
        records = sorted(diff[product], key=_control_sort_key)
        counts: dict[str, int] = {}
        for record in records:
            classification = record["Classification"]
            counts[classification] = counts.get(classification, 0) + 1
        # Counts follow the classification order; any classification outside
        # it is appended rather than dropped.
        ordered_counts = {name: counts[name] for name in CLASSIFICATIONS if name in counts}
        ordered_counts.update(counts)
        ordered_diff[product] = records
        summary[product] = ordered_counts

    before_products = set(before_report["Results"])
    after_products = set(after_report["Results"])
    timestamp_zulu = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    return {
        "SchemaVersion": SCHEMA_VERSION,
        "MetaData": {
            "Tool": "ScubaGoggles",
            "ToolVersion": Version.number,
            "TimestampZulu": timestamp_zulu,
            "Before": _run_metadata(before_report),
            "After": _run_metadata(after_report),
            "ProductsOnlyInBefore": _ordered_products(before_products - after_products),
            "ProductsOnlyInAfter": _ordered_products(after_products - before_products),
        },
        "Summary": summary,
        "Diff": ordered_diff,
    }


def write_json(result: dict[str, Any], path: Path) -> None:
    """Write a diff result as JSON."""
    path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _csv_safe(value: Any) -> Any:
    """Keep a spreadsheet from evaluating a CSV value as a formula.

    A string starting with =, +, -, @, tab, or carriage return is prefixed
    with a single quote so it is read as text. Other values are unchanged.
    """
    if isinstance(value, str) and value.startswith(CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def write_csv(result: dict[str, Any], path: Path) -> None:
    """Write a diff result as CSV, one row per control.

    Unchanged rows are included. Fields a record does not carry are left
    empty, and every value is protected against formula evaluation.
    """
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for product, records in result["Diff"].items():
            for record in records:
                row = {"Product": product}
                row.update({field: record.get(field) for field in CSV_FIELDS[1:]})
                writer.writerow({field: _csv_safe(value) for field, value in row.items()})


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
    for product, records in result["Diff"].items():
        for record in records:
            current_state = str(record["ResultAfter"]) or ""
            classification = str(record["Classification"])

            # class labels reflect color coded rows
            class_label = current_state.lower()
            if class_label not in {"pass", "fail", "warning"}:
                class_label = "other"

            escaped_classification = html.escape(classification)
            control = record["Control ID (After)"] or record["Control ID (Before)"]
            rows.append(
                f'<tr class="{class_label}" '
                f'data-classification="{escaped_classification}">'
                f'<td>{html.escape(product)}</td>'
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
.fail {{ background: #ffe6e6; }}
.pass {{ background: #e7f6e7; }}
.warning {{ background: #fff4d6; }}
.other {{ background: #f1f1f1; }}
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
    row.style.display = active.has(classification) ? '' : 'none';
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
    *,
    outputpath: Path | None = None,
    outjsonfilename: str = "DiffResults",
    outcsvfilename: str = "DiffResults",
    outreportfilename: str = "DiffReport",
    quiet: bool = False,
) -> dict[str, Path]:
    """Compare two reports and write JSON, CSV, and HTML outputs.

    Args:
        before: Path to the earlier ("before") ScubaGoggles report.
        after: Path to the later ("after") ScubaGoggles report.
        outputpath: Folder to write the three outputs to. Created if it
            does not exist. Defaults to the current directory.
        outjsonfilename: Base name (no extension) of the diff JSON.
        outcsvfilename: Base name (no extension) of the diff CSV.
        outreportfilename: Base name (no extension) of the diff HTML report.
        quiet: Suppress printing the output file paths.

    Returns:
        The paths written, keyed "JsonPath", "CsvPath", and "ReportPath".
    """
    result = compare(load_report(before), load_report(after))
    if outputpath is None:
        outputpath = Path.cwd()

    outputpath.mkdir(parents=True, exist_ok=True)
    json_path = outputpath / f"{outjsonfilename}.json"
    csv_path = outputpath / f"{outcsvfilename}.csv"
    report_path = outputpath / f"{outreportfilename}.html"
    write_json(result, json_path)
    write_csv(result, csv_path)
    write_html(result, report_path)
    if not quiet:
        print(f"ScubaGoggles diff written to:\n  {json_path}\n  {csv_path}\n  {report_path}")
    return {"JsonPath": json_path, "CsvPath": csv_path, "ReportPath": report_path}
