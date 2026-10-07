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

from scubagoggles.orchestrator import Orchestrator
from scubagoggles.version import Version

SCHEMA_VERSION = "1.0"
VERSION_RE = re.compile(r"^(?P<base>.+?)(?:v(?P<version>\d+))$", re.IGNORECASE)

# Display order for the summary table's classification columns, their filter
# checkboxes, and the JSON summary counts. The order is by severity, in tiers:
#
#   1. Broken now:            Errored, NewFail
#   2. Degraded:              NewWarning
#   3. Needs manual review:   NewIncorrectResult, PolicyVersionUpdate,
#                             NewOmission, NoLogEvents, Other
#   4. Coverage shape:        NewAutomatedCheck, NewManualCheck, NewLogBasedCheck
#   5. Good news / admin:     NewPass, NewPolicy, RemovedPolicy
#   6. Hidden by default:     Unchanged
#
# Row color keys off Result (After), so the tiers roughly track the row
# colors and column order and row color tell one severity story.
CLASSIFICATIONS = (
    "Errored",
    "NewFail",
    "NewWarning",
    "NewIncorrectResult",
    "PolicyVersionUpdate",
    "NewOmission",
    "NoLogEvents",
    "Other",
    "NewAutomatedCheck",
    "NewManualCheck",
    "NewLogBasedCheck",
    "NewPass",
    "NewPolicy",
    "RemovedPolicy",
    "Unchanged",
)

# Classification -> label shown in the HTML report's Diff column.
# Classifications not listed are shown as their raw token.
CLASSIFICATION_LABELS = {
    "NewFail": "New Fail",
    "NewPass": "New Pass",
    "NewWarning": "New Warning",
    "NewOmission": "New Omission",
    "NewAutomatedCheck": "New Automated Check",
    "NewManualCheck": "New Manual Check",
    "NewLogBasedCheck": "New Log-Based Check",
    "NoLogEvents": "No Log Events",
    "NewIncorrectResult": "New Incorrect Result (false positive)",
    "NewPolicy": "New Policy",
    "RemovedPolicy": "Removed Policy",
    "PolicyVersionUpdate": "Policy Version Update",
}

# Result category -> HTML row color. Rows are colored by Result (After), so
# the color shows the control's current state; anything else is grey.
ROW_COLORS = {
    "Fail": "red",
    "Error": "red",
    "Warning": "yellow",
    "Pass": "green",
}

# Result category -> CSS class coloring a Result (Before) / Result (After)
# cell's text, so a reader can see which way a policy moved.
RESULT_TEXT_CLASSES = {
    "Pass": "result-pass",
    "Fail": "result-fail",
    "Warning": "result-warning",
}

REPORTER_DIR = Path(__file__).parent / "reporter"
DIFF_REPORT_CSS = REPORTER_DIR / "styles" / "DiffReport.css"
DIFF_REPORT_JS = REPORTER_DIR / "scripts" / "DiffReport.js"

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


def _escape(value: Any) -> str:
    """HTML-escape a value for the report; None becomes an empty string."""
    return html.escape("" if value is None else str(value))


def _product_display_name(product: str) -> str:
    """Return a product's full name, such as "Gmail" or "Google Drive and Docs"."""
    full_names = Orchestrator.gws_products()["prod_to_fullname"]
    return full_names.get(product.lower(), product)


def _classification_label(classification: str) -> str:
    """Return the report label for a classification."""
    return CLASSIFICATION_LABELS.get(classification, classification)


def _row_color(record: dict[str, Any]) -> str:
    """Return the row color for a record.

    Removed policies have no after result and are grey. Every other row is
    colored by its Result (After): Fail and Error red, Warning yellow, Pass
    green, and anything else (N/A, No events found, Omitted, ...) grey.
    """
    if record["Classification"] == "RemovedPolicy":
        return "grey"
    return ROW_COLORS.get(result_category(record["ResultAfter"]), "grey")


def _result_text_class(result: str | None) -> str:
    """Return the CSS class coloring a Result (Before/After) cell's text."""
    return RESULT_TEXT_CLASSES.get(result_category(result), "")


def _html_header() -> list[str]:
    """Build the report title and the unchanged / dark mode toggles."""
    return [
        '<div class="report-header">',
        '  <div class="report-title">',
        "    <h1>ScubaGoggles Diff Report</h1>",
        '    <p class="report-subtitle">Comparison between two ScubaGoggles results '
        "files</p>",
        "  </div>",
        '  <div class="controls-bar">',
        '    <label><input type="checkbox" id="toggle-unchanged"> Show unchanged rows</label>',
        '    <label><input type="checkbox" id="toggle-dark"> Dark Mode</label>',
        "  </div>",
        "</div>",
    ]


def _html_sources(metadata: dict[str, Any]) -> list[str]:
    """Build the Before/After source cards and the products-only callouts."""
    lines = ['<div class="source-summary">']
    for side in ("Before", "After"):
        source = metadata.get(side) or {}
        lines += [
            '  <div class="source-card">',
            f"    <h3>{side}</h3>",
            f"    <div>Tool version: {_escape(source.get('ToolVersion'))}</div>",
            f"    <div>Timestamp: {_escape(source.get('TimestampZulu'))}</div>",
            f'    <div class="uuid">Report UUID: {_escape(source.get("ReportUUID"))}</div>',
            "  </div>",
        ]
    lines.append("</div>")
    lines.append(
        f'<p class="diff-generated">Diff generated {_escape(metadata.get("TimestampZulu"))} '
        f'by ScubaGoggles {_escape(metadata.get("ToolVersion"))}.</p>'
    )

    callouts = (
        ("ProductsOnlyInBefore", "Products only in Before (all controls Removed Policy)"),
        ("ProductsOnlyInAfter", "Products only in After (all controls New Policy)"),
    )
    for key, text in callouts:
        products = metadata.get(key) or []
        if products:
            names = ", ".join(_product_display_name(product) for product in products)
            lines.append(f"<p><strong>{text}:</strong> {_escape(names)}</p>")
    return lines


def _html_legend() -> list[str]:
    """Build the row color legend."""
    return [
        '<div class="legend">',
        '  <span><span class="swatch diff-red"></span>Fail / Error (Result After)</span>',
        '  <span><span class="swatch diff-yellow"></span>Warning (Result After)</span>',
        '  <span><span class="swatch diff-green"></span>Pass (Result After)</span>',
        '  <span><span class="swatch diff-grey"></span>'
        "Manual (N/A) / No events found / Omitted / Removed Policy</span>",
        "  <span>Unchanged rows are hidden by default (use the toggle above).</span>",
        "</div>",
    ]


def _html_summary(result: dict[str, Any]) -> list[str]:
    """Build the per-product summary table with its classification filters.

    Every classification gets a column, including ones absent from this
    diff, so each one has a filter checkbox. Unchanged has no checkbox; it is
    governed by the "Show unchanged rows" toggle and always counted in Total.
    """
    lines = [
        "<h2>Summary</h2>",
        '<div class="filter-controls">',
        '  <span class="filter-hint">Use the checkboxes in the column headers to filter '
        "classifications. Filters apply to this table and the product tables below.</span>",
        '  <button type="button" id="toggle-all-filters" class="filter-btn">'
        "Uncheck all filters</button>",
        "</div>",
        '<table class="summary-table">',
    ]

    header = ["<tr><th>Product</th>"]
    for classification in CLASSIFICATIONS:
        name = _escape(classification)
        if classification == "Unchanged":
            header.append(f'<th class="classification-col" data-classification="{name}">'
                          f"{name}</th>")
        else:
            header.append(f'<th class="classification-col classification-filter" '
                          f'data-classification="{name}"><label><input type="checkbox" '
                          f'class="classification-toggle" data-classification="{name}" '
                          f"checked> {name}</label></th>")
    header.append("<th>Total</th></tr>")
    lines.append("".join(header))

    for product, counts in result["Summary"].items():
        row = [f"<tr><td>{_escape(_product_display_name(product))}</td>"]
        total = 0
        for classification in CLASSIFICATIONS:
            count = counts.get(classification, 0)
            total += count
            css_class = "count count-zero" if count == 0 else "count"
            row.append(f'<td class="{css_class}" data-classification="{_escape(classification)}" '
                       f'data-count="{count}">{count}</td>')
        row.append(f'<td class="summary-total">{total}</td></tr>')
        lines.append("".join(row))

    lines.append("</table>")
    return lines


def _html_result_cell(record: dict[str, Any], side: str) -> str:
    """Build a Result (Before/After) cell.

    A side marked "Incorrect result" (a false positive) also shows the
    underlying tool-computed result.
    """
    result = record[f"Result{side}"]
    content = _escape(result)
    underlying = record.get(f"UnderlyingResult{side}")
    if record.get(f"MarkedIncorrect{side}") and underlying:
        content += f' <span class="underlying">(underlying: {_escape(underlying)})</span>'
    css_class = f"result-cell {_result_text_class(result)}".strip()
    return f'  <td class="{css_class}">{content}</td>'


def _html_product_tables(result: dict[str, Any]) -> list[str]:
    """Build one diff table per product."""
    lines = []
    for product, records in result["Diff"].items():
        lines += [
            f"<h2>{_escape(_product_display_name(product))}</h2>",
            '<table class="policy-diff">',
            "<tr><th>Control ID</th><th>Group</th><th>Diff</th><th>Result (Before)</th>"
            "<th>Result (After)</th><th>Requirement</th><th>Details (After)</th></tr>",
        ]
        for record in records:
            classification = record["Classification"]
            row_class = f"diff-row diff-{_row_color(record)}"
            if classification == "Unchanged":
                row_class += " diff-unchanged-row"

            # Show "before -> after" when the IDs differ (a policy version update).
            before_id = record["Control ID (Before)"]
            after_id = record["Control ID (After)"]
            if before_id and after_id and before_id != after_id:
                control_id = f"{_escape(before_id)} &rarr; {_escape(after_id)}"
            else:
                control_id = _escape(after_id or before_id)

            group = f"{record['GroupNumber'] or ''} {record['GroupName'] or ''}".strip()
            lines += [
                f'<tr class="{row_class}" data-classification="{_escape(classification)}">',
                f"  <td>{control_id}</td>",
                f"  <td>{_escape(group)}</td>",
                f'  <td class="classification-label">'
                f"{_escape(_classification_label(classification))}</td>",
                _html_result_cell(record, "Before"),
                _html_result_cell(record, "After"),
                f"  <td>{_escape(record['Requirement'])}</td>",
                f"  <td>{_escape(record['DetailsAfter'])}</td>",
                "</tr>",
            ]
        lines.append("</table>")
    return lines


def write_html(result: dict[str, Any], path: Path, darkmode: bool = False) -> None:
    """Write a self-contained HTML diff report.

    The report's CSS and JavaScript are inlined. Unchanged rows are written
    but hidden until the "Show unchanged rows" toggle is checked, and every
    report string is HTML-escaped.

    Args:
        result: The diff result from compare().
        path: The HTML file to write.
        darkmode: Open the report in dark mode.
    """
    body = (_html_header()
            + _html_sources(result["MetaData"])
            + _html_legend()
            + _html_summary(result)
            + _html_product_tables(result))
    css = DIFF_REPORT_CSS.read_text(encoding="utf-8")
    javascript = DIFF_REPORT_JS.read_text(encoding="utf-8")
    dark_flag = "true" if darkmode else "false"
    body_html = "\n".join(body)
    document = f"""<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ScubaGoggles Diff Report</title>
<style>
{css}
</style>
</head>
<body>
{body_html}
<script id="dark-mode-flag" type="application/json">{dark_flag}</script>
<script>
{javascript}
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
    darkmode: bool = False,
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
        darkmode: Open the HTML report in dark mode.
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
    write_html(result, report_path, darkmode=darkmode)
    if not quiet:
        print(f"ScubaGoggles diff written to:\n  {json_path}\n  {csv_path}\n  {report_path}")
    return {"JsonPath": json_path, "CsvPath": csv_path, "ReportPath": report_path}
