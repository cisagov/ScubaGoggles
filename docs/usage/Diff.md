# Comparing Two ScubaGoggles Runs

## Overview

`scubagoggles diff` compares two ScubaResults JSON files produced by earlier
ScubaGoggles runs, a **before** file and an **after** file, and reports how each
policy's result changed between them. It is an offline command: it performs no
authentication and never contacts a Google Workspace tenant.

It produces three files:

1. **`DiffResults.json`**: a machine-readable record of every policy's change
   between the two runs, with a top-level `SchemaVersion` for anything that
   reads it. See [The JSON](#the-json).
2. **`DiffResults.csv`**: the same records flattened to one row per policy, for
   spreadsheets and other tabular tools. See [The CSV](#the-csv).
3. **`DiffReport.html`**: a self-contained HTML report that highlights the
   changes with color-coded rows and hides unchanged rows behind a toggle. See
   [The HTML report](#the-html-report).

## Usage

Provide the path to the earlier ScubaResults file and the path to the later one:

```bash
scubagoggles diff --beforepath ./q1/ScubaResults_abc123.json \
                  --afterpath  ./q2/ScubaResults_def456.json
```

By default the three files are written to the current directory as
`DiffResults.json`, `DiffResults.csv`, and `DiffReport.html`. Use `--outputpath`
to choose a folder (it is created if it does not exist) and `--darkmode true` to
open the report in dark mode:

```bash
scubagoggles diff --beforepath ./q1/ScubaResults_abc123.json \
                  --afterpath  ./q2/ScubaResults_def456.json \
                  --outputpath ./diff \
                  --darkmode true
```

### Run order

The two files are compared in the order given: `--afterpath` is taken as the
later run. That order is not enforced, because the pair may equally be two
tenants captured at the same point in time, where order carries no meaning.

As a guard against a swapped pair, the run timestamps recorded in each file's
`MetaData.TimestampZulu` are compared, and a warning is written when the after
run is not later than the before run. The diff still runs. The check is skipped
when either timestamp is missing or is not a valid date and time.

A swapped pair produces a self-consistent report that reads in reverse: a policy
that was fixed between the two runs is classified `NewFail`.

### Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `--beforepath` | Yes | n/a | Path to the earlier ("before") ScubaResults JSON file. |
| `--afterpath` | Yes | n/a | Path to the later ("after") ScubaResults JSON file. |
| `--outputpath`, `-o` | No | Current directory | Folder to write the three files to. Created if missing. |
| `--outjsonfilename` | No | `DiffResults` | Base name (no extension) of the diff JSON. |
| `--outcsvfilename` | No | `DiffResults` | Base name (no extension) of the diff CSV. |
| `--outputreportfilename` | No | `DiffReport` | Base name (no extension) of the diff HTML report. |
| `--darkmode`, `-dm` | No | `false` | `true` to open the HTML report in dark mode. |
| `--quiet` | No | Off | Do not print the paths of the files written. |

A file that is missing, empty, not valid JSON, or missing any of the
`MetaData`, `Summary`, or `Results` top-level keys is rejected with an error.

## How controls are matched

ScubaGoggles policy IDs carry a version suffix, e.g. `GWS.GMAIL.1.1v1`. The
suffix increments (`v1` to `v2`) when the *meaning* of the policy changes.
`scubagoggles diff` matches controls on their **base ID**, the ID with the
version suffix removed (`GWS.GMAIL.1.1v1` becomes `GWS.GMAIL.1.1`):

- **Same base ID, same version**: the results are compared directly.
- **Same base ID, different version**: the change is classified as
  `PolicyVersionUpdate`. Because the policy's meaning changed between the two
  runs, the before and after results are reported for information only, not as
  a pass/fail change.
- **Base ID present in only one file**: `NewPolicy` (only in *after*) or
  `RemovedPolicy` (only in *before*).

  > **Note:** `RemovedPolicy` is inferred purely from presence. That usually
  > means the policy was removed from the baseline, but it also happens when the
  > after run did not assess that control or product (for example, comparing
  > two runs with different `--baselines`).

> **Note:** Compare reports from ScubaGoggles v1 onward. Earlier releases were
> drafts and betas whose policy IDs carried versions such as `v0.6`, which are
> not matched to their `v1` counterparts.

Products are matched by name only. A product present in only one file has all
of its controls reported as `NewPolicy` (only in *after*) or `RemovedPolicy`
(only in *before*).

If a file lists the same base ID more than once within a product, a warning is
written and the last one is compared.

## Diff Key Terminology

Every base control ID present in either file is assigned exactly one
classification. Classifications are named for the state the control **lands
in**, so any change that ends in Pass, Fail, or Warning reports as `NewPass`,
`NewFail`, or `NewWarning`, including changes out of `Omitted`, a prior error,
an `Incorrect result` marking, or `No events found`.

### Precedence order

A control can match more than one rule at once (for example, its version
changed *and* its result changed). It is assigned the **first** matching
classification in this order:

| Rank | Classification | Applies when |
|---|---|---|
| 1 | `NewPolicy` / `RemovedPolicy` | The base ID is present in only one file. |
| 2 | `Errored` | The **after** result is an error (any result starting with `Error`). Keyed off the latest run only, so a current error shows even under a version change. |
| 3 | `PolicyVersionUpdate` | The version suffix changed; the before and after results are informational. |
| 4 | `Unchanged` | The result and version are identical (hidden by default). |
| 5 | `NewIncorrectResult` | The after result is newly marked `Incorrect result`. |
| 6 | specific changes | A recognized result change: `NewFail`, `NewPass`, `NewWarning`, `NewAutomatedCheck`, `NewManualCheck`, `NewLogBasedCheck`, `NoLogEvents`. |
| 7 | `NewOmission` | A remaining change into or out of `Omitted`. |
| 8 | `Other` | Anything else (both result values are kept). |

> A control that errored in the earlier run but not the later one
> (`Error` to `Pass`, `Fail`, or `Warning`) is **not** `Errored`; it is
> classified by the state it lands in.

Results are compared ignoring case and surrounding spaces.

### Diff table

| Before → After | Classification |
|---|---|
| Pass → Fail | `NewFail` |
| Fail → Pass | `NewPass` |
| Warning → Pass | `NewPass` |
| Warning → Fail | `NewFail` |
| Pass/Fail → Warning | `NewWarning` |
| N/A → Pass/Fail/Warning | `NewAutomatedCheck` |
| Pass/Fail/Warning → N/A | `NewManualCheck` |
| No events found → Pass/Fail/Warning | `NewPass` / `NewFail` / `NewWarning` |
| N/A → No events found | `NewLogBasedCheck` |
| No events found → N/A | `NewManualCheck` |
| Any other result → No events found | `NoLogEvents` |
| Any → Omitted, or Omitted → any result not covered elsewhere in this table | `NewOmission` |
| Any → Incorrect result | `NewIncorrectResult` |
| Omitted → Pass/Fail/Warning | `NewPass` / `NewFail` / `NewWarning` |
| Incorrect result → Pass/Fail/Warning | `NewPass` / `NewFail` / `NewWarning` |
| Error → Pass/Fail/Warning (recovered) | `NewPass` / `NewFail` / `NewWarning` |
| Error or Incorrect result → N/A | `NewManualCheck` |
| GWS.PRODUCT.X.XvN → GWS.PRODUCT.X.XvN+1 | `PolicyVersionUpdate` |
| No prior policy → new policy | `NewPolicy` |
| Policy → none (removed from the baseline) | `RemovedPolicy` |
| Any → Error | `Errored` |
| Any → the same result and version | `Unchanged` (hidden by default) |
| Anything else | `Other` (both result values are kept) |

The classification appears in the report's **Diff** column. Results are treated
as an **open set**: a value the diff does not recognize (e.g. a future status)
classifies as `Other` with both values kept. It never stops the diff.

### Google Workspace results

Two results are specific to ScubaGoggles:

- **`No events found`** comes from a
  [log-based check](Limitations.md#log-based-policy-checks). These checks are
  automated, but they can only report a setting's state once an admin log event
  for it exists. `No events found` is therefore compared as its own result, not
  as a manual check like `N/A`:
  - A new log event that now reports `Pass`, `Fail`, or `Warning` is
    `NewPass`, `NewFail`, or `NewWarning`.
  - A manual (`N/A`) check that became a log-based check is `NewLogBasedCheck`.
  - Any other change into `No events found` is `NoLogEvents`. A common cause is
    the log event that showed the setting aging out of the admin log retention
    period.
- **`Error - Test results missing`**, like any result starting with `Error`, is
  treated as an error.

## Classification order

The summary table's classification columns, their filter checkboxes, and the
per-product counts in `DiffResults.json` are laid out in severity order:

| Tier | Meaning | Classifications |
|---|---|---|
| 1 | Broken now | `Errored`, `NewFail` |
| 2 | Degraded | `NewWarning` |
| 3 | Needs manual review | `NewIncorrectResult`, `PolicyVersionUpdate`, `NewOmission`, `NoLogEvents`, `Other` |
| 4 | Coverage shape changed | `NewAutomatedCheck`, `NewManualCheck`, `NewLogBasedCheck` |
| 5 | Good news and administrative | `NewPass`, `NewPolicy`, `RemovedPolicy` |
| 6 | Hidden by default | `Unchanged` |

Row color keys off Result (After), so the tiers roughly track the row colors
below.

## Row coloring

Report rows are colored by the **Result (After)** value, so the color shows the
control's *current* state, not the kind of change (which is in the Diff column):

| Result (After) | Row color |
|---|---|
| Fail | red |
| Error | red |
| Warning | yellow |
| Pass | green |
| N/A / No events found / Omitted / Incorrect result / other | grey |
| Removed from the baseline (`RemovedPolicy`) | grey |

The **Result (Before)** and **Result (After)** text is also colored (Pass
green, Fail red, Warning amber), so a reader can see which way a policy moved.
Other results keep the default text color.

## Annotations (Fail → Fail)

For controls that fail in both runs, the diff compares the
`AnnotatedFailedPolicies` entries in the two files and adds three fields to the
record:

- `AnnotationChanged`: `true` if the comment or remediation date differs.
- `Comment`: the after file's comment.
- `RemediationDate`: the after file's anticipated remediation date.

Annotation changes are only compared for `Fail → Fail` records.

## False positives (results marked incorrect)

When a policy result is marked incorrect in the config file (a false positive),
ScubaGoggles reports that control's `Result` as `Incorrect result`. The diff
reports the change in the marking itself:

- A result becoming a false positive is classified `NewIncorrectResult`.
- A false positive being removed is classified by the result it reveals:
  `NewPass`, `NewFail`, or `NewWarning` (or `NewManualCheck`, `NoLogEvents`, or
  `NewOmission` when the marking clears to N/A, No events found, or Omitted).
- A marking present in both runs is `Unchanged`.

For any record where either side is marked incorrect, four fields are added:

- `MarkedIncorrectBefore` / `MarkedIncorrectAfter`: whether each side was
  marked a false positive.
- `UnderlyingResultBefore` / `UnderlyingResultAfter`: the result ScubaGoggles
  computed (`OriginalResult`) on each side.

In the report, the Result columns show the underlying result inline (e.g.
`Incorrect result (underlying: Fail)`).

## The JSON

`DiffResults.json` has four top-level keys:

- `SchemaVersion`: the version of this file's layout (currently `1.0`).
- `MetaData`: the ScubaGoggles version and time that produced the diff; the
  `ReportUUID`, `TimestampZulu`, and `ToolVersion` of the before and after
  files; and `ProductsOnlyInBefore` / `ProductsOnlyInAfter`.
- `Summary`: for each product, the count of each classification that occurs,
  in the [classification order](#classification-order).
- `Diff`: for each product, its records in policy order. Products appear in the
  same order as a ScubaGoggles run, and products with no records are left out.

Each record carries `Control ID (Before)`, `Control ID (After)`, `Requirement`,
`GroupName`, `GroupNumber`, `ResultBefore`, `ResultAfter`, `Classification`,
`CriticalityBefore`, `CriticalityAfter`, and `DetailsAfter`, plus the
[annotation](#annotations-fail--fail) and
[false-positive](#false-positives-results-marked-incorrect) fields where they
apply. Fields that do not apply to a `NewPolicy` or `RemovedPolicy` record (the
missing side) are `null`. `Requirement` and `DetailsAfter` are plain text; the
HTML in the ScubaResults file, including the indicator badges, is removed.

## The CSV

`DiffResults.csv` is the same data as `DiffResults.json`, flattened to **one row
per policy**. The product is carried in a leading `Product` column. Column names
match the JSON field names:

`Product`, `Control ID (Before)`, `Control ID (After)`, `GroupNumber`,
`GroupName`, `Classification`, `ResultBefore`, `ResultAfter`,
`CriticalityBefore`, `CriticalityAfter`, `Requirement`, `DetailsAfter`,
`MarkedIncorrectBefore`, `MarkedIncorrectAfter`, `UnderlyingResultBefore`,
`UnderlyingResultAfter`, `AnnotationChanged`, `Comment`, `RemediationDate`.

Every row has every column. The last seven are only filled in where they apply
(the false-positive fields where a side is marked incorrect, the annotation
fields for `Fail → Fail`) and are empty elsewhere.

Two differences from the HTML report:

- **Unchanged rows are included**, not hidden. Filter on `Classification` to
  drop them.
- The `Classification` column has the raw value (`NewFail`), not the report's
  label ("New Fail").

Spreadsheets evaluate a cell whose text begins with `=`, `+`, `-`, or `@` as a
formula, so any such value is written with a leading single quote (`'`) that
makes it read as text. This is most visible on `Comment`, which is free text.

## The HTML report

- **Unchanged rows are hidden by default.** Check **Show unchanged rows** at the
  top of the report to show them.
- **Classification filters are in the summary table.** Every classification has
  a column, including ones absent from the current diff, and each column
  header (except `Unchanged`) has a checkbox. Unchecking a classification hides
  its rows in the product tables, dims its summary column, and recalculates
  each product's **Total**. `Unchanged` is controlled by **Show unchanged
  rows** and is always counted in the Total.
- **Dark Mode** can be toggled with the **Dark Mode** checkbox;
  `--darkmode true` sets its default.
- Each product has its own table, in the same order as a ScubaGoggles run. A
  control whose version changed shows both IDs (`GWS.GMAIL.1.1v1 →
  GWS.GMAIL.1.1v2`).
- Rows are color-coded by Result (After) (see [Row coloring](#row-coloring)),
  and a legend explains the colors.
- All report text is HTML-escaped.

## Example workflow

```bash
# 1. Run ScubaGoggles at two points in time (or on two tenants).
scubagoggles gws -o ./runs/q1
# ... later ...
scubagoggles gws -o ./runs/q2

# 2. Compare the two ScubaResults files.
scubagoggles diff \
    --beforepath ./runs/q1/GWSBaselineConformance_<timestamp>/ScubaResults_<id>.json \
    --afterpath  ./runs/q2/GWSBaselineConformance_<timestamp>/ScubaResults_<id>.json \
    --outputpath ./runs/diff

# 3. Open ./runs/diff/DiffReport.html, or read DiffResults.json or
#    DiffResults.csv (one row per policy).
```

- Return to [Documentation Home](/README.md)
