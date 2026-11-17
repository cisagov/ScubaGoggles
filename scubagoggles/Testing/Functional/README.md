# Functional tests

Product tests verify that a configuration produces the expected result in the
ScubaGoggles report. Cases are defined in YAML under `Products/TestPlans/`.
The [Common Controls plan](Products/TestPlans/commoncontrols.yaml) includes
examples for policies 4.1 and 5.3.

Cached execution loads one provider export per session, applies each case to an
isolated copy, and runs the ScubaGoggles evaluator and report generator. It does
not modify tenant settings. Live execution is not implemented; `--test-driver=live`
is rejected.

[Smoke tests](SmokeTests/README.md) validate generated HTML reports using Selenium.
Run `Products/` or `SmokeTests/` separately; selecting all of `Functional/` also
collects smoke tests and requires their browser and tenant setup.

## Setup

Use Python 3.11 or newer and an activated virtual environment. Run commands from
the repository root:

```sh
python -m pip install -e . "pytest>=9" pytest-mock
```

Install OPA with `scubagoggles getopa`. Tests use the OPA directory saved by
`scubagoggles setup`, or the directory supplied through `--opapath`.

## Run product tests

Choose one source option. Providing both is an error; providing neither skips
cached cases. Cached is the default test driver.

| Option | Behavior |
|---|---|
| `--export-file <path>` | Read an existing JSON export without Google authentication. |
| `--collect` | Collect one export from Google using read-only API calls. This boolean flag takes no value. |

### Existing export

Supply a `ScubaResults_*.json` file or `ProviderSettingsExport.json`, not a report
directory. For a ScubaResults file, the framework reads its `Raw` section. The
export must contain data for the products being tested; the source file is never
modified.

```sh
python -m pytest scubagoggles/Testing/Functional/Products -v --export-file="path/to/ScubaResults.json"
```

### Fresh collection

Collection runs once for the products selected by the test cases. For a service
account using domain-wide delegation:

```sh
python -m pytest scubagoggles/Testing/Functional/Products -v --collect --credentials="path/to/credentials.json" --subjectemail=admin@example.com
```

Omit `--subjectemail` for OAuth. `--credentials` and `--opapath` use the defaults
saved by `scubagoggles setup` when omitted. `--customerid` is also supported.
These options have the same meaning as their `scubagoggles gws` equivalents.

Fresh collection uses empty break-glass and exclusion lists and must run
serially; it cannot be combined with pytest-xdist `-n`.

### Select or list cases

To run only Common Controls 4.1, append `-k` to either source command:

```sh
python -m pytest scubagoggles/Testing/Functional/Products -v --export-file="path/to/ScubaResults.json" -k "GWS.COMMONCONTROLS.4.1-"
```

Test IDs follow `<policy ID>-<driver>-<case name>`. Additional selectors include:

| Selection | Argument |
|---|---|
| Common Controls | `-k COMMONCONTROLS` |
| Policies 4.1 and 5.3 | `-k "GWS.COMMONCONTROLS.4.1- or GWS.COMMONCONTROLS.5.3-"` |
| 24-hour session case | `-k "session and 24"` |

`-k` matches substrings. Include the trailing `-` after a policy ID to distinguish
IDs such as 1.1 and 1.10. Use `and` or `or` to select words in descriptive names.

List cases and validate plans without loading an export or contacting Google:

```sh
python -m pytest scubagoggles/Testing/Functional/Products --collect-only -q
```

A pytest case passes when the report matches `expected_result`, including when
the expected report result is `Fail`, `Warning`, or `Error`.

## Author test plans

Create or edit `Products/TestPlans/<product>.yaml`, using the application's product
name (`drive` for DRIVEDOCS). Each policy in that product's baseline needs an
entry. Use `cases: []` for policies without tests; omitting `cases` also defaults
to an empty list.

```yaml
GWS.COMMONCONTROLS.1.1:
  live_testing: false
  cases: []

GWS.COMMONCONTROLS.4.1:
  live_testing: false
  cases:
    - name: Session duration of 12 hours is compliant
      test_driver: cached
      expected_result: Pass
      settings:
        security_session_controls.webSessionDuration: 43200s
    - name: Session duration of 24 hours is noncompliant
      test_driver: cached
      expected_result: Fail
      settings:
        security_session_controls.webSessionDuration: 86400s
    - name: Missing session duration produces an error
      test_driver: cached
      expected_result: Error
      patch:
        - helper: missing_setting
          args:
            setting: security_session_controls.webSessionDuration
```

### Policy fields

| Field | Requirement | Description |
|---|---|---|
| `live_testing` | Required boolean | Whether live cases are permitted. Use unquoted `true` or `false`. Cached cases are permitted with either value. |
| `cases` | Optional list | Scenarios for this policy. Use `[]` for an empty list; a bare `cases:` key is null and invalid. |
| `live` | Optional mapping | Defaults for live cases; requires `live_testing: true`. |

### Case fields

| Field | Requirement | Description |
|---|---|---|
| `name` | Required string | Nonempty, printable, single-line name, unique within the policy and driver. Surrounding spaces are trimmed. |
| `test_driver` | Required | `cached` or `live`; only cached execution is available. |
| `expected_result` | Required | `Pass`, `Fail`, `Warning`, `No events found`, `N/A`, or `Error`. |
| `settings` | Optional mapping | Exported `setting_type.fieldName` keys and their values. |
| `patch` | Optional list | Registered patch helpers and arguments; cached cases only. |
| `description` | Optional string | Additional context for the scenario. |
| `live` | Optional mapping | Live-case overrides for `write_api` and `scope`. Invalid on cached cases. |

Malformed plans fail during collection, including duplicate or unknown keys,
invalid setting names, and missing or unexpected helper arguments. The unit
suite also validates checked-in plans.

An `N/A` assertion verifies reporting for an unimplemented policy; it does not
establish coverage of its configuration requirements.

### Settings and patches

Setting keys must be declared in `policy_api.py` or in the product's Rego
prerequisites. Settings and patch arguments accept JSON-compatible values,
including nested lists and mappings with string keys. Quote date strings to
prevent YAML date conversion.

A setting is applied to the top-level OU and any OU or group that already
contains that setting section. Inheriting views remain unchanged, and the
setting's missing-data marker is cleared.

Patches run after settings. The `missing_setting` helper removes a top-level OU
field and marks it missing. Other export structures, such as log events, DNS
records, or sections containing rule lists, require an appropriate patch helper.
Add helpers to `framework/patch_helpers.py`, decorate them with `@patch_helper`,
and accept the export dictionary followed by keyword arguments. Helpers modify
the case's export copy in place.

### Live-case configuration

Plans can contain cached and live cases together, although live execution is
unavailable. `live_testing: true` permits live cases; it does not establish API
availability. Policies with `live_testing: false` reject live defaults and cases.

Policy-level `live` defaults and case-level overrides support:

| Field | Values |
|---|---|
| `write_api` | `policy_api`, `directory_api`, `cloud_identity_api`, or `group_settings_api`; accepts one name or a nonempty list of unique names. |
| `scope` | `ou`, `group`, or `tenant`. |

Each live case must resolve both fields. An override replaces only its supplied
field; a `write_api` override replaces the entire API list. Policies without live
cases may omit either default. Cached cases do not inherit live configuration,
and live cases cannot use patch helpers.

## Results

Each case writes JSON, HTML, and CSV output to its pytest temporary directory.
The `Raw` section of `ScubaResults_*.json` contains the patched export. Assertion
failures include the policy's HTML report path. Fresh collection saves its
unpatched output in a separate `cached-source` temporary directory.

Reports and exports collected from a tenant contain tenant data and must not be
committed to the repository.

## Framework unit tests

These tests cover plan validation, export isolation, session acquisition, and
report assertions. They require neither OPA nor Google credentials.

```sh
python -m pytest scubagoggles/Testing/Unit/Python/test_functional_framework.py -v
```

## Directory layout

```text
Functional/
  conftest.py
  SmokeTests/
  Products/
    conftest.py
    test_products.py
    TestPlans/
      commoncontrols.yaml
    framework/
      plan_model.py
      plan_loader.py
      patch_helpers.py
      cached_runner.py
      scuba_app.py
```
