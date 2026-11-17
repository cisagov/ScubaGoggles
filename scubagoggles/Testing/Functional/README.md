# Functional tests

Functional tests check that a given tenant configuration produces the expected
result in the ScubaGoggles report (Pass, Fail, Warning, and so on). Each case runs
ScubaGoggles in-process through the same argument parser and `Orchestrator` as
`scubagoggles gws`, so it exercises the real export, Rego, and report code. The
test then reads the policy's row from the `ScubaResults` file, which is what a
user would see.

There are two suites:

- **Product tests** (`Products/`): one case per configuration scenario, written
  as data in a YAML test plan per product.
- **Smoke tests** (`SmokeTests/`): Selenium checks of the generated HTML report.
  See the [smoke test README](SmokeTests/README.md).

```
Functional/
  conftest.py              # command-line options for both suites
  SmokeTests/              # Selenium report checks (conftest.py holds their fixtures)
  Products/
    conftest.py            # fixtures: source export, runners
    test_products.py       # one generic test; never needs editing to add cases
    TestPlans/
      commoncontrols.yaml  # one plan per product, named after the product
    framework/             # the code behind the tests; authors rarely need it
      plan_model.py        # PolicyPlan, PolicyCase, and the field enums
      plan_loader.py       # loads and validates TestPlans/*.yaml
      patch_helpers.py     # functions that edit an export for cached cases
      cached_runner.py     # the cached test driver (live_runner.py will sit beside it)
      scuba_app.py         # runs `scubagoggles gws` in-process; reads report rows
```

Run pytest against `Products/` or `SmokeTests/` directly. Running all of
`Functional/` also collects the smoke tests, which need Chrome and a tenant.

## Test drivers

Every case names its `test_driver`:

- **`cached`** loads one provider export per pytest session, gives each case a
  private copy, and applies the case's settings to that copy. It then runs
  `scubagoggles gws --runcached --skipexport` on the copy. The tenant is never
  written to. Every policy can have cached cases.
- **`live`** will change the setting in the tenant, run ScubaGoggles, and restore
  it. Live mode is not implemented yet. Live cases are only allowed on policies
  whose plan entry says `live_testing: true`. Each live case must resolve to a
  write API and a concrete scope using the shared `live` defaults and any case overrides.

`--test-driver` picks which cases run (default `cached`). Cached and live cases
for the same policy sit side by side in the same plan entry.

## Setup

From the repository root, with Python 3.11 or newer and your virtual
environment active:

```sh
python -m pip install -e . pytest pytest-mock
```

You also need the OPA executable (`scubagoggles getopa`). By default the tests
use the OPA directory saved by `scubagoggles setup`; pass `--opapath` with the
directory, not the executable, to use another one.

## Run the cached tests

Choose one option to provide the session's source export:

| Option | Behavior |
|---|---|
| `--collect` | Collect one export from the tenant using read-only API calls. |
| `--export-file <path>` | Replay an existing JSON export without Google authentication. |

`--collect` is a boolean flag: present means true, omitted means false. It takes
no value. `--export-file` takes a file path. These options are alternatives and
cannot be combined.

`--test-driver` selects how cases execute. Cached is the default driver, so it
can be omitted.

**Reuse output from an earlier run.** Pass a `ScubaResults_*.json` file (its
`Raw` section is used) or a `ProviderSettingsExport.json` from a recent
`scubagoggles gws` run. It must cover the products you're testing. The file is
read once and never modified:

```sh
python -m pytest scubagoggles/Testing/Functional/Products -v --export-file="/path/to/ScubaResults_<uuid>.json"
```

**Collect from the tenant.** This does one normal `scubagoggles gws` run per
session, using read-only API calls, for only the products the selected cases
need:

```sh
python -m pytest scubagoggles/Testing/Functional/Products -v --collect --subjectemail=admin@example.com
```

`--opapath`, `--credentials`, `--subjectemail` and `--customerid` are passed
straight to `scubagoggles gws`, so they mean the same thing and have the same
defaults as on the command line. For example, the credentials default to the
file saved by `scubagoggles setup`. Include `--subjectemail` for a service account
using domain-wide delegation; omit it for OAuth. Collection uses empty
break-glass and exclusion lists. Fresh collection cannot be combined with
pytest-xdist `-n`.

Without `--collect` or `--export-file`, cached cases are skipped. `--collect-only` lists the
cases without loading an export or contacting Google.

### Select cases

Test IDs are `<policy ID>-<driver>-<case name>`. Names can be descriptive sentences;
`-k` selects by product, policy, driver, or words in the name:

```sh
-k COMMONCONTROLS                    # one product
-k "GWS.COMMONCONTROLS.4.1-"         # one policy
-k "4.1- or 5.3-"                    # several policies
-k "session and 24"                 # the 24-hour session case
-k "minimum and 16"                 # the 16-character minimum password case
```

`-k` matches substrings, so end a policy ID with `-`: `GWS.DRIVEDOCS.1.1`
alone would also select 1.10 and 1.11. Use `and`/`or` between words when selecting
descriptive names; quoting a whole sentence does not make it an exact-name match.

## Add a test case

1. Open `Products/TestPlans/<product>.yaml` and find the policy's entry.
2. Add a case under `cases`, replacing `cases: []` with the populated list.
3. Run it: `python -m pytest scubagoggles/Testing/Functional/Products -v --export-file="<ScubaResults file>" -k "<policy ID>-"`.

```yaml
GWS.COMMONCONTROLS.4.1:  # security_session_controls
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
```

A plan mistake fails test collection with a message naming the policy and the
problem. The same checks run in the unit test suite, so they also run in CI.

### Case fields

| Field | Required | Meaning |
|---|---|---|
| `name` | Yes | Nonempty, single-line text; spaces and punctuation are accepted. Surrounding spaces are trimmed; names must be unique per policy and driver. |
| `test_driver` | Yes | `cached` or `live`. |
| `expected_result` | Yes | The report label: `Pass`, `Fail`, `Warning`, `No events found`, `N/A` or `Error`. |
| `settings` | No | `setting_type.fieldName: value` pairs. |
| `patch` | No | Named patch helpers for data that isn't a setting (cached only). |
| `description` | No | Why the case exists, when the name isn't enough. |
| `live` | For live cases when defaults are insufficient | Overrides for `write_api` and/or `scope`. Omit this block on cached cases. |

`settings` keys are the provider's exported setting names, the same names the
Rego prerequisites (`policy/security_password.minimumLength`) and the export's
`missing_policies` use. The exact section/field pair must be declared in
`policy_api.py` or named in the product's Rego prerequisites. A case can set
several fields.

Settings and patch arguments accept JSON-compatible values: strings, integers,
floats, booleans, null, lists, and dictionaries with string keys. Quote dates to
keep YAML from turning them into date objects. Duplicate YAML keys, malformed
case fields, and missing or unexpected helper arguments fail during collection.

A cached case sets each value on the top-level OU, and on any OU or group that
already overrides that setting type in the export. Views that inherit the setting
are left alone, as they would be in a real tenant. The setting's
missing/invalid marker is cleared because the case now supplies it.

Settings are applied first, then patches. Patch helpers cover data that isn't
a Policy API setting, such as log events, DNS records, directory data, or a
setting the provider couldn't read:

```yaml
    - name: Missing session duration produces an error
      test_driver: cached
      expected_result: Error
      patch:
        - helper: missing_setting
          args: {setting: security_session_controls.webSessionDuration}
```

To add a helper, write a function in `Products/framework/patch_helpers.py` that takes the
export dict followed by keyword arguments, changes the export in place, and is
decorated with `@patch_helper`. Plans can then name it.
Plan loading validates the `missing_setting` helper's setting name using the
same rules as `settings`.

`N/A` and `No events found` are valid expected results. An `N/A` case only checks
that an unimplemented policy is reported as such; it doesn't test the policy.

### Policy fields

Every policy in the product's baseline needs an entry, even without cases. Each
entry records its live-testing configuration and any implemented cases.

| Field | Values | Meaning |
|---|---|---|
| `live_testing` | `true` or `false` (required boolean) | Whether the team permits live cases for this policy. Use an unquoted YAML boolean, not `allowed`, `denied`, `"true"`, or `"false"`. |
| `live` | Optional mapping | Shared `write_api` and/or `scope` defaults for live cases. Requires `live_testing: true`. Cached-only policies do not need this block. |
| `cases` | list | The policy's cases. Use `[]` when no cases are implemented. |

An empty list creates no tests for that policy. Omitting `cases` also defaults
to an empty list. If present, it must be a list; use `cases: []` rather than a
bare `cases:` key, which YAML reads as null.

```yaml
GWS.COMMONCONTROLS.1.1:
  live_testing: false
  cases: []
```

### Shared live configuration

`live_testing: true` records permission to define live cases. It does not mean a
write API is available or enable the unfinished live runner. A placeholder policy
can have `live_testing: true` without a `live` block.

Both policy-level `live` defaults and case-level `live` overrides accept:

| Field | Values | Meaning |
|---|---|---|
| `write_api` | `policy_api`, `directory_api`, `cloud_identity_api`, `group_settings_api`, or a nonempty list of these | APIs used by the live case. A case override replaces the entire default API list. |
| `scope` | `ou`, `group`, `tenant` | The concrete scope for this scenario. Choose a scope the policy supports; `ou_group` and `unknown` are not execution scopes. |

The loader merges these fields for each live case and requires both to be known.
A case can supply all its live configuration or inherit either field. Missing
fields are acceptable in policy defaults until a live case needs them. Cached
cases do not inherit live configuration. Live cases cannot use patch helpers.

For a policy that supports OU and group changes, an entry could contain:

```yaml
live_testing: true
live:
  write_api: [policy_api]
  scope: ou
cases:
  - name: Cached compliant configuration
    test_driver: cached
    expected_result: Pass
  - name: Compliant configuration in an organizational unit
    test_driver: live
    expected_result: Pass
    # Inherits both API and scope.
  - name: Compliant configuration in a group
    test_driver: live
    expected_result: Pass
    live:
      scope: group
      # Inherits the API; overrides only the scope.
```

Case overrides cannot change the policy's `live_testing` decision. Policies with
`live_testing: false` reject live defaults and live cases. API names, scopes and
test drivers remain named choices because they select behavior rather than
enable or disable it.

### Add a product

Create `Products/TestPlans/<product>.yaml`, named with the product name
ScubaGoggles uses (`drive` for DRIVEDOCS), with an entry for every policy in
that product's baseline. Collection lists any policy IDs that are missing.

## Inspect results

Each cached case writes normal ScubaGoggles output for its product to its pytest
temporary directory. That includes `ScubaResults_*.json` (its `Raw` section is the
patched export), the HTML reports, `TestResults.json` and the CSV files.

A failing assertion prints the product's HTML report path. Results are read from
the directory returned by that run, without searching earlier report directories.
A fresh collection's output, including its unpatched export, is saved under a `cached-source`
temporary directory. Exports and reports
made from a real tenant are tenant data; don't commit them.

## Framework unit tests

The framework's own tests run without OPA or Google credentials. They cover:
- plan validation, including the checked-in plans;
- applying settings and patches;
- case isolation and the single collection per session;
- report outcomes, including prerequisite errors.

```sh
python -m pytest scubagoggles/Testing/Unit/Python/test_functional_framework.py -v
```
