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
  whose plan entry says `live_testing: allowed` and names a `write_api`.

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

Cached cases need a source export from a real tenant. There are two ways to get
one.

**Reuse output from an earlier run.** Pass a `ScubaResults_*.json` file (its
`Raw` section is used) or a `ProviderSettingsExport.json` from a recent
`scubagoggles gws` run. It must cover the products you're testing. The file is
read once and never modified:

```sh
python -m pytest scubagoggles/Testing/Functional/Products -v --cached-export=/path/to/ScubaResults_<uuid>.json
```

**Collect from the tenant.** This does one normal `scubagoggles gws` run per
session, using read-only API calls, for only the products the selected cases
need:

```sh
python -m pytest scubagoggles/Testing/Functional/Products -v --cached-collect --subjectemail=admin@example.com
```

`--opapath`, `--credentials`, `--subjectemail` and `--customerid` are passed
straight to `scubagoggles gws`, so they mean the same thing and have the same
defaults as on the command line. For example, the credentials default to the
file saved by `scubagoggles setup`. Include `--subjectemail` for a service account
using domain-wide delegation; omit it for OAuth. Collection uses empty
break-glass and exclusion lists. It cannot be combined with `--cached-export` or
with pytest-xdist `-n`.

Without `--cached-export` or `--cached-collect`, cached cases are skipped.

### Select cases

Test IDs are `<policy ID>-<case name>`, so `-k` selects by product, policy, or case:

```sh
-k COMMONCONTROLS                    # one product
-k "GWS.COMMONCONTROLS.4.1-"         # one policy
-k "4.1- or 5.3-"                    # several policies
-k session_24h                       # one case
```

`-k` matches substrings, so end a policy ID with `-`: `GWS.DRIVEDOCS.1.1`
alone would also select 1.10 and 1.11.

## Add a test case

1. Open `Products/TestPlans/<product>.yaml` and find the policy's entry.
2. Add a case under `cases`. If the entry only has a `reason` because cases were
   not written yet, remove the `reason`.
3. Run it: `python -m pytest scubagoggles/Testing/Functional/Products -v --cached-export=<ScubaResults file> -k "<policy ID>-"`.

```yaml
GWS.COMMONCONTROLS.4.1:  # security_session_controls
  live_testing: denied
  write_api: unknown
  scope: unknown
  cases:
    - name: session_12h
      test_driver: cached
      expected_result: Pass
      settings:
        security_session_controls.webSessionDuration: 43200s
    - name: session_24h
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
| `name` | Yes | Lowercase letters, digits and underscores; unique per policy and driver. |
| `test_driver` | Yes | `cached` or `live`. |
| `expected_result` | Yes | The report label: `Pass`, `Fail`, `Warning`, `No events found`, `N/A` or `Error`. |
| `settings` | No | `setting_type.fieldName: value` pairs. |
| `patch` | No | Named patch helpers for data that isn't a setting (cached only). |
| `description` | No | Why the case exists, when the name isn't enough. |

`settings` keys are the provider's exported setting names, the same names the
Rego prerequisites (`policy/security_password.minimumLength`) and the export's
`missing_policies` use. A key must be declared in `policy_api.py` or used by the
product's Rego file, which catches misspellings. A case can set several fields.

A cached case sets each value on the top-level OU, and on any OU or group that
already overrides that setting type in the export. Views that inherit the setting
are left alone, as they would be in a real tenant. The setting's
missing/invalid marker is cleared because the case now supplies it.

Settings are applied first, then patches. Patch helpers cover data that isn't
a Policy API setting, such as log events, DNS records, directory data, or a
setting the provider couldn't read:

```yaml
    - name: session_duration_missing
      test_driver: cached
      expected_result: Error
      patch:
        - helper: missing_setting
          args: {setting: security_session_controls.webSessionDuration}
```

To add a helper, write a function in `Products/framework/patch_helpers.py` that takes the
export dict followed by keyword arguments, changes the export in place, and is
decorated with `@patch_helper`. Plans can then name it.

`N/A` and `No events found` are valid expected results. An `N/A` case only checks
that an unimplemented policy is reported as such; it doesn't test the policy.

### Policy fields

Every policy in the product's baseline needs an entry, even without cases. That
entry is the policy's coverage decision.

| Field | Values | Meaning |
|---|---|---|
| `live_testing` | `allowed`, `denied` | Whether the team allows this policy's settings to change in the tenant (allowlist vs denylist). |
| `write_api` | `none`, `unknown`, `policy_api`, `directory_api`, `cloud_identity_api`, `group_settings_api`, or a list | The API that can change the setting. |
| `scope` | `ou_group`, `ou`, `tenant`, `unknown` | Where the setting can be applied. Use `unknown` unless the docs or the Admin console confirm it. |
| `cases` | list | The policy's cases. |
| `reason` | text | Required when there are no cases, e.g. `Not-Implemented in Rego.` |

A `live` case requires `live_testing: allowed` and a `write_api` other than
`none` or `unknown`, and can't use patch helpers.

### Add a product

Create `Products/TestPlans/<product>.yaml`, named with the product name
ScubaGoggles uses (`drive` for DRIVEDOCS), with an entry for every policy in
that product's baseline. Collection lists any policy IDs that are missing.

## Inspect results

Each cached case writes normal ScubaGoggles output for its product to its pytest
temporary directory. That includes `ScubaResults_*.json` (its `Raw` section is the
patched export), the HTML reports, `TestResults.json` and the CSV files.

A failing assertion prints the product's HTML report path. A fresh collection's
output, including its unpatched export, is saved under a `cached-source`
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
