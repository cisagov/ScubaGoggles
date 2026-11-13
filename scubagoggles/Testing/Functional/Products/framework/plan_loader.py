"""Load and validate the YAML test plans in Products/TestPlans/.

Schema problems are collected into one PlanError. Invalid YAML and duplicate
keys fail immediately with their source location.
"""

from enum import StrEnum
from functools import cache
from inspect import signature
import json
from pathlib import Path
import re

import yaml

from scubagoggles.orchestrator import Orchestrator
from scubagoggles.policy_api import PolicyAPI
from scubagoggles.Testing.Functional.Products.framework.patch_helpers import PATCH_HELPERS
from scubagoggles.Testing.Functional.Products.framework.plan_model import (
    JsonValue, LiveConfig, LiveDefaults, Outcome, Patch, PlanError, PolicyCase, PolicyPlan,
    Scope, TestDriver, WriteApi,
)
from scubagoggles.Testing.Functional.Products.framework.scuba_app import (
    PACKAGE_DIR, baseline_policy_ids,
)

_PLAN_KEYS = {'live_testing', 'live', 'cases', 'reason'}
_CASE_KEYS = {'name', 'test_driver', 'expected_result', 'settings', 'patch', 'description', 'live'}
_SETTING_KEY_RE = re.compile(r'^([a-z0-9_]+)\.([A-Za-z0-9]+)$')
_REGO_SETTING_RE = re.compile(r'"policy/([a-z0-9_]+\.[A-Za-z0-9]+)"')


# SafeLoader combines PyYAML's reader, scanner, parser and constructor classes.
# pylint: disable-next=too-many-ancestors
class _PlanLoader(yaml.SafeLoader):
    """Read safe YAML while rejecting duplicate and non-string mapping keys."""

    def construct_mapping(self, node, deep=False):
        self.flatten_mapping(node)
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise yaml.constructor.ConstructorError(
                    None, None, 'mapping keys must be strings', key_node.start_mark)
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    None, None, f'duplicate key {key!r}', key_node.start_mark)
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def load_plans(directory: Path) -> list[PolicyPlan]:
    """Load and validate every product test plan in directory."""
    plans = []
    for path in sorted(directory.glob('*.yaml')):
        plans.extend(load_plan(path))
    return plans


def load_plan(path: Path) -> list[PolicyPlan]:
    """Load one product's test plan; raise PlanError listing every problem."""
    product = path.stem
    if product not in Orchestrator.gws_products()['gws_baselines']:
        raise PlanError(f'{path.name}: name the file after a product, '
                        'e.g. commoncontrols.yaml or drive.yaml.')
    try:
        with path.open(encoding='utf-8') as stream:
            doc = yaml.load(stream, Loader=_PlanLoader)
    except yaml.YAMLError as error:
        raise PlanError(f'{path.name}: {error}') from error
    if not isinstance(doc, dict):
        raise PlanError(f'{path.name}: expected a mapping of policy IDs.')

    problems = []
    baseline_ids = baseline_policy_ids(product)
    for policy_id in sorted(baseline_ids - doc.keys(), key=_policy_sort_key):
        problems.append(f'{policy_id}: missing; every baseline policy needs an entry')
    for policy_id in sorted(doc.keys() - baseline_ids):
        problems.append(f'{policy_id}: not a policy in the {product} baseline')

    plans = []
    for policy_id, entry in doc.items():
        if policy_id in baseline_ids:
            plan = _read_policy(policy_id, product, entry, problems)
            if plan:
                plans.append(plan)
    if problems:
        details = '\n'.join(f'  - {problem}' for problem in problems)
        raise PlanError(f'{path.name} has problems:\n{details}')
    return plans


def _policy_sort_key(policy_id: str) -> list[int]:
    return [int(part) for part in policy_id.split('.')[2:]]


@cache
def _rego_settings(product: str) -> frozenset[str]:
    """Exact setting names in the product's Rego prerequisites."""
    rego_dir = PACKAGE_DIR / 'rego'
    return frozenset(key for name in (f'{product.capitalize()}.rego', 'Utils.rego')
                     for key in _REGO_SETTING_RE.findall(
                         (rego_dir / name).read_text(encoding='utf-8')))


def _read_policy(policy_id: str, product: str, entry, problems: list) -> PolicyPlan | None:
    if not isinstance(entry, dict):
        problems.append(f'{policy_id}: expected a policy mapping with '
                        'live_testing and cases/reason')
        return None
    _check_keys(policy_id, entry, _PLAN_KEYS, problems)
    live_testing = entry.get('live_testing')
    if not isinstance(live_testing, bool):
        problems.append(f'{policy_id}: live_testing must be a boolean (true or false)')
        live_testing = None
    defaults = (_read_live_defaults(entry['live'], policy_id, problems)
                if 'live' in entry else None)
    if live_testing is False and defaults is not None:
        problems.append(f'{policy_id}: live defaults require live_testing: true')
    reason = _read_text(entry, 'reason', policy_id, problems)

    cases = _read_cases(entry.get('cases', []), policy_id, product, problems,
                       live_defaults=defaults)
    if not cases and not reason.strip():
        problems.append(f'{policy_id}: add cases, or a reason explaining why there are none')

    if live_testing is None:
        return None
    for case in cases:
        if case.test_driver is not TestDriver.LIVE:
            continue
        if not live_testing:
            problems.append(f'{case.test_id}: live case requires live_testing: true')
        if case.patches:
            problems.append(f'{case.test_id}: patch helpers only apply to cached cases')
    return PolicyPlan(policy_id, product, live_testing, tuple(cases), reason, defaults)


def _read_cases(raw, policy_id: str, product: str, problems: list, *,
                live_defaults: LiveDefaults | None = None) -> list[PolicyCase]:
    if not isinstance(raw, list):
        problems.append(f'{policy_id}: cases must be a list')
        return []
    cases = []
    seen = set()
    for index, raw_case in enumerate(raw):
        case = _read_case(policy_id, product, index, raw_case, problems,
                          live_defaults=live_defaults)
        if case is None:
            continue
        if (case.test_driver, case.name) in seen:
            problems.append(f'{case.test_id}: duplicate {case.test_driver} case name')
        seen.add((case.test_driver, case.name))
        cases.append(case)
    return cases


def _read_case(policy_id: str, product: str, index: int, raw,
               problems: list, *, live_defaults: LiveDefaults | None = None) -> PolicyCase | None:
    where = f'{policy_id} case {index + 1}'
    if not isinstance(raw, dict):
        problems.append(f'{where}: expected name, test_driver and expected_result')
        return None
    name = raw.get('name')
    name_ok = isinstance(name, str) and bool(name.strip()) and name.isprintable()
    if name_ok:
        name = name.strip()
        where = f'{policy_id}-{name}'
    else:
        problems.append(f'{where}: name must be nonempty, single-line text')
    _check_keys(where, raw, _CASE_KEYS, problems)
    test_driver = _read_enum(TestDriver, raw, 'test_driver', where, problems)
    expected_result = _read_enum(Outcome, raw, 'expected_result', where, problems)
    description = _read_text(raw, 'description', where, problems)
    live = _resolve_live(raw, test_driver, live_defaults, where, problems)

    settings = _read_values(raw.get('settings', {}), 'settings', where, problems)
    for key in settings:
        problem = _setting_problem(key, product)
        if problem:
            problems.append(f'{where}: {problem}')

    patches = _read_patches(raw.get('patch'), product, where, problems)
    if not name_ok or None in (test_driver, expected_result):
        return None
    return PolicyCase(policy_id, product, name, test_driver, expected_result,
                      settings, patches, description, live)


def _read_live_defaults(raw, where: str, problems: list) -> LiveDefaults:
    """Read a policy's defaults or a live case's partial overrides."""
    where = f'{where} live'
    if not isinstance(raw, dict):
        problems.append(f'{where}: expected a mapping of write_api and/or scope')
        return LiveDefaults()
    _check_keys(where, raw, {'write_api', 'scope'}, problems)
    write_api = _read_write_api(raw, where, problems) if 'write_api' in raw else None
    scope = _read_enum(Scope, raw, 'scope', where, problems) if 'scope' in raw else None
    return LiveDefaults(write_api, scope)


def _resolve_live(raw: dict, driver: TestDriver | None, defaults: LiveDefaults | None,
                  where: str, problems: list) -> LiveConfig | None:
    """Give each live case a complete configuration; cached cases receive none."""
    if driver is not TestDriver.LIVE:
        if 'live' in raw:
            problems.append(f'{where}: case-level live configuration requires test_driver: live')
        return None
    overrides = (_read_live_defaults(raw['live'], where, problems)
                 if 'live' in raw else LiveDefaults())
    defaults = defaults or LiveDefaults()
    write_api = overrides.write_api or defaults.write_api
    scope = overrides.scope or defaults.scope
    if not write_api:
        problems.append(f'{where}: live.write_api is required for a live case')
    if scope is None:
        problems.append(f'{where}: live.scope is required for a live case (ou, group or tenant)')
    if not write_api or scope is None:
        return None
    return LiveConfig(write_api, scope)


def _read_patches(raw, product: str, where: str, problems: list) -> tuple[Patch, ...]:
    if raw is None:
        return ()
    steps = raw if isinstance(raw, list) else [raw]
    patches = []
    for index, step in enumerate(steps):
        location = f'{where} patch {index + 1}'
        if not isinstance(step, dict):
            problems.append(f'{location}: expected a helper name and optional args mapping')
            continue
        _check_keys(location, step, {'helper', 'args'}, problems)
        helper = step.get('helper')
        if not isinstance(helper, str) or helper not in PATCH_HELPERS:
            known = ', '.join(sorted(PATCH_HELPERS))
            problems.append(f'{location}: unknown patch helper {helper!r} '
                            f'(known: {known})')
            continue
        args = _read_values(step.get('args', {}), 'args', location, problems)
        try:
            signature(PATCH_HELPERS[helper]).bind({}, **args)
        except TypeError as error:
            problems.append(f'{location}: invalid arguments for {helper}: {error}')
            continue
        if helper == 'missing_setting':
            problem = _setting_problem(args.get('setting'), product)
            if problem:
                problems.append(f'{location}: {problem}')
        patches.append(Patch(helper, args))
    return tuple(patches)


def _setting_problem(key: object, product: str) -> str | None:
    match = _SETTING_KEY_RE.fullmatch(key) if isinstance(key, str) else None
    if not match:
        return f'setting {key!r} must look like setting_type.fieldName'
    section, field_name = match.groups()
    # The provider's own list of expected fields is the authoritative source.
    # pylint: disable-next=protected-access
    declared = PolicyAPI._expectedPolicySettings.get(section, {}).get('settings', {})
    if field_name in declared or key in _rego_settings(product):
        return None
    return (f'setting {key!r} is not declared in policy_api.py or named in '
            f'{product.capitalize()}.rego prerequisites; check the spelling')


def _read_values(raw: object, field: str, where: str,
                 problems: list) -> dict[str, JsonValue]:
    """Read JSON-compatible settings or patch arguments from safe YAML."""
    if not isinstance(raw, dict):
        problems.append(f'{where}: {field} must be a mapping')
        return {}
    # _PlanLoader already rejects non-string keys at every nesting level.
    try:
        json.dumps(raw, allow_nan=False)
    except (TypeError, ValueError) as error:
        problems.append(f'{where}: {field} must contain JSON values: {error}')
        return {}
    return raw


def _read_text(mapping: dict, key: str, where: str, problems: list) -> str:
    value = mapping.get(key, '')
    if not isinstance(value, str):
        problems.append(f'{where}: {key} must be text')
        return ''
    return value


def _check_keys(where: str, mapping: dict, allowed: set, problems: list):
    for key in sorted(mapping.keys() - allowed, key=str):
        problems.append(f'{where}: unknown key {key!r} (allowed: {", ".join(sorted(allowed))})')


def _read_enum(kind: type[StrEnum], mapping: dict, key: str, where: str, problems: list):
    value = mapping.get(key)
    try:
        return kind(value)
    except ValueError:
        choices = ', '.join(member.value for member in kind)
        problems.append(f'{where}: {key} must be one of: {choices} (got {value!r})')
        return None


def _read_write_api(entry: dict, where: str, problems: list) -> tuple[WriteApi, ...] | None:
    raw = entry.get('write_api')
    values = raw if isinstance(raw, list) else [raw]
    if not values:
        problems.append(f'{where}: write_api must name at least one API')
        return None
    apis = []
    for value in values:
        api = _read_enum(WriteApi, {'write_api': value}, 'write_api', where, problems)
        if api is None:
            return None
        apis.append(api)
    if len(set(apis)) != len(apis):
        problems.append(f'{where}: write_api must not repeat an API')
        return None
    return tuple(apis)
