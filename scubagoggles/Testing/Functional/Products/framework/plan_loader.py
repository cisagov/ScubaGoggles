"""Load and validate the YAML test plans in Products/TestPlans/.

Every problem in a plan is collected and raised as one PlanError, so a test
author sees all of them in a single run.
"""

from enum import StrEnum
from functools import cache
from pathlib import Path
import re

import yaml

from scubagoggles.orchestrator import Orchestrator
from scubagoggles.policy_api import PolicyAPI
from scubagoggles.Testing.Functional.Products.framework.patch_helpers import PATCH_HELPERS
from scubagoggles.Testing.Functional.Products.framework.plan_model import (
    LiveTesting, Outcome, Patch, PlanError, PolicyCase, PolicyPlan, Scope, TestDriver, WriteApi,
)
from scubagoggles.Testing.Functional.Products.framework.scuba_app import (
    PACKAGE_DIR, baseline_policy_ids,
)

_PLAN_KEYS = {'live_testing', 'write_api', 'scope', 'cases', 'reason'}
_CASE_KEYS = {'name', 'test_driver', 'expected_result', 'settings', 'patch', 'description'}
_CASE_NAME_RE = re.compile(r'^[a-z0-9_]+$')
_SETTING_KEY_RE = re.compile(r'^([a-z0-9_]+)\.([A-Za-z0-9]+)$')


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
    with path.open(encoding='utf-8') as stream:
        doc = yaml.safe_load(stream) or {}
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
def _rego_text(product: str) -> str:
    rego_dir = PACKAGE_DIR / 'rego'
    return ''.join((rego_dir / name).read_text(encoding='utf-8')
                   for name in (f'{product.capitalize()}.rego', 'Utils.rego'))


def _read_policy(policy_id: str, product: str, entry, problems: list) -> PolicyPlan | None:
    if not isinstance(entry, dict):
        problems.append(f'{policy_id}: expected live_testing, write_api, scope and cases')
        return None
    _check_keys(policy_id, entry, _PLAN_KEYS, problems)
    live_testing = _read_enum(LiveTesting, entry, 'live_testing', policy_id, problems)
    write_api = _read_write_api(entry, policy_id, problems)
    scope = _read_enum(Scope, entry, 'scope', policy_id, problems)

    cases = []
    for index, raw_case in enumerate(entry.get('cases') or []):
        case = _read_case(policy_id, product, index, raw_case, problems)
        if case:
            cases.append(case)
    seen = set()
    for case in cases:
        if (case.test_driver, case.name) in seen:
            problems.append(f'{case.test_id}: duplicate {case.test_driver} case name')
        seen.add((case.test_driver, case.name))
    if not cases and not entry.get('reason'):
        problems.append(f'{policy_id}: add cases, or a reason explaining why there are none')

    if live_testing is None or write_api is None or scope is None:
        return None
    for case in cases:
        if case.test_driver is not TestDriver.LIVE:
            continue
        if live_testing is not LiveTesting.ALLOWED:
            problems.append(f'{case.test_id}: live case, but live_testing is {live_testing}')
        if WriteApi.NONE in write_api or WriteApi.UNKNOWN in write_api:
            problems.append(f'{case.test_id}: live case, but write_api is {write_api[0]}')
        if case.patches:
            problems.append(f'{case.test_id}: patch helpers only apply to cached cases')
    return PolicyPlan(policy_id, product, live_testing, write_api, scope,
                      tuple(cases), entry.get('reason') or '')


def _read_case(policy_id: str, product: str, index: int, raw,
               problems: list) -> PolicyCase | None:
    where = f'{policy_id} case {index + 1}'
    if not isinstance(raw, dict):
        problems.append(f'{where}: expected name, test_driver and expected_result')
        return None
    name = raw.get('name')
    name_ok = isinstance(name, str) and bool(_CASE_NAME_RE.match(name))
    if name_ok:
        where = f'{policy_id}-{name}'
    else:
        problems.append(f'{where}: name must use lowercase letters, digits and underscores')
    _check_keys(where, raw, _CASE_KEYS, problems)
    test_driver = _read_enum(TestDriver, raw, 'test_driver', where, problems)
    expected_result = _read_enum(Outcome, raw, 'expected_result', where, problems)

    settings = raw.get('settings') or {}
    if not isinstance(settings, dict):
        problems.append(f'{where}: settings must map setting_type.fieldName to a value')
        settings = {}
    for key in settings:
        problem = _setting_problem(str(key), product)
        if problem:
            problems.append(f'{where}: {problem}')

    patches = _read_patches(raw.get('patch'), where, problems)
    if not name_ok or None in (test_driver, expected_result, patches):
        return None
    return PolicyCase(policy_id, product, name, test_driver, expected_result,
                      settings, patches, raw.get('description') or '')


def _read_patches(raw, where: str, problems: list) -> tuple[Patch, ...] | None:
    if raw is None:
        return ()
    steps = raw if isinstance(raw, list) else [raw]
    patches = []
    for step in steps:
        if not isinstance(step, dict) or not isinstance(step.get('args', {}), dict):
            problems.append(f'{where}: each patch needs a helper name and optional args mapping')
            return None
        if step.get('helper') not in PATCH_HELPERS:
            known = ', '.join(sorted(PATCH_HELPERS))
            problems.append(f'{where}: unknown patch helper {step.get("helper")!r} '
                            f'(known: {known})')
            return None
        patches.append(Patch(step['helper'], step.get('args', {})))
    return tuple(patches)


def _setting_problem(key: str, product: str) -> str | None:
    match = _SETTING_KEY_RE.match(key)
    if not match:
        return f'setting {key!r} must look like setting_type.fieldName'
    section, field_name = match.groups()
    # The provider's own list of expected fields is the authoritative source.
    # pylint: disable-next=protected-access
    declared = PolicyAPI._expectedPolicySettings.get(section, {}).get('settings', {})
    rego = _rego_text(product)
    if field_name in declared or (section in rego and field_name in rego):
        return None
    return (f'setting {key!r} is not declared in policy_api.py or used by '
            f'{product.capitalize()}.rego; check the spelling')


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
    apis = []
    for value in values:
        api = _read_enum(WriteApi, {'write_api': value}, 'write_api', where, problems)
        if api is None:
            return None
        apis.append(api)
    if len(apis) > 1 and ({WriteApi.NONE, WriteApi.UNKNOWN} & set(apis)):
        problems.append(f'{where}: write_api none/unknown cannot be combined with an API')
        return None
    return tuple(apis)
