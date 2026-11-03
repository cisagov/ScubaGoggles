"""Functional test framework guarantees: plans, acquisition, isolation, and
real report outcomes."""

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from scubagoggles import orchestrator
from scubagoggles.Testing.Functional.Products.framework import cached_runner
from scubagoggles.Testing.Functional.Products.framework.cached_runner import (
    CachedRunner, collect_export, load_export,
)
from scubagoggles.Testing.Functional.Products.framework.patch_helpers import (
    PATCH_HELPERS, missing_setting, set_setting,
)
from scubagoggles.Testing.Functional.Products.framework.plan_loader import load_plan, load_plans
from scubagoggles.Testing.Functional.Products.framework.plan_model import (
    Outcome, Patch, PlanError, PolicyCase, TestDriver,
)
from scubagoggles.Testing.Functional.Products.framework.scuba_app import baseline_policy_ids

pytest_plugins = ['pytester']
PRODUCTS_DIR = Path(cached_runner.__file__).parent.parent
FUNCTIONAL_DIR = PRODUCTS_DIR.parent
PLAN_FILE = PRODUCTS_DIR / 'TestPlans' / 'commoncontrols.yaml'


@pytest.fixture(name='source_export')
def source_export_fixture():
    """A minimal synthetic export: enough for the Orchestrator and reporter to
    run Common Controls, with no tenant data."""
    settings = {'security_session_controls': {'webSessionDuration': '86400s'},
                'security_password': {'minimumLength': 8}}
    return {
        'tenant_info': {'ID': 'synthetic-customer', 'domain': 'example.invalid',
                        'topLevelOU': 'Example'},
        'policies': {'Example': deepcopy(settings), 'Example child': deepcopy(settings)},
        'successful_calls': [],
        'unsuccessful_calls': [],
        'missing_policies': [],
        'commoncontrols_logs': {'items': []},
        'organizational_units': {'organizationUnits': []},
        'organizational_unit_names': ['Example', 'Example child'],
        'super_admins': [],
        'privileged_users': [],
        'inbound_sso_assignments': [],
        'privileged_users_error': None,
        'inbound_sso_assignments_error': None,
        'group_settings': [],
        'license_data': [],
        'break_glass_accounts': [],
        'report_uuid': '00000000-0000-0000-0000-000000000000',
    }


@pytest.fixture(name='case')
def case_fixture():
    """One implemented policy; the runner resolves its current version."""
    return PolicyCase('GWS.COMMONCONTROLS.4.1', 'commoncontrols', 'example',
                      TestDriver.CACHED, Outcome.PASS)


@pytest.fixture(name='evaluator')
def evaluator_fixture(monkeypatch):
    """Fake only OPA; run the real Orchestrator, baseline parser and reporter."""
    inputs = []
    test = {'Criticality': 'Shall', 'RequirementMet': True, 'NoSuchEvent': False,
            'ReportDetails': 'Example details', 'ActualValue': {},
            'Prerequisites': ['policy/security_session_controls.webSessionDuration']}

    def evaluate(_product, input_file, _opa_dir, _rego_dir, _debug):
        data = json.loads(Path(input_file).read_text(encoding='utf-8'))
        inputs.append(data)
        policy_id = 'GWS.COMMONCONTROLS.4.1'
        suffix = data['baseline_versions'].get(policy_id, data['baseline_suffix'])
        return [[dict(test, PolicyId=policy_id + suffix)]]

    monkeypatch.setattr(orchestrator, 'opa_eval', evaluate)
    monkeypatch.setattr(orchestrator, 'find_opa', lambda _opa_dir: None)
    return inputs, test


# ---------------------------------------------------------------------------
# Test plans
# ---------------------------------------------------------------------------

def test_repository_plans_are_valid():
    """Every checked-in plan loads and gives each baseline policy a decision."""
    plans = load_plans(PLAN_FILE.parent)
    covered = {plan.policy_id for plan in plans if plan.product == 'commoncontrols'}
    assert covered == baseline_policy_ids('commoncontrols')


def write_plan(tmp_path, edit) -> Path:
    """Copy the real Common Controls plan with one edit applied."""
    doc = yaml.safe_load(PLAN_FILE.read_text(encoding='utf-8'))
    edit(doc)
    path = tmp_path / 'commoncontrols.yaml'
    path.write_text(yaml.safe_dump(doc), encoding='utf-8')
    return path


def first_case(doc, policy_id='GWS.COMMONCONTROLS.4.1') -> dict:
    """The first case of a policy entry, for editing."""
    return doc[policy_id]['cases'][0]


def add_case(policy_id, **case):
    """An edit that appends a case to a policy entry."""
    def edit(doc):
        doc[policy_id].setdefault('cases', []).append(
            {'name': 'added', 'test_driver': 'cached', 'expected_result': 'Pass', **case})
    return edit


@pytest.mark.parametrize('edit,message', [
    (lambda doc: doc.pop('GWS.COMMONCONTROLS.9.1'),
     'GWS.COMMONCONTROLS.9.1: missing'),
    (lambda doc: doc.update({'GWS.GMAIL.1.1': doc['GWS.COMMONCONTROLS.9.1']}),
     'not a policy in the commoncontrols baseline'),
    (lambda doc: first_case(doc).update(expected_result='Passed'),
     'expected_result must be one of'),
    (lambda doc: first_case(doc).update(expected='Pass'),
     "unknown key 'expected'"),
    (lambda doc: first_case(doc).update(name='Session 12h'),
     'name must use lowercase'),
    (lambda doc: first_case(doc).update(settings={'security_password.minLength': 16}),
     'is not declared in policy_api.py'),
    (lambda doc: first_case(doc).update(settings={'security_password': 16}),
     'must look like setting_type.fieldName'),
    (lambda doc: first_case(doc).update(patch=[{'helper': 'no_such_helper'}]),
     'unknown patch helper'),
    (add_case('GWS.COMMONCONTROLS.4.1', name='session_12h'),
     'duplicate cached case name'),
    (lambda doc: doc['GWS.COMMONCONTROLS.9.1'].pop('reason'),
     'add cases, or a reason'),
    (lambda doc: doc['GWS.COMMONCONTROLS.9.1'].update(scope='everywhere'),
     'scope must be one of'),
    (lambda doc: doc['GWS.COMMONCONTROLS.6.2'].update(write_api=['none', 'policy_api']),
     'cannot be combined'),
])
def test_plan_problems_are_reported(tmp_path, edit, message):
    """Plan mistakes fail at collection with a message naming the policy."""
    with pytest.raises(PlanError, match=message):
        load_plan(write_plan(tmp_path, edit))


@pytest.mark.parametrize('policy_id,case,message', [
    ('GWS.COMMONCONTROLS.4.1', {}, 'live_testing is denied'),
    ('GWS.COMMONCONTROLS.2.1', {}, 'write_api is none'),
    ('GWS.COMMONCONTROLS.6.2',
     {'patch': {'helper': 'missing_setting', 'args': {'setting': 'a.b'}}},
     'patch helpers only apply to cached cases'),
])
def test_live_cases_need_an_allowed_writable_policy(tmp_path, policy_id, case, message):
    """The policy-level fields are guard rails for live cases."""
    edit = add_case(policy_id, test_driver='live', **case)
    with pytest.raises(PlanError, match=message):
        load_plan(write_plan(tmp_path, edit))


def test_live_and_cached_cases_share_a_policy(tmp_path):
    """An allowed, writable policy can hold both kinds of case."""
    path = write_plan(tmp_path, add_case('GWS.COMMONCONTROLS.6.2', test_driver='live'))
    plan = next(plan for plan in load_plan(path) if plan.policy_id == 'GWS.COMMONCONTROLS.6.2')
    assert [case.test_driver for case in plan.cases] == [TestDriver.LIVE]


def test_all_plan_problems_reported_together(tmp_path):
    """Authors see every problem in one run, not one at a time."""
    def edit(doc):
        doc.pop('GWS.COMMONCONTROLS.9.1')
        first_case(doc).update(expected_result='Passed')
    with pytest.raises(PlanError) as error:
        load_plan(write_plan(tmp_path, edit))
    assert 'GWS.COMMONCONTROLS.9.1: missing' in str(error.value)
    assert 'expected_result must be one of' in str(error.value)


def test_plan_file_must_be_named_after_a_product(tmp_path):
    """The file name is the product, so it must be one ScubaGoggles knows."""
    path = tmp_path / 'common.yaml'
    path.write_text('{}', encoding='utf-8')
    with pytest.raises(PlanError, match='name the file after a product'):
        load_plan(path)


# ---------------------------------------------------------------------------
# Export editing
# ---------------------------------------------------------------------------

def test_set_setting_follows_inheritance(source_export):
    """Top-level OU and existing overrides change; inheriting views do not."""
    source_export['policies']['Inherits'] = {}
    source_export['policies']['group@example.invalid'] = {'other_setting': {}}
    source_export['missing_policies'] = [
        'security_password.minimumLength', 'security_session_controls.webSessionDuration']
    source_export['unsuccessful_calls'] = ['reports/v1/activities/list']

    set_setting(source_export, 'security_password.minimumLength', 16)

    policies = source_export['policies']
    assert policies['Example']['security_password']['minimumLength'] == 16
    assert policies['Example child']['security_password']['minimumLength'] == 16
    assert policies['Inherits'] == {}
    assert policies['group@example.invalid'] == {'other_setting': {}}
    assert source_export['missing_policies'] == ['security_session_controls.webSessionDuration']
    assert source_export['unsuccessful_calls'] == ['reports/v1/activities/list']


def test_set_setting_needs_top_level_ou(source_export):
    """No top-level policies must not silently become a vacuous pass."""
    source_export['policies'] = {}
    with pytest.raises(ValueError, match='top-level OU'):
        set_setting(source_export, 'security_password.minimumLength', 16)


def test_missing_setting_marks_top_level_field(source_export):
    """The helper mirrors how the provider reports an unreadable field."""
    missing_setting(source_export, 'security_password.minimumLength')
    assert 'minimumLength' not in source_export['policies']['Example']['security_password']
    assert source_export['missing_policies'] == ['security_password.minimumLength']


# ---------------------------------------------------------------------------
# Exports and the cached runner
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('wrapped', [False, True])
def test_load_export_formats(tmp_path, source_export, wrapped):
    """Support both raw provider files and the application result wrapper."""
    path = tmp_path / 'export.json'
    path.write_text(json.dumps({'Raw': source_export} if wrapped else source_export))
    assert load_export(path) == source_export


@pytest.mark.parametrize('data', [[], {}, {'policies': []}, {'Raw': []}, 'no_uuid'])
def test_reject_malformed_export(tmp_path, source_export, data):
    """Malformed snapshots fail before they can yield misleading policy passes."""
    if data == 'no_uuid':
        data = {key: value for key, value in source_export.items() if key != 'report_uuid'}
    path = tmp_path / 'export.json'
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        load_export(path)


def test_collect_export_runs_scubagoggles(tmp_path, monkeypatch, source_export, evaluator):
    """Collection is a normal `scubagoggles gws` run; its export keeps failure metadata."""
    provider = MagicMock()
    provider.__enter__.return_value = provider
    provider.call_gws_providers.return_value = deepcopy(source_export)
    provider.successful_calls = {'read/success'}
    provider.unsuccessful_calls = {'read/failure'}
    provider.missing_policies = {'security_password.minimumLength'}
    factory = MagicMock(return_value=provider)
    monkeypatch.setattr(orchestrator, 'Provider', factory)
    credentials = tmp_path / 'credentials.json'
    credentials.write_text('{}', encoding='utf-8')

    result = collect_export(tmp_path / 'collect', ['commoncontrols'],
                            ['--credentials', str(credentials), '--customerid', 'C0123'])

    assert factory.call_args.args == ('C0123', credentials)
    provider.call_gws_providers.assert_called_once_with(['commoncontrols'], True)
    assert result['unsuccessful_calls'] == ['read/failure']
    assert result['missing_policies'] == ['security_password.minimumLength']
    assert len(evaluator[0]) == 1


def test_cases_and_caller_cannot_mutate_snapshot(tmp_path, source_export, case, evaluator):
    """One case's settings and later caller mutations never reach another case."""
    original = deepcopy(source_export)
    runner = CachedRunner(source_export)
    source_export['tenant_info']['topLevelOU'] = 'Changed outside runner'

    patched = replace(case, settings={'security_password.minimumLength': 99})
    runner.run(patched, tmp_path / 'patched').assert_expected(case)
    runner.run(case, tmp_path / 'original').assert_expected(case)
    inputs, _ = evaluator
    assert inputs[0]['policies']['Example']['security_password']['minimumLength'] == 99
    for key in ('tenant_info', 'policies', 'successful_calls'):
        assert inputs[1][key] == original[key]
    assert source_export['policies'] == original['policies']


def test_failed_patch_does_not_contaminate_next_case(tmp_path, source_export, case,
                                                     evaluator, monkeypatch):
    """A patch helper that raises still leaves the runner's source intact."""
    def broken(data):
        data['policies'].clear()
        raise RuntimeError('broken patch')
    monkeypatch.setitem(PATCH_HELPERS, 'broken', broken)
    runner = CachedRunner(source_export)

    with pytest.raises(RuntimeError, match='broken patch'):
        runner.run(replace(case, patches=(Patch('broken'),)), tmp_path / 'broken')
    runner.run(case, tmp_path / 'next')
    assert evaluator[0][0]['policies'] == source_export['policies']


@pytest.mark.parametrize('criticality,met,no_events,expected', [
    ('Shall', True, False, Outcome.PASS),
    ('Shall', False, False, Outcome.FAIL),
    ('Should', False, False, Outcome.WARNING),
    ('Shall', True, True, Outcome.NO_EVENTS),
    ('Shall/Not-Implemented', False, True, Outcome.NOT_IMPLEMENTED),
])
# pytest supplies each fixture and scenario field by name.
# pylint: disable-next=too-many-positional-arguments
def test_user_facing_outcomes(tmp_path, source_export, case, evaluator,
                              criticality, met, no_events, expected):
    """Use reporter semantics, including warning and manual outcomes."""
    evaluator[1].update(Criticality=criticality, RequirementMet=met, NoSuchEvent=no_events)
    result = CachedRunner(source_export).run(case, tmp_path)
    result.assert_expected(replace(case, expected_result=expected))
    assert result.report_path.is_file()
    assert len(list(tmp_path.glob('ScubaResults_*.json'))) == 1
    assert result.policy_id.endswith('v1')


@pytest.mark.parametrize('failed_api', [False, True])
def test_failed_prerequisites_override_rego_pass(tmp_path, source_export, case,
                                                 evaluator, failed_api):
    """A raw Rego pass must not hide the reporter's missing-input error."""
    if failed_api:
        evaluator[1]['Prerequisites'] = ['reports/v1/activities/list']
        source_export['successful_calls'] = ['reports/v1/activities/list']
        source_export['unsuccessful_calls'] = ['reports/v1/activities/list']
    else:
        source_export['missing_policies'] = ['security_session_controls.webSessionDuration']
    result = CachedRunner(source_export).run(case, tmp_path)
    result.assert_expected(replace(case, expected_result=Outcome.ERROR))
    with pytest.raises(AssertionError, match='expected Pass, got Error'):
        result.assert_expected(case)


# ---------------------------------------------------------------------------
# pytest wiring (conftest options and session fixtures)
# ---------------------------------------------------------------------------

def functional_conftest() -> str:
    """The Functional root options plus the Products fixtures, as one conftest."""
    return ((FUNCTIONAL_DIR / 'conftest.py').read_text(encoding='utf-8')
            + (PRODUCTS_DIR / 'conftest.py').read_text(encoding='utf-8'))


def test_session_fixture_collects_once(pytester, source_export):
    """Products come from the selected cases, whatever the parameter is named,
    and one collection serves every case."""
    stub = f"""
_collection_count = 0
def collect_export(output_dir, products, cli_args):
    global _collection_count
    _collection_count += 1
    assert _collection_count == 1
    assert products == ['commoncontrols', 'gmail']
    assert cli_args == ['--credentials', 'fake.json']
    return {source_export!r}
"""
    pytester.makeconftest(functional_conftest() + stub)
    pytester.makepyfile("""
import pytest
from scubagoggles.Testing.Functional.Products.framework.plan_model import Outcome, PolicyCase, TestDriver
CASES = [PolicyCase('GWS.COMMONCONTROLS.4.1', 'commoncontrols', 'a', TestDriver.CACHED, Outcome.PASS),
         PolicyCase('GWS.GMAIL.1.1', 'gmail', 'b', TestDriver.CACHED, Outcome.PASS)]
@pytest.mark.parametrize('scenario', CASES)
def test_snapshot(scenario, provider_export):
    assert provider_export['tenant_info']['topLevelOU'] == 'Example'
""")
    result = pytester.runpytest('--cached-collect', '--credentials=fake.json', '-q')
    result.assert_outcomes(passed=2)


def test_source_selection_is_explicit(pytester):
    """Default runs skip; conflicting options and the live driver fail."""
    pytester.makeconftest(functional_conftest())
    pytester.makepyfile('def test_source(provider_export): assert provider_export')
    pytester.runpytest('-q').assert_outcomes(skipped=1)
    for args in (['--cached-export=a.json', '--cached-collect'], ['--test-driver=live']):
        assert pytester.runpytest(*args).ret == pytest.ExitCode.USAGE_ERROR
