"""Functional test framework guarantees: plans, acquisition, isolation, and
real report outcomes."""

from copy import deepcopy
from dataclasses import replace
from datetime import date
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
    LiveConfig, Outcome, Patch, PlanError, PolicyCase, Scope, TestDriver, WriteApi,
)
from scubagoggles.Testing.Functional.Products.framework.scuba_app import (
    baseline_policy_ids, find_results_file,
)

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
    (lambda doc: first_case(doc).update(name='Session\n12h'),
     'name must be nonempty, single-line text'),
    (lambda doc: first_case(doc).update(settings={'security_password.minLength': 16}),
     'is not declared in policy_api.py'),
    (lambda doc: first_case(doc).update(settings={'security_password.minimum': 16}),
     'is not declared in policy_api.py'),
    (lambda doc: first_case(doc).update(settings={'security_password.webSessionDuration': '12s'}),
     'is not declared in policy_api.py'),
    (lambda doc: first_case(doc).update(settings={'security_password': 16}),
     'must look like setting_type.fieldName'),
    (lambda doc: first_case(doc).update(patch=[{'helper': 'no_such_helper'}]),
     'unknown patch helper'),
    (lambda doc: first_case(doc).update(patch={'helper': []}),
     'unknown patch helper'),
    (lambda doc: first_case(doc).update(patch={'helper': 'missing_setting'}),
     'invalid arguments for missing_setting'),
    (lambda doc: first_case(doc).update(patch={
        'helper': 'missing_setting', 'args': {'typo': 'security_password.minimumLength'}}),
     'invalid arguments for missing_setting'),
    (lambda doc: first_case(doc).update(patch={
        'helper': 'missing_setting',
        'args': {'setting': 'security_password.minimumLength', 'extra': True}}),
     'invalid arguments for missing_setting'),
    (lambda doc: first_case(doc).update(patch={
        'helper': 'missing_setting', 'args': {'setting': date(2026, 1, 1)}}),
     'args must contain JSON values'),
    (lambda doc: first_case(doc).update(patch={
        'helper': 'missing_setting', 'args': {'setting': 12}}),
     'must look like setting_type.fieldName'),
    (lambda doc: first_case(doc).update(patch={
        'helper': 'missing_setting', 'args': {'setting': 'security_password.minimum'}}),
     'is not declared in policy_api.py'),
    (lambda doc: first_case(doc).update(patch={'helper': 'missing_setting', 'args': []}),
     'args must be a mapping'),
    (lambda doc: first_case(doc).update(patch={'helper': 'missing_setting', 'typo': {}}),
     "unknown key 'typo'"),
    (lambda doc: doc['GWS.COMMONCONTROLS.4.1'].update(cases=1),
     'cases must be a list'),
    (lambda doc: first_case(doc).update(settings=[]),
     'settings must be a mapping'),
    (lambda doc: first_case(doc).update(description=[]),
     'description must be text'),
    (lambda doc: doc['GWS.COMMONCONTROLS.9.1'].update(reason=True),
     'reason must be text'),
    (add_case('GWS.COMMONCONTROLS.4.1', name='Session duration of 12 hours is compliant'),
     'duplicate cached case name'),
    (lambda doc: doc['GWS.COMMONCONTROLS.9.1'].pop('reason'),
     'add cases, or a reason'),
    (lambda doc: doc['GWS.COMMONCONTROLS.6.2']['live'].update(scope='everywhere'),
     'scope must be one of'),
    (lambda doc: doc['GWS.COMMONCONTROLS.6.2']['live'].update(write_api=['none', 'policy_api']),
     'write_api must be one of'),
    (lambda doc: doc['GWS.COMMONCONTROLS.6.2']['live'].update(write_api=[]),
     'write_api must name at least one'),
])
def test_plan_problems_are_reported(tmp_path, edit, message):
    """Plan mistakes fail at collection with a message naming the policy."""
    with pytest.raises(PlanError, match=message):
        load_plan(write_plan(tmp_path, edit))


@pytest.mark.parametrize('text,key,line', [
    ('GWS.COMMONCONTROLS.4.1: {}\nGWS.COMMONCONTROLS.4.1: {}\n',
     'GWS.COMMONCONTROLS.4.1', 2),
    ('GWS.COMMONCONTROLS.4.1:\n  cases: []\n  cases: []\n', 'cases', 3),
    ('GWS.COMMONCONTROLS.4.1:\n  cases:\n    - settings:\n'
     '        security_password.minimumLength: 8\n'
     '        security_password.minimumLength: 16\n',
     'security_password.minimumLength', 5),
])
def test_duplicate_yaml_keys_report_source_location(tmp_path, text, key, line):
    """Repeated policies and nested keys cannot silently replace test data."""
    path = tmp_path / 'commoncontrols.yaml'
    path.write_text(text, encoding='utf-8')

    with pytest.raises(PlanError) as error:
        load_plan(path)

    assert f'duplicate key {key!r}' in str(error.value)
    assert 'commoncontrols.yaml' in str(error.value)
    assert f'line {line}' in str(error.value)


@pytest.mark.parametrize('text,message', [
    ('[', 'expected'),
    ('[]', 'expected a mapping'),
    ('', 'expected a mapping'),
    ('1: {}', 'mapping keys must be strings'),
])
def test_invalid_yaml_is_a_plan_error(tmp_path, text, message):
    """Syntax and root-type errors use the same exception as schema failures."""
    path = tmp_path / 'commoncontrols.yaml'
    path.write_text(text, encoding='utf-8')
    with pytest.raises(PlanError, match=message):
        load_plan(path)


@pytest.mark.parametrize('value', [date(2026, 1, 1), {'value'}, float('nan'), float('inf')])
def test_plan_values_must_be_json_compatible(tmp_path, value):
    """YAML-only values fail at collection instead of during export writing."""
    path = write_plan(tmp_path, lambda doc: first_case(doc).update(
        settings={'security_password.minimumLength': value}))
    with pytest.raises(PlanError, match='settings must contain JSON values'):
        load_plan(path)


def test_nested_json_settings_and_patch_arguments(tmp_path, monkeypatch):
    """Nested JSON data remains available to future setting and patch helpers."""
    def example_patch(_data, payload):
        assert payload

    monkeypatch.setitem(PATCH_HELPERS, 'example_patch', example_patch)
    value = {'items': [True, None, 1, 1.5, 'text', {'nested': []}]}
    path = write_plan(tmp_path, lambda doc: first_case(doc).update(
        settings={'security_password.minimumLength': value},
        patch={'helper': 'example_patch', 'args': {'payload': value}}))
    plan = next(plan for plan in load_plan(path) if plan.policy_id == 'GWS.COMMONCONTROLS.4.1')

    assert plan.cases[0].settings['security_password.minimumLength'] == value
    assert plan.cases[0].patches[0].args['payload'] == value


def test_rego_prerequisites_allow_exact_undeclared_setting(tmp_path, monkeypatch):
    """A Rego prerequisite remains valid before the provider catalog catches up."""
    from scubagoggles.policy_api import PolicyAPI  # pylint: disable=import-outside-toplevel
    # pylint: disable-next=protected-access
    monkeypatch.delitem(PolicyAPI._expectedPolicySettings, 'security_session_controls')
    assert load_plan(write_plan(tmp_path, lambda _doc: None))


@pytest.mark.parametrize('policy_id,case,message', [
    ('GWS.COMMONCONTROLS.4.1', {}, 'live case requires live_testing: true'),
    ('GWS.COMMONCONTROLS.2.1', {}, 'live.write_api is required'),
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
    """One scenario name can run with either driver, using distinct pytest IDs."""
    def edit(doc):
        for driver in ('cached', 'live'):
            add_case('GWS.COMMONCONTROLS.6.2', name='Compliant configuration',
                     test_driver=driver)(doc)
    path = write_plan(tmp_path, edit)
    plan = next(plan for plan in load_plan(path) if plan.policy_id == 'GWS.COMMONCONTROLS.6.2')
    cached, live = plan.cases
    assert cached.live is None
    assert live.live == LiveConfig((WriteApi.DIRECTORY_API,), Scope.TENANT)
    assert cached.test_id == 'GWS.COMMONCONTROLS.6.2-cached-Compliant configuration'
    assert live.test_id == 'GWS.COMMONCONTROLS.6.2-live-Compliant configuration'


@pytest.mark.parametrize('value', ['allowed', 'denied', 'true', 'false', 0, 1, None, []])
def test_live_testing_requires_a_boolean(tmp_path, value):
    """Quoted booleans, legacy labels and truthy values do not authorize live cases."""
    path = write_plan(tmp_path, lambda doc: doc['GWS.COMMONCONTROLS.4.1'].update(
        live_testing=value))
    with pytest.raises(PlanError, match='live_testing must be a boolean'):
        load_plan(path)


def test_live_testing_must_be_explicit(tmp_path):
    """Every policy records its live-testing decision even when it only has cached cases."""
    path = write_plan(tmp_path, lambda doc: doc['GWS.COMMONCONTROLS.4.1'].pop('live_testing'))
    with pytest.raises(PlanError, match='live_testing must be a boolean'):
        load_plan(path)


@pytest.mark.parametrize('value', [True, False])
def test_cached_cases_need_no_live_metadata(tmp_path, value):
    """A cached-only plan works with either live-testing decision and no live block."""
    path = write_plan(tmp_path, lambda doc: doc['GWS.COMMONCONTROLS.4.1'].update(
        live_testing=value))
    plan = next(plan for plan in load_plan(path) if plan.policy_id == 'GWS.COMMONCONTROLS.4.1')
    assert plan.live_testing is value
    assert plan.live is None
    assert all(case.live is None for case in plan.cases)


@pytest.mark.parametrize('overrides,expected', [
    ({'scope': 'group'}, LiveConfig((WriteApi.DIRECTORY_API,), Scope.GROUP)),
    ({'write_api': ['policy_api', 'cloud_identity_api']},
     LiveConfig((WriteApi.POLICY_API, WriteApi.CLOUD_IDENTITY_API), Scope.TENANT)),
])
def test_live_case_overrides_only_supplied_fields(tmp_path, overrides, expected):
    """Overrides inherit unspecified fields without changing defaults or sibling cases."""
    def edit(doc):
        add_case('GWS.COMMONCONTROLS.6.2', name='Override', test_driver='live',
                 live=overrides)(doc)
        add_case('GWS.COMMONCONTROLS.6.2', name='Default', test_driver='live')(doc)
    plan = next(plan for plan in load_plan(write_plan(tmp_path, edit))
                if plan.policy_id == 'GWS.COMMONCONTROLS.6.2')
    assert plan.cases[0].live == expected
    assert plan.cases[1].live == LiveConfig((WriteApi.DIRECTORY_API,), Scope.TENANT)
    assert plan.live.write_api == (WriteApi.DIRECTORY_API,)
    assert plan.live.scope is Scope.TENANT


def test_live_case_can_supply_all_configuration(tmp_path):
    """Policy defaults are optional when the live case supplies both fields."""
    def edit(doc):
        doc['GWS.COMMONCONTROLS.6.2'].pop('live')
        add_case('GWS.COMMONCONTROLS.6.2', test_driver='live',
                 live={'write_api': 'directory_api', 'scope': 'tenant'})(doc)
    plan = next(plan for plan in load_plan(write_plan(tmp_path, edit))
                if plan.policy_id == 'GWS.COMMONCONTROLS.6.2')
    assert plan.live is None
    assert plan.cases[0].live == LiveConfig((WriteApi.DIRECTORY_API,), Scope.TENANT)


@pytest.mark.parametrize('edit,message', [
    (lambda doc: doc['GWS.COMMONCONTROLS.6.2'].update(live_testing=False),
     'live defaults require live_testing: true'),
    (lambda doc: doc['GWS.COMMONCONTROLS.6.2'].update(live=None),
     'expected a mapping'),
    (lambda doc: doc['GWS.COMMONCONTROLS.6.2']['live'].update(scope='ou_group'),
     'scope must be one of'),
    (lambda doc: doc['GWS.COMMONCONTROLS.6.2']['live'].update(write_api='unknown'),
     'write_api must be one of'),
    (lambda doc: doc['GWS.COMMONCONTROLS.6.2']['live'].update(
        write_api=['directory_api', 'directory_api']), 'must not repeat an API'),
    (lambda doc: first_case(doc).update(live={'scope': 'ou'}),
     'case-level live configuration requires test_driver: live'),
    (add_case('GWS.COMMONCONTROLS.6.1', test_driver='live'),
     'live.scope is required'),
    (add_case('GWS.COMMONCONTROLS.6.2', test_driver='live', live={'scope': 'everywhere'}),
     'scope must be one of'),
    (add_case('GWS.COMMONCONTROLS.6.2', test_driver='live', live={'live_testing': True}),
     "unknown key 'live_testing'"),
    (add_case('GWS.COMMONCONTROLS.4.1', test_driver='live',
              live={'write_api': 'policy_api', 'scope': 'ou'}),
     'live case requires live_testing: true'),
])
def test_live_configuration_errors(tmp_path, edit, message):
    """Reject incomplete, contradictory and unsupported live configuration."""
    with pytest.raises(PlanError, match=message):
        load_plan(write_plan(tmp_path, edit))


@pytest.mark.parametrize('name', ['', '   ', 16, 'Name\twith tab', 'Two\nlines'])
def test_case_names_require_readable_single_line_text(tmp_path, name):
    """Empty names and control characters cannot produce confusing pytest IDs."""
    path = write_plan(tmp_path, lambda doc: first_case(doc).update(name=name))
    with pytest.raises(PlanError, match='name must be nonempty, single-line text'):
        load_plan(path)


def test_descriptive_names_preserve_punctuation(tmp_path):
    """Human-readable case names retain punctuation and trim surrounding spaces."""
    name = '12-hour session: compliant (cached)'
    path = write_plan(tmp_path, lambda doc: first_case(doc).update(name=f' {name} '))
    plan = next(plan for plan in load_plan(path) if plan.policy_id == 'GWS.COMMONCONTROLS.4.1')
    assert plan.cases[0].name == name
    assert plan.cases[0].test_id == f'{plan.policy_id}-cached-{name}'


@pytest.mark.parametrize('has_cases,reason,valid', [
    (True, None, True), (True, 'Partial coverage.', True),
    (False, None, False), (False, '', False), (False, 'Cases not written yet.', True),
])
def test_reason_does_not_control_execution(tmp_path, has_cases, reason, valid):
    """Reason documents absent or partial coverage; it never disables defined cases."""
    def edit(doc):
        entry = doc['GWS.COMMONCONTROLS.4.1']
        if not has_cases:
            entry['cases'] = []
        if reason is not None:
            entry['reason'] = reason
    path = write_plan(tmp_path, edit)
    if not valid:
        with pytest.raises(PlanError, match='add cases, or a reason'):
            load_plan(path)
        return
    plan = next(plan for plan in load_plan(path) if plan.policy_id == 'GWS.COMMONCONTROLS.4.1')
    assert len(plan.cases) == (3 if has_cases else 0)


def test_all_plan_problems_reported_together(tmp_path):
    """Authors see every problem in one run, not one at a time."""
    def edit(doc):
        doc.pop('GWS.COMMONCONTROLS.9.1')
        first_case(doc).update(expected_result='Passed')
        doc['GWS.COMMONCONTROLS.5.3'].update(cases=1)
        first_case(doc).update(patch=[{'helper': 'missing_setting'}, {'helper': []}])
    with pytest.raises(PlanError) as error:
        load_plan(write_plan(tmp_path, edit))
    assert 'GWS.COMMONCONTROLS.9.1: missing' in str(error.value)
    assert 'expected_result must be one of' in str(error.value)
    assert 'cases must be a list' in str(error.value)
    assert 'invalid arguments for missing_setting' in str(error.value)
    assert 'unknown patch helper' in str(error.value)


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


@pytest.mark.parametrize('edit,message', [
    (lambda data: data['tenant_info'].update(topLevelOU=[]), 'topLevelOU'),
    (lambda data: data['tenant_info'].update(topLevelOU='Missing'), 'top-level OU'),
    (lambda data: data['policies'].update(Example=None), 'policies for'),
    (lambda data: data['policies'].update(Child=[]), 'policies for'),
    (lambda data: data['policies']['Example'].update(security_password=None), 'setting'),
])
def test_export_structure_is_validated_before_patching(tmp_path, source_export, edit, message):
    """Reject malformed OU and setting containers when reading the snapshot."""
    edit(source_export)
    path = tmp_path / 'export.json'
    path.write_text(json.dumps(source_export), encoding='utf-8')
    with pytest.raises(ValueError, match=message):
        load_export(path)


def test_find_results_uses_only_the_current_directory(tmp_path):
    """An older nested report cannot be mistaken for this run's result."""
    old = tmp_path / 'old'
    old.mkdir()
    (old / 'ScubaResults_old.json').write_text('{}', encoding='utf-8')
    with pytest.raises(RuntimeError, match='found 0'):
        find_results_file(tmp_path)

    current = tmp_path / 'ScubaResults_current.json'
    current.write_text('{}', encoding='utf-8')
    assert find_results_file(tmp_path) == current

    (tmp_path / 'ScubaResults_duplicate.json').write_text('{}', encoding='utf-8')
    with pytest.raises(RuntimeError, match='found 2'):
        find_results_file(tmp_path)


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
    old = tmp_path / 'collect' / 'old'
    old.mkdir(parents=True)
    (old / 'ScubaResults_old.json').write_text('{}', encoding='utf-8')

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
