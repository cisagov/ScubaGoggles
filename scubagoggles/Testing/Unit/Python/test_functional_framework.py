"""Unit tests for plan loading, export handling, and source selection."""

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml

from scubagoggles.Testing.Functional import conftest as functional_options
from scubagoggles.Testing.Functional.Products import conftest as product_fixtures
from scubagoggles.Testing.Functional.Products.framework import cached_runner, plan_loader, scuba_app
from scubagoggles.Testing.Functional.Products.framework.patch_helpers import (
    PATCH_HELPERS, missing_setting, set_setting,
)
from scubagoggles.Testing.Functional.Products.framework.plan_model import (
    LiveConfig, Outcome, Patch, PlanError, PolicyCase, Scope, TestDriver, WriteApi,
)

PRODUCTS_DIR = Path(cached_runner.__file__).parent.parent
POLICY_ID = 'GWS.COMMONCONTROLS.4.1'
SETTING = 'security_session_controls.webSessionDuration'


@pytest.fixture(name='case')
def case_fixture():
    """A case shared by runner and report-reader tests."""
    return PolicyCase(POLICY_ID, 'commoncontrols', 'Example', TestDriver.CACHED, Outcome.PASS)


@pytest.fixture(name='plan')
def plan_fixture():
    """One policy entry, independent of the checked-in functional scenarios."""
    return {'live_testing': False, 'cases': [
        {'name': ' Example ', 'test_driver': 'cached', 'expected_result': 'Pass',
         'settings': {SETTING: '43200s'}}]}


@pytest.fixture(name='load_policy')
def load_policy_fixture(tmp_path, monkeypatch):
    """Restrict schema tests to one policy so they need no full baseline plan."""
    monkeypatch.setattr(plan_loader, 'baseline_policy_ids', lambda _product: {POLICY_ID})

    def load(entry):
        path = tmp_path / 'commoncontrols.yaml'
        path.write_text(yaml.safe_dump({POLICY_ID: entry}), encoding='utf-8')
        return plan_loader.load_plan(path)[0]

    return load


@pytest.fixture(name='export')
def export_fixture():
    """Only the fields required by the export loader and patch helpers."""
    return {
        'tenant_info': {'topLevelOU': 'Root'},
        'policies': {'Root': {'security_session_controls': {'webSessionDuration': '86400s'}}},
        'successful_calls': [], 'unsuccessful_calls': [], 'missing_policies': [],
        'report_uuid': 'unit-test',
    }


def test_repository_plans_load():
    """Checked-in YAML must remain compatible with the framework."""
    assert plan_loader.load_plans(PRODUCTS_DIR / 'TestPlans')


@pytest.mark.parametrize('live_testing', [False, True])
def test_cached_plan_fields(load_policy, plan, live_testing):
    """Cached cases accept descriptive names without requiring live metadata."""
    plan['live_testing'] = live_testing
    loaded = load_policy(plan)
    case = loaded.cases[0]
    assert case.test_id == f'{POLICY_ID}-cached-Example'
    assert case.expected_result is Outcome.PASS
    assert case.settings == {SETTING: '43200s'}
    assert loaded.live is None and case.live is None


@pytest.mark.parametrize('omit_cases', [False, True])
def test_empty_cases(load_policy, plan, omit_cases):
    """Empty and omitted case lists both produce no scenarios."""
    if omit_cases:
        plan.pop('cases')
    else:
        plan['cases'] = []
    assert load_policy(plan).cases == ()


@pytest.mark.parametrize('fields,message', [
    ({'name': 'Two\nlines'}, 'single-line text'),
    ({'expected': 'Pass'}, "unknown key 'expected'"),
    ({'settings': {'security_password.webSessionDuration': '12s'}}, 'not declared'),
    ({'settings': {SETTING: float('nan')}}, 'JSON values'),
    ({'patch': {'helper': 'unknown'}}, 'unknown patch helper'),
    ({'patch': {'helper': 'missing_setting'}}, 'invalid arguments'),
    ({'patch': {'helper': 'missing_setting', 'args': {'setting': SETTING, 'extra': 1}}},
     'invalid arguments'),
])
def test_invalid_case_fields(load_policy, plan, fields, message):
    """Reject representative authoring errors before running a case."""
    plan['cases'][0].update(fields)
    with pytest.raises(PlanError, match=message):
        load_policy(plan)


@pytest.mark.parametrize('live_testing', ['true', 1])
def test_plan_errors_are_aggregated(load_policy, plan, live_testing):
    """Strict booleans and outcome labels are validated in one collection pass."""
    plan['live_testing'] = live_testing
    plan['cases'][0]['expected_result'] = 'Passed'
    with pytest.raises(PlanError) as error:
        load_policy(plan)
    assert 'live_testing must be a boolean' in str(error.value)
    assert 'expected_result must be one of' in str(error.value)


@pytest.mark.parametrize('text,message', [
    ('[', 'expected'),
    ('1: {}', 'mapping keys must be strings'),
    (f'{POLICY_ID}:\n  cases: []\n  cases: []\n', "duplicate key 'cases'"),
])
def test_yaml_errors_include_source(tmp_path, text, message):
    """YAML errors identify the plan file and offending input."""
    path = tmp_path / 'commoncontrols.yaml'
    path.write_text(text, encoding='utf-8')
    with pytest.raises(PlanError, match=message) as error:
        plan_loader.load_plan(path)
    assert path.name in str(error.value)


@pytest.mark.parametrize('overrides,expected', [
    ({'scope': 'group'}, LiveConfig((WriteApi.DIRECTORY_API,), Scope.GROUP)),
    ({'write_api': ['policy_api', 'cloud_identity_api']},
     LiveConfig((WriteApi.POLICY_API, WriteApi.CLOUD_IDENTITY_API), Scope.TENANT)),
])
def test_live_defaults_and_overrides(load_policy, plan, overrides, expected):
    """Mixed drivers and partial overrides preserve defaults for sibling cases."""
    plan.update(live_testing=True, live={'write_api': 'directory_api', 'scope': 'tenant'})
    live = dict(plan['cases'][0], test_driver='live')
    plan['cases'] += [live, dict(live, name='Override', live=overrides)]
    cached, default, overridden = load_policy(plan).cases
    assert cached.live is None
    assert cached.test_id != default.test_id
    assert default.live == LiveConfig((WriteApi.DIRECTORY_API,), Scope.TENANT)
    assert overridden.live == expected


@pytest.mark.parametrize('allowed,fields,message', [
    (False, {'live': {'write_api': 'policy_api', 'scope': 'ou'}}, 'live case requires'),
    (True, {}, 'live.write_api is required'),
    (True, {'live': {'write_api': 'policy_api'}}, 'live.scope is required'),
    (True, {'live': {'write_api': 'policy_api', 'scope': 'ou'},
            'patch': {'helper': 'missing_setting', 'args': {'setting': SETTING}}},
     'patch helpers only'),
])
def test_live_case_requirements(load_policy, plan, allowed, fields, message):
    """Live cases require permission and metadata and cannot use cached patches."""
    plan['live_testing'] = allowed
    plan['cases'][0].update(test_driver='live', **fields)
    with pytest.raises(PlanError, match=message):
        load_policy(plan)


def test_setting_patches_preserve_inheritance(export):
    """Patch overrides and missing markers without changing inheriting views."""
    export['policies'].update(Child={'security_session_controls': {}}, Inherits={})
    export['missing_policies'] = [SETTING, 'other.field']
    set_setting(export, SETTING, '43200s')
    assert export['policies']['Root'] == export['policies']['Child']
    assert export['policies']['Root']['security_session_controls']['webSessionDuration'] == '43200s'
    assert export['policies']['Inherits'] == {}
    assert export['missing_policies'] == ['other.field']
    missing_setting(export, SETTING)
    assert 'webSessionDuration' not in export['policies']['Root']['security_session_controls']
    assert export['missing_policies'] == ['other.field', SETTING]


@pytest.mark.parametrize('wrapped', [False, True])
@pytest.mark.parametrize('rules', [[], [{'state': 'ACTIVE'}]])
def test_export_formats_preserve_lists(tmp_path, export, wrapped, rules):
    """Rule lists must survive both input formats, including empty lists."""
    export['policies']['Root'].update(rule_dlp=rules, dlp_pii=['drive'])
    path = tmp_path / 'export.json'
    path.write_text(json.dumps({'Raw': export} if wrapped else export), encoding='utf-8')
    assert cached_runner.load_export(path) == export


def test_invalid_export_inputs(tmp_path, export):
    """Reject report directories and malformed setting containers early."""
    with pytest.raises(ValueError, match='JSON file, not a directory'):
        cached_runner.load_export(tmp_path)
    export['policies']['Root']['security_session_controls'] = None
    path = tmp_path / 'export.json'
    path.write_text(json.dumps(export), encoding='utf-8')
    with pytest.raises(ValueError, match='object or a list'):
        cached_runner.load_export(path)


def test_collect_export_uses_returned_directory(tmp_path, monkeypatch, export):
    """Read the current run's output and forward collection arguments."""
    report_dir = tmp_path / 'new-report'
    report_dir.mkdir()
    (report_dir / 'ScubaResults.json').write_text(json.dumps({'Raw': export}), encoding='utf-8')
    run = Mock(return_value=report_dir)
    monkeypatch.setattr(cached_runner, 'run_scubagoggles', run)
    result = cached_runner.collect_export(tmp_path, ['commoncontrols'], ['--customerid', 'C1'])
    assert result == export
    run.assert_called_once_with('--baselines', 'commoncontrols', '--outputpath', str(tmp_path),
                                '--customerid', 'C1')


@pytest.mark.parametrize('broken_patch', [False, True])
def test_cached_runner_isolates_cases(tmp_path, monkeypatch, case, broken_patch):
    """Caller mutations and successful or failed patches cannot alter later cases."""
    source = {'values': []}

    def edit(data):
        data['values'].append('patched')
        if broken_patch:
            raise RuntimeError('broken patch')

    monkeypatch.setitem(PATCH_HELPERS, 'edit', edit)
    run = Mock(return_value=tmp_path / 'reports')
    read = Mock()
    monkeypatch.setattr(cached_runner, 'run_scubagoggles', run)
    monkeypatch.setattr(cached_runner, 'read_policy_result', read)
    monkeypatch.setattr(cached_runner, 'baseline_versions', lambda _product: ('v1', {}))
    runner = cached_runner.CachedRunner(source, ['--opapath', 'opa'])
    source['values'].append('caller')
    patched = replace(case, patches=(Patch('edit'),))
    if broken_patch:
        with pytest.raises(RuntimeError, match='broken patch'):
            runner.run(patched, tmp_path / 'patched')
        run.assert_not_called()
    else:
        runner.run(patched, tmp_path / 'patched')
        data = json.loads((tmp_path / 'patched' / 'ProviderSettingsExport.json').read_text())
        assert data['values'] == ['patched']
    output = tmp_path / 'original'
    assert runner.run(case, output) is read.return_value
    data = json.loads((output / 'ProviderSettingsExport.json').read_text())
    assert data == {'values': [], 'baseline_suffix': 'v1', 'baseline_versions': {}}
    assert source == {'values': ['caller']}
    run.assert_called_with('--baselines', 'commoncontrols', '--outputpath', str(output),
                            '--runcached', '--skipexport', '--opapath', 'opa')
    read.assert_called_with(run.return_value, case)


def test_apply_case_runs_patches_after_settings(export, case):
    """A missing-setting patch must override a value supplied by settings."""
    patched = replace(case, settings={SETTING: '43200s'},
                      patches=(Patch('missing_setting', {'setting': SETTING}),))
    cached_runner.apply_case(export, patched)
    assert export['policies']['Root']['security_session_controls'] == {}
    assert export['missing_policies'] == [SETTING]


def test_find_results_requires_one_current_file(tmp_path):
    """Nested reports are ignored; missing or ambiguous current reports fail."""
    old = tmp_path / 'old'
    old.mkdir()
    (old / 'ScubaResults.json').touch()
    with pytest.raises(RuntimeError, match='found 0'):
        scuba_app.find_results_file(tmp_path)
    current = tmp_path / 'ScubaResults.json'
    current.touch()
    assert scuba_app.find_results_file(tmp_path) == current
    (tmp_path / 'ScubaResults_duplicate.json').touch()
    with pytest.raises(RuntimeError, match='found 2'):
        scuba_app.find_results_file(tmp_path)


@pytest.mark.parametrize('matches', [0, 1, 2])
def test_report_reader_and_assertion(tmp_path, monkeypatch, case, matches):
    """Match one versioned policy row and assert its reported result unchanged."""
    (tmp_path / 'ScubaResults.json').touch()
    row = {'Control ID': POLICY_ID + 'v2', 'Result': 'Warning', 'Details': 'Reported detail'}
    rows = [dict(row, **{'Control ID': 'GWS.COMMONCONTROLS.5.3v1'}), *[row] * matches]
    monkeypatch.setattr(scuba_app, 'load_report', lambda _path: {
        'Results': {'commoncontrols': [{'Controls': rows}]}})
    if matches != 1:
        with pytest.raises(RuntimeError, match=f'got {matches}'):
            scuba_app.read_policy_result(tmp_path, case)
        return
    result = scuba_app.read_policy_result(tmp_path, case)
    result.assert_expected(replace(case, expected_result=Outcome.WARNING))
    assert result.details == row['Details']
    assert result.report_path == tmp_path / 'IndividualReports' / 'CommoncontrolsReport.html'
    with pytest.raises(AssertionError, match='expected Pass, got Warning') as error:
        result.assert_expected(case)
    assert str(result.report_path) in str(error.value)


@pytest.mark.parametrize('collect', [False, True])
def test_provider_source_selection(tmp_path, monkeypatch, case, collect):
    """Return the selected source and forward arguments only to that provider."""
    options = {'--collect': collect, '--export-file': None if collect else tmp_path / 'export.json',
               '--credentials': Path('credentials.json')}
    config = Mock(getoption=Mock(side_effect=options.get))
    request = Mock(session=Mock(items=[Mock(callspec=Mock(params={'case': case}))]))
    factory, load, acquire = Mock(), Mock(), Mock()
    monkeypatch.setattr(product_fixtures, 'load_export', load)
    monkeypatch.setattr(product_fixtures, 'collect_export', acquire)
    result = product_fixtures.provider_export_fixture.__wrapped__(config, factory, request)
    if collect:
        acquire.assert_called_once_with(factory.mktemp.return_value, ['commoncontrols'],
                                         ['--credentials', 'credentials.json'])
        load.assert_not_called()
        assert result is acquire.return_value
    else:
        load.assert_called_once_with(options['--export-file'])
        acquire.assert_not_called()
        assert result is load.return_value


@pytest.mark.parametrize('options,workers,message', [
    ({'--collect': True, '--export-file': Path('export.json')}, None, 'Choose'),
    ({'--collect': True}, 2, 'serially'),
    ({'--test-driver': 'live'}, None, 'not implemented'),
])
def test_invalid_source_options(options, workers, message):
    """Reject conflicting sources, parallel collection, and unavailable live execution."""
    config = Mock(getoption=Mock(side_effect=options.get),
                  option=SimpleNamespace(numprocesses=workers))
    with pytest.raises(pytest.UsageError, match=message):
        functional_options.pytest_configure(config)
