"""Tests for ScubaGoggles orchestration."""

import csv
import logging
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import scubagoggles.orchestrator as orchestrator_module
from scubagoggles.orchestrator import Orchestrator, UserRuntimeError


# pylint: disable=too-few-public-methods
class MembershipNamespace(SimpleNamespace):
    """Namespace that supports ``in`` checks used by ``_run_reporter``."""

    def __contains__(self, key):
        return hasattr(self, key)


class StopAfterMetadataCapture(Exception):
    """Stop ``_run_reporter`` after capturing the report payload."""


class TestOrchestratorMetadata:
    """Test OrgName/OrgUnitName in report metadata.
        Each org_case has two dictionaries:
            (
                input_args,
                expected_metadata,
            )
    """

    @pytest.mark.parametrize(
        'org_case',
        [
            (
                {'OrgName': 'TestOrg', 'OrgUnitName': 'TestDept'},
                {'OrgName': 'TestOrg', 'OrgUnitName': 'TestDept'},
            ),
            (
                {'OrgName': None, 'OrgUnitName': None},
                {'OrgName': None, 'OrgUnitName': None},
            ),
            (
                {},
                {'OrgName': None, 'OrgUnitName': None},
            ),
        ],
    )
    # pylint: disable=protected-access
    def test_orgname_orgunitname_are_written_to_report_metadata(
            self,
            tmp_path,
            monkeypatch,
            org_case,
    ):
        """Test OrgName and OrgUnitName are included in report metadata."""
        org_args, expected_metadata = org_case
        args = MembershipNamespace(
            baselines=['gmail'],
            outputpath=tmp_path / 'output',
            fullnamesdict={'gmail': 'Gmail'},
            outputregofilename='TestResults',
            outputproviderfilename='ProviderOutput',
            darkmode='false',
            cicdtestingmode='false',
            quiet=True,
            outputreportfilename='BaselineReports',
            silencebodwarnings=True,
            omitpolicy=None,
            annotatepolicy=None,
            **org_args,
        )

        orchestrator = object.__new__(Orchestrator)
        orchestrator._args = args
        orchestrator.args_dict = vars(args)
        orchestrator._baseline_policies = {'gmail': []}

        reporter = Mock()
        reporter.rego_json_to_ind_reports.return_value = [{}, []]
        reporter.rules_table = None
        reporter.annotated_failed_policies = {}
        monkeypatch.setattr(orchestrator_module, 'Reporter',
                            Mock(return_value=reporter))

        settings_data = {
            'tenant_info': {
                'domain': 'example.org',
                'ID': 'tenant-id',
                'topLevelOU': 'Example Tenant',
            },
            'successful_calls': [],
            'unsuccessful_calls': [],
            'missing_policies': [],
            'report_uuid': '12345678-1234-1234-1234-123456789abc',
        }
        captured_output = {}

        def capture_total_output(_outputpath, _out_jsonfile, total_output):
            captured_output['total_output'] = total_output
            raise StopAfterMetadataCapture

        monkeypatch.setattr(orchestrator, '_copy_cisa_logo', Mock())
        monkeypatch.setattr(orchestrator, '_load_test_results_json',
                            Mock(return_value=[]))
        monkeypatch.setattr(orchestrator, '_get_commands_statuses',
                            Mock(return_value=settings_data))
        monkeypatch.setattr(orchestrator, '_get_full_out_jsonfile_name',
                            Mock(return_value='ScubaResults'))
        monkeypatch.setattr(orchestrator, '_load_scuba_results_file',
                            Mock(return_value={}))
        monkeypatch.setattr(orchestrator, 'convert_to_result_csv', Mock())
        monkeypatch.setattr(orchestrator, '_dump_report_files',
                            capture_total_output)

        with pytest.raises(StopAfterMetadataCapture):
            orchestrator._run_reporter()

        metadata = captured_output['total_output']['MetaData']
        assert metadata['OrgName'] == expected_metadata['OrgName']
        assert metadata['OrgUnitName'] == expected_metadata['OrgUnitName']


class TestOrchestrator:
    """Unit tests for the Orchestrator class."""

    # The test module needs to access "internal" Orchestrator methods.
    # pylint: disable=protected-access

    @pytest.fixture
    def orchestrator_paths(self, tmp_path):
        """Create filesystem paths required by ``start_automation``."""
        credentials = tmp_path / 'credentials.json'
        credentials.write_text('{}', encoding='utf-8')
        opa_dir = tmp_path / 'opa'
        opa_dir.mkdir()
        rego_dir = tmp_path / 'rego'
        rego_dir.mkdir()
        document_dir = tmp_path / 'baselines'
        document_dir.mkdir()
        output_dir = tmp_path / 'output'
        output_dir.mkdir()
        return {
            'credentials': credentials,
            'opapath': opa_dir,
            'regopath': rego_dir,
            'documentpath': document_dir,
            'outputpath': output_dir,
        }

    @pytest.fixture
    def base_args(self, orchestrator_paths):
        """Namespace with valid defaults for ``start_automation`` tests."""
        return MembershipNamespace(
            baselines=['gmail', 'calendar'],
            outputpath=orchestrator_paths['outputpath'],
            credentials=orchestrator_paths['credentials'],
            usemetadataserverauth=False,
            opapath=orchestrator_paths['opapath'],
            regopath=orchestrator_paths['regopath'],
            documentpath=orchestrator_paths['documentpath'],
            silencebodwarnings=True,
            OrgName='Test Organization',
            skipexport=False,
            runcached=False,
            outputfoldername='GWSBaselineReports',
            outputactionplanfilename='ActionPlan',
            outjsonfilename='ScubaResults',
            numberofuuidcharacterstotruncate=18,
        )

    @pytest.fixture
    def orchestrator(self, base_args):
        """Orchestrator instance bypassing MarkdownParser initialization."""
        instance = object.__new__(Orchestrator)
        instance._args = base_args
        instance.args_dict = vars(base_args)
        instance._baseline_policies = {}
        return instance

    def _patch_start_automation_dependencies(self, mocker, orchestrator):
        """Mock network, OPA lookup, and pipeline steps for start_automation."""
        mocker.patch.object(
            orchestrator,
            'notify_user_if_new_release_is_available',
        )
        mocker.patch.object(
            orchestrator_module,
            'find_opa',
        )
        providers = mocker.patch.object(orchestrator, '_run_gws_providers')
        rego = mocker.patch.object(orchestrator, '_rego_eval')
        reporter = mocker.patch.object(orchestrator, '_run_reporter')
        cached = mocker.patch.object(orchestrator, '_run_cached')
        return providers, rego, reporter, cached

    def test_start_automation_raises_error_if_no_credentials_file_provided(
            self,
            orchestrator,
            mocker,
    ):
        """Raise when credentials are missing and metadata auth is unused."""
        orchestrator._args.credentials = None
        mocker.patch.object(
            orchestrator,
            'notify_user_if_new_release_is_available',
        )

        with pytest.raises(UserRuntimeError, match='credentials file path'):
            orchestrator.start_automation()

    def test_start_automation_raises_error_if_no_opa_exe_exists(
            self,
            orchestrator,
            mocker,
    ):
        """Raise when the OPA executable cannot be found."""
        mocker.patch.object(
            orchestrator,
            'notify_user_if_new_release_is_available',
        )
        mocker.patch.object(
            orchestrator_module,
            'find_opa',
            side_effect=FileNotFoundError('opa missing'),
        )

        with pytest.raises(UserRuntimeError, match='OPA executable'):
            orchestrator.start_automation()

    def test_start_automation_logs_warning_if_orgname_missing(
            self,
            orchestrator,
            mocker,
            caplog,
    ):
        """Warn when OrgName is missing and BOD warnings are not silenced."""
        orchestrator._args.OrgName = None
        orchestrator._args.silencebodwarnings = False
        self._patch_start_automation_dependencies(mocker, orchestrator)

        with caplog.at_level(logging.WARNING):
            orchestrator.start_automation()

        assert 'Config file option OrgName not provided' in caplog.text

    def test_start_automation_raises_error_if_skipexport_used_without_runcached(
            self,
            orchestrator,
            mocker,
    ):
        """Raise when --skipexport is used without --runcached."""
        orchestrator._args.skipexport = True
        orchestrator._args.runcached = False
        self._patch_start_automation_dependencies(mocker, orchestrator)

        with pytest.raises(UserRuntimeError, match='skipexport'):
            orchestrator.start_automation()

    def test_start_automation_creates_timestamped_output_folder(
            self,
            orchestrator,
            mocker,
    ):
        """Create a timestamped output subdirectory when not running cached."""
        fixed_now = datetime(2026, 8, 3, 12, 30, 45)
        mock_datetime = mocker.patch.object(orchestrator_module, 'datetime')
        mock_datetime.now.return_value = fixed_now

        self._patch_start_automation_dependencies(mocker, orchestrator)

        parent_output = orchestrator._args.outputpath
        expected_folder = parent_output / 'GWSBaselineReports_2026_08_03_12_30_45'

        orchestrator.start_automation()

        assert orchestrator._args.outputpath == expected_folder.resolve()
        assert expected_folder.exists()
        assert expected_folder.is_dir()

    def test_start_automation_runs_providers_rego_reporter_without_runcached(
            self,
            orchestrator,
            mocker,
    ):
        """Run provider, rego, and reporter when runcached is False."""
        providers, rego, reporter, cached = (
            self._patch_start_automation_dependencies(mocker, orchestrator)
        )
        orchestrator._args.runcached = False

        orchestrator.start_automation()

        providers.assert_called_once_with()
        rego.assert_called_once_with()
        reporter.assert_called_once_with()
        cached.assert_not_called()

    def test_start_automation_runs_providers_rego_reporter_with_runcached(
            self,
            orchestrator,
            mocker,
    ):
        """Run the cached pipeline when runcached is True."""
        providers, rego, reporter, cached = (
            self._patch_start_automation_dependencies(mocker, orchestrator)
        )
        orchestrator._args.runcached = True

        orchestrator.start_automation()

        cached.assert_called_once_with()
        providers.assert_not_called()
        rego.assert_not_called()
        reporter.assert_not_called()

    def test_convert_to_result_csv_creates_action_plan(
            self,
            orchestrator,
            tmp_path,
    ):
        """Write failed controls into the action plan CSV."""
        output_dir = tmp_path / 'csv_output'
        output_dir.mkdir()
        orchestrator._args.outputpath = output_dir
        orchestrator._args.outputactionplanfilename = 'ActionPlan'

        output_dict = {
            'Results': {
                'gmail': [
                    {
                        'Controls': [
                            {
                                'ControlID': 'GWS.GMAIL.1.1v1',
                                'Requirement': '  Mail Delegation SHOULD be disabled.  ',
                                'Result': 'Fail',
                                'Criticality': 'Should',
                                'Details': (
                                    'The following OUs are non-compliant:'
                                    '<ul><li>Example OU: enabled</li></ul>'
                                ),
                            },
                            {
                                'ControlID': 'GWS.GMAIL.1.2v1',
                                'Requirement': 'Passing control',
                                'Result': 'Pass',
                                'Criticality': 'Shall',
                                'Details': 'Compliant',
                            },
                        ]
                    }
                ]
            }
        }

        orchestrator.convert_to_result_csv(output_dict)

        csv_path = output_dir / 'ActionPlan.csv'
        assert csv_path.exists()

        with csv_path.open(encoding='UTF-8', newline='') as csv_file:
            rows = list(csv.DictReader(csv_file))

        assert len(rows) == 1
        assert rows[0]['ControlID'] == 'GWS.GMAIL.1.1v1'
        assert rows[0]['Requirement'] == 'Mail Delegation SHOULD be disabled.'
        assert rows[0]['Result'] == 'Fail'
        assert rows[0]['Non-Compliance Reason'] == ' '
        assert rows[0]['Remediation Completion Date'] == ' '
        assert rows[0]['Justification'] == ' '
        assert '- Example OU: enabled' in rows[0]['Details']

    def test_convert_to_result_csv_only_creates_header_with_no_failed_controls(
            self,
            orchestrator,
            tmp_path,
            caplog,
    ):
        """Write only the CSV header when no controls failed."""
        output_dir = tmp_path / 'csv_header_only'
        output_dir.mkdir()
        orchestrator._args.outputpath = output_dir
        orchestrator._args.outputactionplanfilename = 'ActionPlan'

        output_dict = {
            'Results': {
                'gmail': [
                    {
                        'Controls': [
                            {
                                'ControlID': 'GWS.GMAIL.1.1v1',
                                'Requirement': 'Passing control',
                                'Result': 'Pass',
                                'Criticality': 'Shall',
                                'Details': 'Compliant',
                            }
                        ]
                    }
                ]
            }
        }

        with caplog.at_level(logging.INFO):
            orchestrator.convert_to_result_csv(output_dict)

        csv_path = output_dir / 'ActionPlan.csv'
        assert csv_path.exists()

        with csv_path.open(encoding='UTF-8', newline='') as csv_file:
            reader = csv.reader(csv_file)
            header = next(reader)
            remaining = list(reader)

        assert header == [
            'ControlID',
            'Requirement',
            'Result',
            'Criticality',
            'Details',
            'Non-Compliance Reason',
            'Remediation Completion Date',
            'Justification',
        ]
        assert not remaining
        assert 'No action required' in caplog.text

    def test_get_full_out_jsonfile_name_truncates_uuid(self, orchestrator):
        """Truncate the report UUID according to the configured character count."""
        report_uuid = '12345678-1234-1234-1234-123456789abc'
        orchestrator._args.outjsonfilename = 'ScubaResults'
        orchestrator._args.numberofuuidcharacterstotruncate = 18

        result = orchestrator._get_full_out_jsonfile_name(report_uuid)

        truncated_uuid = report_uuid[:-18]
        assert result == f'ScubaResults_{truncated_uuid}'

    def test_pluralize_returns_singular(self):
        """Return the singular form when the count is one."""
        assert Orchestrator._pluralize('pass', 'passes', 1) == 'pass'
        assert Orchestrator._pluralize('warning', 'warnings', 1) == 'warning'

    def test_pluralize_returns_plural(self):
        """Return the plural form when the count is not one."""
        assert Orchestrator._pluralize('pass', 'passes', 0) == 'passes'
        assert Orchestrator._pluralize('failure', 'failures', 2) == 'failures'

    def test_generate_summary_returns_correct_html_format(self):
        """Build the expected HTML summary fragments from stats."""
        stats = {
            'Passes': 2,
            'Warnings': 1,
            'Failures': 3,
            'Manual': 1,
            'Errors': 0,
            'Omit': 0,
            'IncorrectResults': 0,
        }

        summary = Orchestrator._generate_summary(stats)

        assert "<div class='summary pass'>2 passes</div>" in summary
        assert "<div class='summary warning'>1 warning</div>" in summary
        assert "<div class='summary failure'>3 failures</div>" in summary
        assert "<div class='summary manual'>1 manual check</div>" in summary
        # Empty placeholders remain when counts are zero
        assert summary.count("<div class='summary'></div>") == 3
