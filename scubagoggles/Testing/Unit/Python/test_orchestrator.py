"""Tests for ScubaGoggles orchestration."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import scubagoggles.orchestrator as orchestrator_module
from scubagoggles.orchestrator import Orchestrator


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
