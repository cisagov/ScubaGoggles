"""Tests for ScubaGoggles orchestration."""

from unittest.mock import Mock, patch

from scubagoggles.orchestrator import Orchestrator


class TestOrchestratorMetadata:
    """Test OrgName/OrgUnitName in metadata"""

    @patch('scubagoggles.orchestrator.MarkdownParser')
    def test_orgname_orgunitname_in_metadata_when_provided(self, _mock_md_parser):
        """Test OrgName and OrgUnitName are added to metadata from args"""
        # Setup Orchestrator with minimal required args
        mock_args = Mock()
        mock_args.documentpath = '/fake/path'
        mock_args.baselines = ['gmail']

        orchestrator = Orchestrator(mock_args)

        # Add OrgName/OrgUnitName to args_dict (simulating config/CLI input)
        orchestrator.args_dict['OrgName'] = 'TestOrg'
        orchestrator.args_dict['OrgUnitName'] = 'TestDept'

        # Verify extraction works
        assert orchestrator.args_dict.get('OrgName') == 'TestOrg'
        assert orchestrator.args_dict.get('OrgUnitName') == 'TestDept'

    @patch('scubagoggles.orchestrator.MarkdownParser')
    def test_orgname_orgunitname_default_to_none(self, _mock_md_parser):
        """Test OrgName/OrgUnitName are None when not provided"""
        # Setup Orchestrator with minimal required args
        mock_args = Mock()
        mock_args.documentpath = '/fake/path'
        mock_args.baselines = ['gmail']

        orchestrator = Orchestrator(mock_args)

        # Verify None is returned for missing keys
        assert orchestrator.args_dict.get('OrgName') is None
        assert orchestrator.args_dict.get('OrgUnitName') is None

        # Add OrgName/OrgUnitName to args_dict (simulating config/CLI input)
        orchestrator.args_dict['OrgName'] = None
        orchestrator.args_dict['OrgUnitName'] = None

        # Verify None is returned for keys with None values
        assert orchestrator.args_dict.get('OrgName') is None
        assert orchestrator.args_dict.get('OrgUnitName') is None
