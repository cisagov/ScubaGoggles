"""Unit tests for the scuba_argument_parser.py module.

This module contains unit tests for the ScubaArgumentParser class and its methods,
following the ScubaGoggles testing framework patterns.
"""

import argparse
import tempfile
import warnings
from pathlib import Path

import pytest
import yaml

from scubagoggles.scuba_argument_parser import ScubaArgumentParser


class TestScubaArgumentParser:  # pylint: disable=too-many-public-methods
    """Test class for the ScubaArgumentParser class methods."""

    def setup_method(self):
        """Setup method to ensure clean state for each test."""
        # Clear any warnings from previous tests
        warnings.resetwarnings()

    @pytest.fixture
    def mock_parser(self, mocker):
        """Fixture for mock argument parser."""
        parser = mocker.Mock(spec=argparse.ArgumentParser)
        return parser

    @pytest.fixture
    def sample_args(self):
        """Fixture providing sample parsed arguments."""
        args = argparse.Namespace()
        args.baselines = ['teams', 'sharepoint']
        args.outputpath = Path('/tmp/output')
        args.credentials = Path('/tmp/creds.json')
        args.config = None
        args.breakglassaccounts = []
        return args

    @pytest.fixture
    def sample_config_data(self):
        """Fixture providing sample configuration data."""
        return {
            'baselines': ['teams', 'sharepoint', 'onedrive'],
            'outputpath': '/custom/output',
            'credentials': '/custom/creds.json',
            'omitpolicy': ['teams.1.1v1', 'sharepoint.2.1v1'],
            'annotatepolicy': ['teams.1.2v1'],
            'orgname': 'TestOrg',
            'orgunitname': 'TestUnit'
        }

    def test_init(self, mock_parser):
        """Test ScubaArgumentParser initialization."""
        scuba_parser = ScubaArgumentParser(mock_parser)

        assert scuba_parser.parser == mock_parser
        assert hasattr(scuba_parser, '_param_to_alias')
        assert 'baselines' in scuba_parser._param_to_alias  # pylint: disable=protected-access
        assert 'outputpath' in scuba_parser._param_to_alias  # pylint: disable=protected-access
        assert 'credentials' in scuba_parser._param_to_alias  # pylint: disable=protected-access

    def test_parse_args(self, mock_parser):
        """Test parse_args method."""
        # Setup mock return value
        expected_args = argparse.Namespace()
        expected_args.baselines = ['teams']
        mock_parser.parse_args.return_value = expected_args

        scuba_parser = ScubaArgumentParser(mock_parser)
        result = scuba_parser.parse_args()

        mock_parser.parse_args.assert_called_once()
        assert result == expected_args

    def test_parse_args_with_config_no_config(self, mock_parser, sample_args):
        """Test parse_args_with_config when no config file is provided."""
        sample_args.config = None
        mock_parser.parse_args.return_value = sample_args

        scuba_parser = ScubaArgumentParser(mock_parser)
        result = scuba_parser.parse_args_with_config()

        assert result == sample_args
        assert result.breakglassaccounts == []

    def test_parse_args_with_config_with_file(self, mock_parser, sample_args,
                                              sample_config_data, mocker):
        """Test parse_args_with_config with a config file."""
        # Create temporary config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(sample_config_data, f)
            config_path = f.name

        try:
            sample_args.config = config_path
            mock_parser.parse_args.return_value = sample_args

            # Mock the validation method
            mock_validate = mocker.patch.object(ScubaArgumentParser, 'validate_config')

            scuba_parser = ScubaArgumentParser(mock_parser)
            result = scuba_parser.parse_args_with_config()

            # Config values should override args where CLI args weren't explicitly set
            # From config
            assert result.baselines == ['teams', 'sharepoint', 'onedrive']
            assert result.omitpolicy == ['teams.1.1v1', 'sharepoint.2.1v1']
            assert result.annotatepolicy == ['teams.1.2v1']

            # Validation should be called
            mock_validate.assert_called_once_with(result)

        finally:
            Path(config_path).unlink()

    def test_get_explicit_cli_args(self, sample_args):
        """Test _get_explicit_cli_args method."""
        # Create args with some values
        sample_args.baselines = ['teams']
        sample_args.outputpath = Path('/tmp/output')
        sample_args.verbose = True
        sample_args.config = None

        # pylint: disable=protected-access
        result = ScubaArgumentParser._get_explicit_cli_args(sample_args)

        # Result should be a namespace-like object
        assert hasattr(result, '__dict__')

    def test_validate_config_path_conversion(self):
        """Test validate_config method for path conversion."""
        args = argparse.Namespace()
        args.credentials = '/tmp/creds.json'  # String path
        args.outputpath = '/tmp/output'       # String path
        args.documentpath = '/tmp/docs'       # String path

        ScubaArgumentParser.validate_config(args)

        # Paths should be converted to Path objects
        assert isinstance(args.credentials, Path)
        assert isinstance(args.outputpath, Path)
        assert isinstance(args.documentpath, Path)

    def test_validate_config_orgname_conversion(self):
        """Test validate_config method for orgname conversion."""
        args = argparse.Namespace()
        args.orgname = 'testorg'
        args.orgunitname = 'testunit'

        ScubaArgumentParser.validate_config(args)

        # Should convert to PascalCase and remove original
        assert hasattr(args, 'OrgName')
        assert hasattr(args, 'OrgUnitName')
        assert args.OrgName == 'testorg'
        assert args.OrgUnitName == 'testunit'
        assert not hasattr(args, 'orgname')
        assert not hasattr(args, 'orgunitname')

    def test_validate_config_calls_validation_methods(self, mocker):
        """Test validate_config calls omission and annotation validation when needed."""
        mock_validate_omissions = mocker.patch.object(
            ScubaArgumentParser, 'validate_omissions')
        mock_validate_annotations = mocker.patch.object(
            ScubaArgumentParser, 'validate_annotations')

        args = argparse.Namespace()
        args.omitpolicy = ['teams.1.1v1']
        args.annotatepolicy = ['sharepoint.2.1v1']

        ScubaArgumentParser.validate_config(args)

        mock_validate_omissions.assert_called_once_with(args)
        mock_validate_annotations.assert_called_once_with(args)

    def test_validate_omissions(self, mocker):
        """Test validate_omissions method."""
        # Mock the MarkdownParser and its methods
        mock_md_parser = mocker.Mock()
        mock_md_parser.parse_baselines.return_value = {
            'teams': [
                {
                    'Controls': [
                        {'Id': 'teams.1.1v1'},
                        {'Id': 'teams.1.2v1'}
                    ]
                }
            ]
        }
        mocker.patch('scubagoggles.scuba_argument_parser.MarkdownParser',
                     return_value=mock_md_parser)

        # Mock warnings
        mock_warn = mocker.patch('warnings.warn')

        args = argparse.Namespace()
        args.baselines = ['teams']
        args.documentpath = Path('/tmp/docs')
        args.omitpolicy = ['teams.1.1v1', 'invalid.control.id']

        ScubaArgumentParser.validate_omissions(args)

        # Should warn about invalid control ID
        mock_warn.assert_called_once()
        warning_message = mock_warn.call_args[0][0]
        assert 'invalid.control.id' in warning_message

    def test_validate_annotations(self, mocker):
        """Test validate_annotations method."""
        # Mock the MarkdownParser and its methods
        mock_md_parser = mocker.Mock()
        mock_md_parser.parse_baselines.return_value = {
            'sharepoint': [
                {
                    'Controls': [
                        {'Id': 'sharepoint.1.1v1'},
                        {'Id': 'sharepoint.1.2v1'}
                    ]
                }
            ]
        }
        mocker.patch('scubagoggles.scuba_argument_parser.MarkdownParser',
                     return_value=mock_md_parser)

        # Mock warnings
        mock_warn = mocker.patch('warnings.warn')

        args = argparse.Namespace()
        args.baselines = ['sharepoint']
        args.documentpath = Path('/tmp/docs')
        args.annotatepolicy = ['sharepoint.1.1v1', 'nonexistent.control.id']

        ScubaArgumentParser.validate_annotations(args)

        # Should warn about invalid control ID
        mock_warn.assert_called_once()
        warning_message = mock_warn.call_args[0][0]
        assert 'nonexistent.control.id' in warning_message

    def test_param_to_alias_mapping(self):
        """Test that parameter to alias mapping is correct."""
        parser = ScubaArgumentParser(None)

        expected_mappings = {
            'baselines': 'b',
            'outputpath': 'o',
            'credentials': 'c'
        }

        assert parser._param_to_alias == expected_mappings  # pylint: disable=protected-access

    def test_config_file_alias_translation(self, mock_parser, sample_args, mocker):
        """Test that config file short aliases are translated to long form."""
        config_data = {
            'b': ['teams'],  # Short form for baselines
            'o': '/tmp/output',  # Short form for outputpath
            'c': '/tmp/creds.json'  # Short form for credentials
        }

        # Create temporary config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name

        try:
            sample_args.config = config_path
            sample_args.baselines = ['original']  # This should be overridden
            mock_parser.parse_args.return_value = sample_args

            # Mock validation
            mocker.patch.object(ScubaArgumentParser, 'validate_config')

            scuba_parser = ScubaArgumentParser(mock_parser)
            result = scuba_parser.parse_args_with_config()

            # Short aliases should be translated to long form
            assert result.baselines == ['teams']
            assert result.outputpath == '/tmp/output'
            assert result.credentials == '/tmp/creds.json'

        finally:
            Path(config_path).unlink()

    def test_cli_args_override_config(self, mock_parser, sample_args, mocker):
        """Test that CLI arguments take precedence over config file."""
        config_data = {
            'baselines': ['config_baseline'],
            'outputpath': '/config/output'
        }

        # Create temporary config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name

        try:
            sample_args.config = config_path
            sample_args.baselines = ['cli_baseline']  # CLI should override config
            mock_parser.parse_args.return_value = sample_args

            # Mock validation and _get_explicit_cli_args to simulate CLI override
            mocker.patch.object(ScubaArgumentParser, 'validate_config')
            mocker.patch.object(ScubaArgumentParser, '_get_explicit_cli_args',
                              return_value={'baselines': ['cli_baseline']})

            scuba_parser = ScubaArgumentParser(mock_parser)
            result = scuba_parser.parse_args_with_config()

            # CLI args should take precedence
            assert result.baselines == ['cli_baseline']
            # Config values should be used where CLI didn't override
            assert result.outputpath == '/config/output'

        finally:
            Path(config_path).unlink()
