"""Unit tests for the version.py module.

This module contains unit tests for the Version class and its methods,
following the ScubaGoggles testing framework patterns.
"""

import argparse
import csv
import logging
import pytest
import re
import tempfile
from collections import defaultdict
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

from scubagoggles.version import Version


class TestVersion:
    """Test class for the Version class methods."""
    
    def setup_method(self):
        """Setup method to ensure clean state for each test."""
        Version._baseline_version_map = {}

    @pytest.fixture
    def mock_arguments_check(self):
        """Fixture for mock arguments with check option."""
        args = Mock(spec=argparse.Namespace)
        args.check = True
        args.upgrade = False
        return args

    @pytest.fixture
    def mock_arguments_upgrade(self):
        """Fixture for mock arguments with upgrade option."""
        args = Mock(spec=argparse.Namespace)
        args.check = False
        args.upgrade = "2.0.0"
        return args

    @pytest.fixture
    def mock_arguments_default(self):
        """Fixture for mock arguments with no options."""
        args = Mock(spec=argparse.Namespace)
        args.check = False
        args.upgrade = False
        return args

    @pytest.fixture
    def sample_policy_data(self):
        """Fixture providing sample policy ID data for testing."""
        return {
            'valid_single': 'GWS.CHAT.1.0v1',
            'valid_multiple': 'GWS.CHAT.1.0v1 and GWS.GMAIL.2.1v2',
            'invalid_suffix': 'GWS.CHAT.1.0v0',
            'mixed_valid_invalid': 'GWS.CHAT.1.0v1 and GWS.GMAIL.2.1v0',
            'no_policy_ids': 'This is just regular text with no policy IDs',
            'malformed_policy': 'GWS.INVALID.FORMAT'
        }

    @pytest.fixture
    def temp_csv_file(self):
        """Fixture creating a temporary CSV file for testing."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            writer = csv.DictWriter(f, fieldnames=['PolicyId', 'Description'])
            writer.writeheader()
            writer.writerow({'PolicyId': 'GWS.CHAT.1.0v0', 'Description': 'Test policy'})
            writer.writerow({'PolicyId': 'GWS.DRIVE.3.0v0', 'Description': 'Another policy'})
            temp_path = Path(f.name)
        
        yield temp_path
        
        # Cleanup
        if temp_path.exists():
            temp_path.unlink()

    @pytest.fixture
    def temp_md_file(self):
        """Fixture creating a temporary Markdown file for testing."""
        content = """# Test Markdown File
        
This file contains policy IDs like GWS.CHAT.1.0v0 and others.
Some regular text without policy IDs.
Another policy: GWS.DRIVE.3.0v0
Same policy again: GWS.CHAT.1.0v0
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(content)
            temp_path = Path(f.name)
        
        yield temp_path
        
        # Cleanup
        if temp_path.exists():
            temp_path.unlink()

    def test_command_dispatch_check(self, mock_arguments_check, capsys):
        """Test command_dispatch with check option."""
        with patch.object(Version, 'check_versions') as mock_check:
            Version.command_dispatch(mock_arguments_check)
            
            captured = capsys.readouterr()
            assert 'ScubaGoggles version check' in captured.out
            mock_check.assert_called_once()

    def test_command_dispatch_upgrade(self, mock_arguments_upgrade, capsys):
        """Test command_dispatch with upgrade option."""
        with patch.object(Version, 'set') as mock_set:
            Version.command_dispatch(mock_arguments_upgrade)
            
            captured = capsys.readouterr()
            assert 'ScubaGoggles version upgrade (2.0.0)' in captured.out
            mock_set.assert_called_once_with("2.0.0")

    def test_command_dispatch_default(self, mock_arguments_default, capsys):
        """Test command_dispatch with no options (default behavior)."""
        Version.command_dispatch(mock_arguments_default)
        
        captured = capsys.readouterr()
        assert Version.with_name in captured.out

    @pytest.mark.parametrize("data,expected_success", [
        ("GWS.CHAT.1.0v0", True),
        ("GWS.CHAT.1.0v0 and GWS.GMAIL.2.1v0", True),
        ("No policy IDs here", True),
    ])
    def test_check_version(self, data, expected_success):
        """Test check_version method with various input data."""
        success, errors = Version.check_version(data)
        
        assert success == expected_success
        if not expected_success:
            assert len(errors) > 0

    def test_check_version_consistent_suffixes(self):
        """Test check_version with consistent version suffixes."""
        
        # First call establishes the baseline
        success1, errors1 = Version.check_version("GWS.CHAT.1.0v0")
        assert success1 is True
        assert errors1 == {}
        
        # Second call with same suffix should succeed
        success2, errors2 = Version.check_version("GWS.CHAT.1.0v0")
        assert success2 is True
        assert errors2 == {}
        
        # Third call with different suffix should fail
        success3, errors3 = Version.check_version("GWS.CHAT.1.0v1")
        assert success3 is False
        assert "GWS.CHAT.1.0" in errors3

    def test_check_versions(self):
        """Test check_versions method."""
        with patch.object(Version, 'check_or_update_readme', return_value=False) as mock_readme, \
             patch.object(Version, 'check_md') as mock_md, \
             patch.object(Version, 'check_csv') as mock_csv, \
             patch('pathlib.Path.glob') as mock_glob, \
             patch.object(Path, 'is_dir', return_value=True):
            
            # Mock file paths
            mock_md_files = [Path('test1.md'), Path('test2.md')]
            mock_csv_files = [Path('test1.csv'), Path('test2.csv')]
            
            # Configure glob to return different results based on pattern
            def glob_side_effect(pattern):
                if pattern == '**/*.md':
                    return mock_md_files
                elif pattern == '*.csv':
                    return mock_csv_files
                return []
            
            mock_glob.side_effect = glob_side_effect
            
            result = Version.check_versions()
            
            mock_readme.assert_called_once_with(False)
            assert mock_md.call_count == len(mock_md_files)
            assert mock_csv.call_count == len(mock_csv_files)
            assert result is False

    def test_check_versions_update_mode(self):
        """Test check_versions method in update mode."""
        with patch.object(Version, 'check_or_update_readme', return_value=True) as mock_readme, \
             patch.object(Version, 'check_md') as mock_md, \
             patch.object(Version, 'check_csv') as mock_csv, \
             patch('pathlib.Path.glob', return_value=[]), \
             patch.object(Path, 'is_dir', return_value=True):
            
            result = Version.check_versions(update=True)
            
            mock_readme.assert_called_once_with(True)
            assert result is True

    def test_check_versions_missing_drift_rules_dir(self):
        """Test check_versions when drift-rules directory is missing."""
        with patch.object(Version, 'check_or_update_readme', return_value=False), \
             patch('pathlib.Path.glob', return_value=[]), \
             patch.object(Path, 'is_dir', return_value=False):
            
            with pytest.raises(NotADirectoryError):
                Version.check_versions()

    def test_check_csv_valid(self, temp_csv_file):
        """Test check_csv with valid CSV file."""
        
        result = Version.check_csv(temp_csv_file)
        
        assert result is True

    def test_check_csv_invalid_policy_id(self):
        """Test check_csv with invalid policy ID format."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            writer = csv.DictWriter(f, fieldnames=['PolicyId', 'Description'])
            writer.writeheader()
            writer.writerow({'PolicyId': 'INVALID.FORMAT', 'Description': 'Invalid policy'})
            temp_path = Path(f.name)
        
        try:
            Version._baseline_version_map = {}
            
            with patch('scubagoggles.version.log') as mock_log:
                result = Version.check_csv(temp_path)
                
                assert result is False
                mock_log.error.assert_called()
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_check_md_valid(self, temp_md_file):
        """Test check_md with valid Markdown file."""
        
        result = Version.check_md(temp_md_file)
        
        assert result is True

    def test_check_md_invalid_versions(self):
        """Test check_md with invalid version suffixes."""
        # Create content with inconsistent version suffixes for the same policy
        content = """This file has policies:
GWS.CHAT.1.0v0 first occurrence
GWS.CHAT.1.0v1 second occurrence with different suffix
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(content)
            temp_path = Path(f.name)
        
        try:
            Version._baseline_version_map = {}
            
            with patch('scubagoggles.version.log') as mock_log:
                result = Version.check_md(temp_path)
                
                assert result is False
                mock_log.error.assert_called()
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_check_or_update_readme_no_file(self):
        """Test check_or_update_readme when README file doesn't exist."""
        with patch.object(Path, 'exists', return_value=False):
            result = Version.check_or_update_readme()
            assert result is False

    def test_check_or_update_readme_check_mode(self):
        """Test check_or_update_readme in check mode."""
        readme_content = "Download ScubaGoggles-v1.0.0 from GitHub"
        
        with patch.object(Path, 'exists', return_value=True), \
             patch.object(Path, 'read_text', return_value=readme_content), \
             patch('scubagoggles.version.log') as mock_log:
            
            result = Version.check_or_update_readme(update=False)
            
            # Should detect version mismatch and log error
            mock_log.error.assert_called()
            assert result is True

    def test_check_or_update_readme_update_mode(self):
        """Test check_or_update_readme in update mode."""
        readme_content = "Download ScubaGoggles-v1.0.0 from GitHub"
        updated_content = f"Download ScubaGoggles-{Version.current} from GitHub"
        
        with patch.object(Path, 'exists', return_value=True), \
             patch.object(Path, 'read_text', return_value=readme_content), \
             patch.object(Path, 'write_text') as mock_write, \
             patch('scubagoggles.version.log') as mock_log:
            
            result = Version.check_or_update_readme(update=True)
            
            mock_write.assert_called_once()
            mock_log.debug.assert_called()
            assert result is True

    @pytest.mark.parametrize("version,should_raise", [
        ("2.0.0", False),
        ("1.5.3", False),
        ("10.20.30", False),
        ("2.0", True),
        ("2.0.0.1", True),
        ("v2.0.0", True),
        ("invalid", True),
    ])
    def test_set_version_validation(self, version, should_raise):
        """Test set method with various version formats."""
        if should_raise:
            with pytest.raises(ValueError):
                Version.set(version)
        else:
            with patch.object(Path, 'exists', return_value=True), \
                 patch.object(Path, 'read_text', return_value="__version__ = '1.0.0'"), \
                 patch.object(Path, 'write_text') as mock_write, \
                 patch.object(Version, 'initialize') as mock_init, \
                 patch.object(Version, 'check_versions') as mock_check:
                
                Version.set(version)
                
                mock_write.assert_called_once()
                mock_init.assert_called_once_with(version)
                mock_check.assert_called_once_with(True)

    def test_set_missing_init_file(self):
        """Test set method when __init__.py file is missing."""
        with patch.object(Path, 'exists', return_value=False):
            with pytest.raises(FileNotFoundError):
                Version.set("2.0.0")

    def test_set_no_changes_needed(self):
        """Test set method when no changes are needed."""
        current_content = "__version__ = '2.0.0'"
        
        with patch.object(Path, 'exists', return_value=True), \
             patch.object(Path, 'read_text', return_value=current_content), \
             patch('scubagoggles.version.log') as mock_log:
            
            Version.set("2.0.0")
            
            mock_log.error.assert_called_with('? ScubaGoggles version set - no changes made')

    @pytest.mark.parametrize("suffix,expected", [
        ("v1", True),
        ("v2", True),
        ("v10", True),
        ("v1.0", True),
        ("v2.5", True),
        ("v0", True),  # v0 is actually valid according to the regex
        ("1", False),
        ("version1", False),
        ("", False),
    ])
    def test_is_valid_suffix(self, suffix, expected):
        """Test is_valid_suffix method with various suffix formats."""
        result = Version.is_valid_suffix(suffix)
        assert result == expected

    def test_log_version_errors(self):
        """Test log_version_errors static method."""
        errors = {
            "GWS.CHAT.1.0": ["v1", "v0", "v2"],
            "GWS.GMAIL.2.1": ["v2", "v1"]
        }
        
        with patch('scubagoggles.version.log') as mock_log:
            Version.log_version_errors(42, errors)
            
            # Should log error for each policy ID
            assert mock_log.error.call_count == len(errors)
            
            # Check that line number and policy details are included
            for call in mock_log.error.call_args_list:
                args = call[0]
                assert 42 in args  # line number
                assert any(policy_id in str(args) for policy_id in errors.keys())

    def test_initialize_method(self):
        """Test initialize class method."""
        test_version = "3.5.7"
        
        Version.initialize(test_version)
        
        assert Version.current == f"v{test_version}"
        assert Version.number == test_version
        assert Version.with_name == f"{Version.name} v{test_version}"
        assert Version.major == 3
        assert Version.minor == 5
        assert Version.build == 7
        assert Version.suffix == "v3"

    def test_class_attributes_initialization(self):
        """Test that class attributes are properly initialized."""
        # Test that class attributes exist and have expected types
        assert isinstance(Version.current, str)
        assert isinstance(Version.name, str)
        assert isinstance(Version.number, str)
        assert isinstance(Version.with_name, str)
        assert isinstance(Version.major, int)
        assert isinstance(Version.minor, int)
        assert isinstance(Version.build, int)
        assert isinstance(Version.suffix, str)
        assert isinstance(Version._code_root, Path)
        assert hasattr(Version, 'suffix_re')
        assert hasattr(Version, 'version_re')

    def test_version_regex_patterns(self):
        """Test the compiled regex patterns."""
        # Test suffix regex
        suffix_match = Version.suffix_re.match("v1")
        assert suffix_match is not None
        assert suffix_match.group('major') == '1'
        
        suffix_match_minor = Version.suffix_re.match("v2.5")
        assert suffix_match_minor is not None
        assert suffix_match_minor.group('major') == '2'
        assert suffix_match_minor.group('minor') == '5'
        
        # Test version regex
        version_match = Version.version_re.match("GWS.CHAT.1.0v1")
        assert version_match is not None
        assert version_match.group('policy_id') == 'GWS.CHAT.1.0'
        assert version_match.group('sfx') == 'v1'
