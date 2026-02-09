"""Unit tests for the config.py module.

This module contains unit tests for the UserConfig class and its methods,
following the ScubaGoggles testing framework patterns.
"""

from pathlib import Path

import pytest

from scubagoggles.config import UserConfig


class TestUserConfig:
    """Test class for the UserConfig class methods."""

    @pytest.fixture
    def temp_dir(self, tmp_path):
        """Fixture providing a temporary directory for test files."""
        return tmp_path

    @pytest.fixture
    def valid_config_file(self):
        """Fixture providing path to valid configuration file."""
        return Path(__file__).parent / "snippets" / "custom_config.yaml"

    @pytest.fixture
    def invalid_config_file(self):
        """Fixture providing path to invalid configuration file."""
        return Path(__file__).parent / "snippets" / "invalid_config.yaml"

    def test_default_config_file_is_used(self, mocker):
        """Test that the default config file path is used when no config is provided."""
        # Mock the _transition_config_file to avoid legacy file checks
        mocker.patch.object(UserConfig, '_transition_config_file')
        # Mock Path.exists to return False so no file is loaded
        mocker.patch.object(Path, 'exists', return_value=False)

        config = UserConfig()

        # Verify the default config file path is used
        expected_default = Path('~/.scubagoggles/userdefaults.yaml').expanduser()
        assert config.config_path == expected_default
        assert config.file_exists is False

    def test_if_custom_config_file_is_used(self, valid_config_file, mocker):
        """Test that a custom config file is used when provided."""
        # Mock the _transition_config_file to avoid legacy file checks
        mocker.patch.object(UserConfig, '_transition_config_file')

        config = UserConfig(config_file=str(valid_config_file))

        # Verify the custom config file path is used
        assert config.config_path == valid_config_file
        assert config.file_exists is True
        # Verify config values are loaded from the custom file
        assert config.output_dir == Path('./output').expanduser()

    def test_if_custom_config_file_is_not_used(self, temp_dir, mocker):
        """Test behavior when custom config file does not exist."""
        # Mock the _transition_config_file to avoid legacy file checks
        mocker.patch.object(UserConfig, '_transition_config_file')

        # Provide a path to a non-existent config file
        non_existent_path = temp_dir / "non_existent_config.yaml"

        config = UserConfig(config_file=str(non_existent_path))

        # Verify the config path is set but file_exists is False
        assert config.config_path == non_existent_path
        assert config.file_exists is False
        # Verify default values are used
        assert config.opa_dir == Path('~/.scubagoggles').expanduser()
        assert config.output_dir == Path('./').expanduser()
        assert config.credentials_file is None

    def test_write_creates_config_file(self, temp_dir, mocker):
        """Test that write() creates the config file."""
        # Mock the _transition_config_file to avoid legacy file checks
        mocker.patch.object(UserConfig, '_transition_config_file')

        # Create a path for a new config file
        new_config_path = temp_dir / "new_config.yaml"

        # Ensure the file doesn't exist initially
        assert not new_config_path.exists()

        config = UserConfig(config_file=str(new_config_path))
        assert config.file_exists is False

        # Set some values using Path for cross-platform compatibility
        custom_output = temp_dir / 'custom' / 'output'
        creds_file = temp_dir / 'path' / 'to' / 'creds.json'
        config.output_dir = str(custom_output)
        config.credentials_file = str(creds_file)

        # Write the config
        config.write()

        # Verify the file was created
        assert new_config_path.exists()
        assert config.file_exists is True

        # Verify the content can be read back
        new_config = UserConfig(config_file=str(new_config_path))
        assert new_config.file_exists is True
        assert new_config.output_dir == custom_output
        assert new_config.credentials_file == creds_file

    def test_validate_raises_key_error(self, invalid_config_file, mocker):
        """Test that _validate raises KeyError for invalid configuration keys."""
        # Mock the _transition_config_file to avoid legacy file checks
        mocker.patch.object(UserConfig, '_transition_config_file')

        # Verify that creating UserConfig with invalid keys raises KeyError
        with pytest.raises(KeyError) as exc_info:
            UserConfig(config_file=str(invalid_config_file))

        # Verify the error message contains the invalid key
        assert 'invalid_key' in str(exc_info.value)
