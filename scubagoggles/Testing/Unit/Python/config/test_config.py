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
    def valid_config_content(self):
        """Fixture providing valid configuration content."""
        return """scubagoggles:
  opa_dir: ~/.scubagoggles
  output_dir: ./output
  credentials: /path/to/credentials.json
"""

    @pytest.fixture
    def invalid_config_content(self):
        """Fixture providing configuration content with invalid keys."""
        return """scubagoggles:
  opa_dir: ~/.scubagoggles
  invalid_key: some_value
  output_dir: ./output
"""

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

    def test_if_custom_config_file_is_used(self, temp_dir, valid_config_content, mocker):
        """Test that a custom config file is used when provided."""
        # Mock the _transition_config_file to avoid legacy file checks
        mocker.patch.object(UserConfig, '_transition_config_file')

        # Create a custom config file
        custom_config_path = temp_dir / "custom_config.yaml"
        custom_config_path.write_text(valid_config_content)

        config = UserConfig(config_file=str(custom_config_path))

        # Verify the custom config file path is used
        assert config.config_path == custom_config_path
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

        # Set some values
        config.output_dir = '/custom/output'
        config.credentials_file = '/path/to/creds.json'

        # Write the config
        config.write()

        # Verify the file was created
        assert new_config_path.exists()
        assert config.file_exists is True

        # Verify the content can be read back
        new_config = UserConfig(config_file=str(new_config_path))
        assert new_config.file_exists is True
        assert str(new_config.output_dir) == '/custom/output'
        assert str(new_config.credentials_file) == '/path/to/creds.json'

    def test_validate_raises_key_error(self, temp_dir, invalid_config_content, mocker):
        """Test that _validate raises KeyError for invalid configuration keys."""
        # Mock the _transition_config_file to avoid legacy file checks
        mocker.patch.object(UserConfig, '_transition_config_file')

        # Create a config file with invalid keys
        invalid_config_path = temp_dir / "invalid_config.yaml"
        invalid_config_path.write_text(invalid_config_content)

        # Verify that creating UserConfig with invalid keys raises KeyError
        with pytest.raises(KeyError) as exc_info:
            UserConfig(config_file=str(invalid_config_path))

        # Verify the error message contains the invalid key
        assert 'invalid_key' in str(exc_info.value)
