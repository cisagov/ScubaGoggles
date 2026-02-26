"""Unit tests for the user_setup.py module.

This module contains unit tests for the user setup functions,
following the ScubaGoggles testing framework patterns.
"""

import argparse

import pytest

from scubagoggles.user_setup import (
    user_setup,
    user_directory,
    create_dir_download_opa,
    validate_opa_dir,
    credentials_file
)


class TestUserSetup:

    """Test class for the user_setup.py module functions.
    """

    @pytest.fixture
    def temp_dir(self, tmp_path):

        """Fixture providing a temporary directory for test files.
        """

        return tmp_path

    @pytest.fixture
    def mock_user_config(self, mocker, tmp_path):

        """Fixture providing a mock UserConfig object.
        """

        config = mocker.Mock()
        config.credentials_file = None
        config.file_exists = False
        config.opa_dir = tmp_path / 'opa'
        config.output_dir = tmp_path / 'output'
        config.write = mocker.Mock()
        return config

    @pytest.fixture
    def mock_arguments(self, mocker, mock_user_config):

        """Fixture providing mock arguments namespace.
        """

        args = mocker.Mock(spec=argparse.Namespace)
        args.credentials = None
        args.nocheck = False
        args.nodownload = False
        args.opapath = None
        args.outputpath = None
        args.user_config = mock_user_config
        return args

    def test_user_setup(self, mock_arguments, mocker, capsys):

        """Test the main user_setup function.
        """

        # Mock the sub-functions to isolate user_setup behavior
        mock_user_dir = mocker.patch('scubagoggles.user_setup.user_directory',
                                     return_value=True)
        mock_opa_dir = mocker.patch('scubagoggles.user_setup.opa_directory',
                                    return_value=False)
        mock_creds = mocker.patch('scubagoggles.user_setup.credentials_file',
                                  return_value=False)

        user_setup(mock_arguments)

        # Verify all sub-functions were called
        mock_user_dir.assert_called_once_with(mock_arguments)
        mock_opa_dir.assert_called_once_with(mock_arguments)
        mock_creds.assert_called_once_with(mock_arguments)

        # Verify config.write() was called since modified=True
        mock_arguments.user_config.write.assert_called_once()

        # Verify output was printed
        captured = capsys.readouterr()
        assert 'Configured default locations:' in captured.out

    def test_user_setup_no_modifications(self, mock_arguments, mocker):

        """Test user_setup when no modifications are made.
        """

        mocker.patch('scubagoggles.user_setup.user_directory', return_value=False)
        mocker.patch('scubagoggles.user_setup.opa_directory', return_value=False)
        mocker.patch('scubagoggles.user_setup.credentials_file', return_value=False)

        user_setup(mock_arguments)

        # Verify config.write() was NOT called since no modifications
        mock_arguments.user_config.write.assert_not_called()

    def test_user_directory(self, mock_arguments, temp_dir):

        """Test the user_directory function.
        """

        # Test when outputpath is not specified
        result = user_directory(mock_arguments)
        assert result is False

        # Test when outputpath is specified and directory exists
        output_path = temp_dir / 'test_output'
        output_path.mkdir()
        mock_arguments.outputpath = output_path
        result = user_directory(mock_arguments)
        assert result is True
        assert mock_arguments.user_config.output_dir.samefile(output_path)

    def test_user_directory_creates_dir(self, mock_arguments, temp_dir):

        """Test that user_directory creates directory if it doesn't exist.
        """

        new_output_path = temp_dir / 'new_output'
        mock_arguments.outputpath = new_output_path
        mock_arguments.nocheck = False

        assert not new_output_path.exists()
        result = user_directory(mock_arguments)

        assert result is True
        assert new_output_path.exists()

    def test_user_directory_raises_not_a_directory(self, mock_arguments, temp_dir):

        """Test that user_directory raises error when path is not a directory.
        """

        # Create a file instead of directory
        file_path = temp_dir / 'not_a_dir'
        file_path.write_text('test')
        mock_arguments.outputpath = file_path
        mock_arguments.nocheck = False

        with pytest.raises(NotADirectoryError):
            user_directory(mock_arguments)

    def test_create_dir_download_opa(self, temp_dir, mocker):

        """Test the create_dir_download_opa function.
        """

        # Mock download_opa and opa_filespec to avoid actual downloads
        mocker.patch('scubagoggles.user_setup.download_opa')
        mocker.patch('scubagoggles.user_setup.opa_filespec',
                     return_value=temp_dir / 'opa_executable')

        # Test creating directory when it doesn't exist
        opa_dir = temp_dir / 'opa_dir'
        assert not opa_dir.exists()

        create_dir_download_opa(opa_dir, create_dir=True, download=False)
        assert opa_dir.exists()

    def test_create_dir_download_opa_downloads(self, temp_dir, mocker):

        """Test that create_dir_download_opa downloads OPA when needed.
        """

        opa_dir = temp_dir / 'opa_dir'
        opa_dir.mkdir()

        # Mock opa_filespec to return a non-existent file
        opa_exe = opa_dir / 'opa_executable'
        mocker.patch('scubagoggles.user_setup.opa_filespec', return_value=opa_exe)
        mock_download = mocker.patch('scubagoggles.user_setup.download_opa')

        create_dir_download_opa(opa_dir, create_dir=True, download=True)

        # Verify download was called since OPA doesn't exist
        mock_download.assert_called_once_with(opa_dir, verify=True)

    def test_create_dir_download_opa_skips_download_if_exists(self, temp_dir, mocker):

        """Test that create_dir_download_opa skips download if OPA exists.
        """

        opa_dir = temp_dir / 'opa_dir'
        opa_dir.mkdir()

        # Create a mock OPA executable file
        opa_exe = opa_dir / 'opa_executable'
        opa_exe.write_text('mock opa')
        mocker.patch('scubagoggles.user_setup.opa_filespec', return_value=opa_exe)
        mock_download = mocker.patch('scubagoggles.user_setup.download_opa')

        create_dir_download_opa(opa_dir, create_dir=True, download=True)

        # Verify download was NOT called since OPA exists
        mock_download.assert_not_called()

    def test_create_dir_download_opa_raises_not_a_directory(self, temp_dir):

        """Test that create_dir_download_opa raises error for non-directory.
        """

        # Create a file instead of directory
        file_path = temp_dir / 'not_a_dir'
        file_path.write_text('test')

        with pytest.raises(NotADirectoryError):
            create_dir_download_opa(file_path, create_dir=True, download=False)

    def test_validate_opa_dir(self, temp_dir, mocker):

        """Test the validate_opa_dir function.
        """

        # Mock find_opa to return a valid path
        opa_exe = temp_dir / 'opa'
        mocker.patch('scubagoggles.user_setup.find_opa', return_value=opa_exe)

        result = validate_opa_dir(temp_dir)
        assert result is True

    def test_validate_opa_dir_not_found(self, temp_dir, mocker):

        """Test validate_opa_dir when OPA is not found.
        """

        mocker.patch('scubagoggles.user_setup.find_opa',
                     side_effect=FileNotFoundError('OPA not found'))

        result = validate_opa_dir(temp_dir)
        assert result is False

    def test_validate_opa_dir_path_is_file(self, temp_dir):

        """Test validate_opa_dir when path is a file, not directory.
        """

        file_path = temp_dir / 'not_a_dir'
        file_path.write_text('test')

        result = validate_opa_dir(file_path)
        assert result is False

    def test_validate_opa_dir_no_path(self, mocker):

        """Test validate_opa_dir with no path (searches PATH).
        """

        mocker.patch('scubagoggles.user_setup.find_opa', return_value=None)

        result = validate_opa_dir()
        assert result is False

    def test_credentials_file(self, mock_arguments, temp_dir):

        """Test the credentials_file function.
        """

        # Test when credentials is not specified
        result = credentials_file(mock_arguments)
        assert result is False

        # Test when credentials is specified and file exists
        creds_path = temp_dir / 'credentials.json'
        creds_path.write_text('{"test": "credentials"}')
        mock_arguments.credentials = creds_path

        result = credentials_file(mock_arguments)
        assert result is True
        assert mock_arguments.user_config.credentials_file.samefile(creds_path)

    def test_credentials_file_not_found(self, mock_arguments, temp_dir):

        """Test credentials_file raises error when file doesn't exist.
        """

        non_existent = temp_dir / 'non_existent.json'
        mock_arguments.credentials = non_existent
        mock_arguments.nocheck = False

        with pytest.raises(FileNotFoundError):
            credentials_file(mock_arguments)

    def test_credentials_file_nocheck(self, mock_arguments, temp_dir):

        """Test credentials_file with nocheck=True skips file validation.
        """

        non_existent = temp_dir / 'non_existent.json'
        mock_arguments.credentials = non_existent
        mock_arguments.nocheck = True

        # Should not raise even though file doesn't exist
        result = credentials_file(mock_arguments)
        assert result is True
