"""Tests for the run_rego module.

This module contains unit tests for the run_rego module functions,
following the ScubaGoggles testing framework patterns.
"""

import json
import logging
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# The import is needed as stated and not how pylint wants it.
# pylint: disable=consider-using-from-import
import scubagoggles.run_rego as run_rego

from scubagoggles.run_rego import find_opa, log_rego_output, opa_eval


class TestRunRego:
    """Test class for the run_rego module functions."""

    # The test module needs to access "internal" module state.
    # pylint: disable=protected-access

    def setup_method(self):
        """Setup method to ensure clean state for each test."""
        # Reset the global OPA_EXE before each test
        run_rego.OPA_EXE = None

    @pytest.fixture
    def opa_test_files(self, tmp_path):
        """Fixture providing mock input and rego files for opa_eval tests.

        Returns a dict with:
            - input_file: Path to the mock input JSON file
            - rego_path: Path to the directory containing mock rego files
            - tmp_path: The temporary directory path
        """
        input_file = tmp_path / "input.json"
        input_file.write_text('{"test": "data"}')

        rego_path = tmp_path / "rego"
        rego_path.mkdir()
        (rego_path / "Test.rego").write_text("package test")
        (rego_path / "Utils.rego").write_text("package utils")

        return {
            'input_file': input_file,
            'rego_path': rego_path,
            'tmp_path': tmp_path
        }

    # =========================================================================
    # Tests for opa_eval
    # =========================================================================

    def test_opa_eval_success(self, monkeypatch, opa_test_files):
        """Tests that opa_eval successfully runs OPA and returns parsed JSON."""

        input_file = opa_test_files['input_file']
        rego_path = opa_test_files['rego_path']
        tmp_path = opa_test_files['tmp_path']

        # Mock the OPA executable path
        mock_opa_exe = tmp_path / "opa.exe"
        monkeypatch.setattr(run_rego, 'OPA_EXE', mock_opa_exe)

        # Mock subprocess.run to return valid JSON output
        expected_output = [{"test_result": "pass"}]
        mock_result = MagicMock()
        mock_result.stdout = json.dumps(expected_output).encode()

        def mock_subprocess_run(_command, **_kwargs):
            return mock_result

        monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)

        result = opa_eval(
            product_name='test',
            input_file=str(input_file),
            opa_path=tmp_path,
            rego_path=rego_path,
            debug=False
        )

        assert result == expected_output

    def test_opa_eval_with_debug(self, monkeypatch, opa_test_files, caplog):
        """Tests that opa_eval includes --explain=full flag when debug is True."""

        input_file = opa_test_files['input_file']
        rego_path = opa_test_files['rego_path']
        tmp_path = opa_test_files['tmp_path']

        # Mock the OPA executable path
        mock_opa_exe = tmp_path / "opa.exe"
        monkeypatch.setattr(run_rego, 'OPA_EXE', mock_opa_exe)

        # Track the command passed to subprocess.run
        captured_command = []

        def mock_subprocess_run(command, **_kwargs):
            captured_command.extend(command)
            mock_result = MagicMock()
            mock_result.stdout = b'[{"result": "ok"}]'
            return mock_result

        monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)

        with caplog.at_level(logging.DEBUG):
            opa_eval(
                product_name='test',
                input_file=str(input_file),
                opa_path=tmp_path,
                rego_path=rego_path,
                debug=True
            )

        assert '--explain=full' in captured_command

    def test_opa_eval_calls_find_opa_when_not_cached(self, monkeypatch, opa_test_files):
        """Tests that opa_eval calls find_opa when OPA_EXE is None."""

        input_file = opa_test_files['input_file']
        rego_path = opa_test_files['rego_path']
        tmp_path = opa_test_files['tmp_path']

        # Ensure OPA_EXE is None
        monkeypatch.setattr(run_rego, 'OPA_EXE', None)

        # Track if find_opa was called
        find_opa_called = []
        mock_opa_path = tmp_path / "opa.exe"

        def mock_find_opa(opa_path):
            find_opa_called.append(opa_path)
            return mock_opa_path

        monkeypatch.setattr(run_rego, 'find_opa', mock_find_opa)

        # Mock subprocess.run
        def mock_subprocess_run(_command, **_kwargs):
            mock_result = MagicMock()
            mock_result.stdout = b'[{"result": "ok"}]'
            return mock_result

        monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)

        opa_eval(
            product_name='test',
            input_file=str(input_file),
            opa_path=tmp_path,
            rego_path=rego_path,
            debug=False
        )

        assert len(find_opa_called) == 1

    def test_opa_eval_raises_on_subprocess_error(self, monkeypatch, opa_test_files):
        """Tests that opa_eval raises RuntimeError when OPA subprocess fails."""

        input_file = opa_test_files['input_file']
        rego_path = opa_test_files['rego_path']
        tmp_path = opa_test_files['tmp_path']

        # Mock the OPA executable path
        mock_opa_exe = tmp_path / "opa.exe"
        monkeypatch.setattr(run_rego, 'OPA_EXE', mock_opa_exe)

        # Mock subprocess.run to raise CalledProcessError
        def mock_subprocess_run(command, **_kwargs):
            error = subprocess.CalledProcessError(1, command)
            error.output = b'OPA error output'
            raise error

        monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)

        with pytest.raises(RuntimeError, match='OPA failure'):
            opa_eval(
                product_name='test',
                input_file=str(input_file),
                opa_path=tmp_path,
                rego_path=rego_path,
                debug=False
            )

    def test_opa_eval_raises_on_unexpected_error(self, monkeypatch, opa_test_files):
        """Tests that opa_eval raises RuntimeError on unexpected exceptions."""

        input_file = opa_test_files['input_file']
        rego_path = opa_test_files['rego_path']
        tmp_path = opa_test_files['tmp_path']

        # Mock the OPA executable path
        mock_opa_exe = tmp_path / "opa.exe"
        monkeypatch.setattr(run_rego, 'OPA_EXE', mock_opa_exe)

        # Mock subprocess.run to raise unexpected exception
        def mock_subprocess_run(_command, **_kwargs):
            raise OSError('Unexpected OS error')

        monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)

        with pytest.raises(RuntimeError, match='Unexpected failure trying to run OPA'):
            opa_eval(
                product_name='test',
                input_file=str(input_file),
                opa_path=tmp_path,
                rego_path=rego_path,
                debug=False
            )

    # =========================================================================
    # Tests for find_opa
    # =========================================================================

    def test_find_opa_in_provided_path(self, monkeypatch, tmp_path):
        """Tests that find_opa finds OPA executable in the provided path."""

        # Create a mock OPA executable
        opa_exe = tmp_path / "opa.exe"
        opa_exe.write_text("mock opa")

        # Mock platform to return windows
        monkeypatch.setattr('platform.system', lambda: 'Windows')
        monkeypatch.setattr('platform.machine', lambda: 'AMD64')

        # Mock os.access to return True for executable check
        monkeypatch.setattr('os.access', lambda path, mode: True)

        # Mock subprocess.run for version check
        mock_result = MagicMock()
        mock_result.stdout = b'Version: 0.55.0'

        def mock_subprocess_run(_command, **_kwargs):
            return mock_result

        monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)

        result = find_opa(tmp_path)

        assert result == opa_exe

    def test_find_opa_in_path_env(self, monkeypatch, tmp_path):
        """Tests that find_opa searches PATH environment variable."""

        # Create a mock OPA executable in a temp directory
        opa_dir = tmp_path / "bin"
        opa_dir.mkdir()
        opa_exe = opa_dir / "opa.exe"
        opa_exe.write_text("mock opa")

        # Mock PATH to include our temp directory
        monkeypatch.setenv('PATH', str(opa_dir))

        # Mock platform to return windows
        monkeypatch.setattr('platform.system', lambda: 'Windows')
        monkeypatch.setattr('platform.machine', lambda: 'AMD64')

        # Mock os.access to return True for executable check
        monkeypatch.setattr('os.access', lambda path, mode: True)

        # Mock subprocess.run for version check
        mock_result = MagicMock()
        mock_result.stdout = b'Version: 0.55.0'

        def mock_subprocess_run(_command, **_kwargs):
            return mock_result

        monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)

        result = find_opa(None)

        assert result.name == 'opa.exe'

    def test_find_opa_not_found_raises_error(self, monkeypatch, tmp_path):
        """Tests that find_opa raises FileNotFoundError when OPA is not found."""

        # Create an empty directory
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        # Mock PATH to only include our empty directory
        monkeypatch.setenv('PATH', str(empty_dir))

        # Mock platform to return windows
        monkeypatch.setattr('platform.system', lambda: 'Windows')
        monkeypatch.setattr('platform.machine', lambda: 'AMD64')

        with pytest.raises(FileNotFoundError, match='OPA executable not found in PATH'):
            find_opa(None)

    def test_find_opa_version_check_failure(self, monkeypatch, tmp_path):
        """Tests that find_opa raises RuntimeError when version check fails."""

        # Create a mock OPA executable
        opa_exe = tmp_path / "opa.exe"
        opa_exe.write_text("mock opa")

        # Mock platform to return windows
        monkeypatch.setattr('platform.system', lambda: 'Windows')
        monkeypatch.setattr('platform.machine', lambda: 'AMD64')

        # Mock os.access to return True for executable check
        monkeypatch.setattr('os.access', lambda path, mode: True)

        # Mock subprocess.run to raise CalledProcessError for version check
        def mock_subprocess_run(command, **_kwargs):
            error = subprocess.CalledProcessError(1, command)
            error.stderr = b'Version check error'
            error.output = b'Error output'
            raise error

        monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)

        with pytest.raises(RuntimeError, match='Error occurred during OPA version check'):
            find_opa(tmp_path)

    @pytest.mark.parametrize('platform_config', [
        {'os_type': 'Windows', 'machine': 'AMD64',
         'expected': ['opa_windows_amd64.exe', 'opa_windows_amd64_static.exe', 'opa.exe']},
        {'os_type': 'Linux', 'machine': 'x86_64',
         'expected': ['opa_linux_x86_64', 'opa_linux_x86_64_static',
                      'opa_linux_amd64', 'opa_linux_amd64_static', 'opa']},
        {'os_type': 'Darwin', 'machine': 'arm64',
         'expected': ['opa_darwin_arm64', 'opa_darwin_arm64_static',
                      'opa_darwin_amd64', 'opa_darwin_amd64_static', 'opa']},
    ])
    def test_find_opa_platform_specific_filenames(self, monkeypatch, tmp_path,
                                                   platform_config):
        """Tests that find_opa looks for platform-specific executable names."""

        os_type = platform_config['os_type']
        machine = platform_config['machine']
        expected_filenames = platform_config['expected']

        # Mock platform
        monkeypatch.setattr('platform.system', lambda: os_type)
        monkeypatch.setattr('platform.machine', lambda: machine)

        # Track which filenames were searched
        searched_files = []

        def mock_exists(path_self):
            searched_files.append(path_self.name)
            return False

        monkeypatch.setattr(Path, 'exists', mock_exists)

        # Expect FileNotFoundError since no file exists
        with pytest.raises(FileNotFoundError):
            find_opa(tmp_path)

        # Verify that expected filenames were searched
        for expected in expected_filenames:
            assert expected in searched_files, f'{expected} not searched'

    # =========================================================================
    # Tests for log_rego_output
    # =========================================================================

    def test_log_rego_output_default_logger(self, caplog):
        """Tests that log_rego_output writes to error log by default."""

        test_output = b'Line 1\nLine 2\nLine 3'

        with caplog.at_level(logging.ERROR):
            log_rego_output(test_output)

        assert 'Line 1' in caplog.text
        assert 'Line 2' in caplog.text
        assert 'Line 3' in caplog.text

    def test_log_rego_output_custom_logger(self, caplog):
        """Tests that log_rego_output can use a custom logger function."""

        test_output = b'Debug line 1\nDebug line 2'

        with caplog.at_level(logging.DEBUG):
            log_rego_output(test_output, logging.getLogger(__name__).debug)

        assert 'Debug line 1' in caplog.text
        assert 'Debug line 2' in caplog.text

    def test_log_rego_output_empty_stream(self, caplog):
        """Tests that log_rego_output handles empty byte streams."""

        test_output = b''

        with caplog.at_level(logging.ERROR):
            log_rego_output(test_output)

        # Should not raise any errors
        # No lines should be logged (empty output)

    def test_log_rego_output_single_line(self, caplog):
        """Tests that log_rego_output handles single line output."""

        test_output = b'Single line output'

        with caplog.at_level(logging.ERROR):
            log_rego_output(test_output)

        assert 'Single line output' in caplog.text

    def test_log_rego_output_unicode_content(self, caplog):
        """Tests that log_rego_output handles unicode content correctly."""

        test_output = 'Unicode content: \u2713 \u2717 \u00e9'.encode('utf-8')

        with caplog.at_level(logging.ERROR):
            log_rego_output(test_output)

        assert 'Unicode content' in caplog.text

    @pytest.mark.parametrize('stream_content,expected_lines', [
        (b'a\nb\nc', ['a', 'b', 'c']),
        (b'single', ['single']),
        (b'line1\n\nline3', ['line1', '', 'line3']),
    ])
    def test_log_rego_output_line_splitting(self, stream_content, expected_lines):
        """Tests that log_rego_output correctly splits lines."""

        logged_lines = []

        def capture_logger(_msg, *args):
            logged_lines.append(args[0] if args else _msg)

        log_rego_output(stream_content, capture_logger)

        assert logged_lines == expected_lines
