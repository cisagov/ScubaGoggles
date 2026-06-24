"""Tests for the ScubaGoggles 'getopa' command.
"""
import argparse
import logging
import platform

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

import scubagoggles.getopa as opa

from scubagoggles.config import UserConfig
from scubagoggles.orchestrator import UserRuntimeError
from scubagoggles.run_rego import find_opa
from scubagoggles.scuba_constants import OPA_VERSION


class InterruptOpaDownload(Exception):

    """Exception for intentionally aborting download_opa()"""


class TestGetopa:

    """This class contains unit tests for the 'getopa' command.  This tests
    the expected functionality and a few of the exceptions that may occur.
    It does not test all exception conditions, as it's not worth the extra
    effort in these cases.
    """

    @pytest.mark.parametrize(('test_name', 'test_data'),
                             (('x86_64-linux-abspath',
                               ('/home/user', 'x86_64', 'linux',
                                '/home/user/opa_linux_amd64_static')),
                              ('x86_64-linux-relpath',
                               ('.', 'x86_64', 'linux',
                                './opa_linux_amd64_static')),
                              ('x64_64-windows-abspath',
                               ('c:/users/me', 'x64_64', 'windows',
                                'c:/users/me/opa_windows_amd64.exe')),
                              ('arm64-macos-nopath',
                               (None, 'arm64', 'darwin',
                                'opa_darwin_arm64_static'))))
    def test_opa_filespec(self, monkeypatch, subtests, test_name, test_data):

        """Tests the opa_filespec() method, which constructs the file
        specification for the OPA executable.  For each test, the system
        architecture and operating system are provided.
        """

        with subtests.test(msg = f'subtest: {test_name}'):

            opa_dir, arch, os_type, expected_filespec = test_data

            monkeypatch.setattr(platform, 'machine', lambda: arch)
            monkeypatch.setattr(platform, 'system', lambda: os_type)

            opa_path = Path(opa_dir) if opa_dir else None

            result = opa.opa_filespec(opa_path)

            exp_path = Path(expected_filespec)

            assert (result.as_posix() == exp_path.as_posix() if opa_dir
                    else result == exp_path.as_posix())

    def test_no_opa_dir(self, monkeypatch):

        """Tests that a UserRuntimeError is raised if there is no directory
        provided to the getopa() function (either directly or via the
        user configuration file).
        """

        user_config = UserConfig()

        monkeypatch.setattr(UserConfig, 'opa_dir', None)

        args = argparse.Namespace(user_config = user_config,
                                  opa_directory = None)

        with pytest.raises(UserRuntimeError):
            opa.getopa(args)

    @pytest.mark.parametrize('version',
                             ('x1.9.3',
                              'vx4.8',
                              'v1.1',
                              '.3.2'))
    def test_bad_version(self, version: str):

        """Tests that a UserRuntimeError is raised if an invalid version
        number is given to the download_opa() function.
        """

        with TemporaryDirectory('_getopa_test',
                                ignore_cleanup_errors=True) as test_dir:
            with pytest.raises(UserRuntimeError, match = 'unrecognized version'):
                opa.download_opa(Path(test_dir), version)

    @pytest.mark.parametrize(('version', 'verify'),
                             ((None, True),
                              ('1.16.0', False),
                              ('v1.15.2', True)))
    def test_download_opa(self, caplog, version: str, verify: bool):

        """Tests that the correct OPA executable is downloaded.  This test
        will **actually download** the executable, so internet access is
        required and the test will take longer than a normal test.  Mocking the
        download doesn't allow for adequate testing.
        """

        with TemporaryDirectory('_getopa_test',
                                ignore_cleanup_errors=True) as test_dir:

            test_path = Path(test_dir)

            with caplog.at_level(logging.DEBUG):
                opa.download_opa(test_path, version, verify)

            opa_exe = find_opa(test_path)

            assert test_path.samefile(opa_exe.parent)

            log_messages = caplog.messages

            latest_version_query = any(m.startswith('Querying latest version')
                                       for m in log_messages)

            # The latest OPA version is supposed to be downloaded if no
            # specific version is provided.

            assert (version is None) == latest_version_query

            # The execute permission should be set on the OPA executable
            # for non-Windows platforms.

            if platform.system().lower() != 'windows':
                assert any('Setting user execute' in m for m in log_messages)

            verify_hash = any(m.startswith('Verifying downloaded OPA hash value')
                              for m in log_messages)

            assert verify == verify_hash

    @pytest.mark.parametrize('force', (True, False))
    def test_force_overwrite(self, monkeypatch, force):

        """Tests the prompting for overwriting an existing OPA executable
        file before downloading.
        """

        # This is used to "short circuit" the download_opa() function at a
        # point where we don't want it doing any more.  We've got to catch
        # the raised exception.

        def abort_function():
            raise InterruptOpaDownload

        # This will let us know whether the prompt was invoked for forcing
        # the overwrite of the existing OPA file.

        prompt_called = 0

        def fake_prompt(*_):

            nonlocal prompt_called
            prompt_called += 1

            return force

        monkeypatch.setattr(opa, 'prompt_boolean', fake_prompt)

        # The OPA download won't happen, and we'll raise the exception to
        # abort the download_opa() function instead of the URL cleanup.

        monkeypatch.setattr(opa, 'urlretrieve', lambda u, o: None)

        monkeypatch.setattr(opa, 'urlcleanup', abort_function)

        with TemporaryDirectory('_getopa_test',
                                ignore_cleanup_errors=True) as test_dir:

            test_path = Path(test_dir)

            # Create a fake OPA file so that download_opa() will detect that
            # the file already exists.

            opa_file = opa.opa_filespec(test_path)

            opa_file.touch()

            # If we're forcing the override of the existing file, the function
            # will proceed to the download; otherwise, it'll return leaving the
            # function immediately following the "overwrite" prompt.

            if force:
                with pytest.raises(InterruptOpaDownload):
                    opa.download_opa(test_path, force = False)
            else:
                opa.download_opa(test_path, force = False)

            assert prompt_called == 1

            # With a "forced" download, the existing file is deleted before
            # the new on is downloaded; otherwise, the current file is left
            # alone.

            assert force != opa_file.exists()


    @pytest.mark.parametrize('kwargs',
                             ({},
                              {'force': True,
                               'latest': True,
                               'version': 'v1.15.0'},
                              {'latest': True},
                              {'version': 'v0.14.2'}))
    def test_getopa_command(self, monkeypatch, kwargs):

        """This tests the interface function for the "getopa" command.
        It does not download OPA, but rather tests the interaction of the
        command arguments.  The parameter
        """

        getopa_args = {'force': False,
                       'latest': False,
                       'nocheck': False,
                       'version': OPA_VERSION}

        getopa_args.update(kwargs)

        if getopa_args['latest']:
            del getopa_args['version']

        def _fake_download_opa(opa_dir, version, verify, force):

            # This mocks the OPA download, so no actual download takes
            # place.  Instead, we're looking for the correct arguments
            # to be passed from the getopa() function.

            assert isinstance(opa_dir, Path)

            assert (version is None if getopa_args['latest']
                    else isinstance(version, str))

            assert isinstance(verify, bool)

            assert isinstance(force, bool)

        monkeypatch.setattr(opa, 'download_opa', _fake_download_opa)

        with TemporaryDirectory('_getopa_test',
                                ignore_cleanup_errors=True) as test_dir:

            config_file = Path(test_dir) / 'scubagoggles_config'

            user_config = UserConfig(config_file)

            opa_dir = Path(test_dir) / 'opa'

            arguments = argparse.Namespace(user_config = user_config,
                                           opa_directory = opa_dir,
                                           **getopa_args)

            opa.getopa(arguments)

            # Both the user configuration file and OPA directory should have
            # been created by getopa().

            assert config_file.exists()

            assert opa_dir.exists()
