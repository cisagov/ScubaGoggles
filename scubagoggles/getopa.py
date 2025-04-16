"""Implementation of ScubaGoggles OPA executable dowload.
"""

import argparse
import logging
import platform
import re
import stat
import subprocess
import sys

from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlcleanup, urlopen, urlretrieve

from scubagoggles.orchestrator import UserRuntimeError
from scubagoggles.utils import prompt_boolean

log = logging.getLogger(__name__)


def getopa(arguments: argparse.Namespace):

    """Main get OPA function - this calls other functions in this module.

    :param arguments: arguments collected by the ArgumentParser.
    """

    log.info('ScubaGoggles OPA Download')

    config = arguments.user_config
    opa_dir = arguments.opa_directory or config.opa_dir

    if opa_dir is None:
        raise UserRuntimeError('No directory set for OPA executable - '
                               'run "setup" first (see documentation)')

    if not opa_dir.is_dir():
        opa_dir.mkdir(exist_ok = True)

    if arguments.opa_directory and not config.opa_dir:
        config.opa_dir = arguments.opa_directory
        config.write()

    verify = not arguments.nocheck
    force = arguments.force

    # The user can specify either to download the latest version, a specific
    # version, or the default if no version options are given on the command
    # line.

    version = None if arguments.latest else arguments.version.lower()

    download_opa(opa_dir, version, verify, force)


def download_opa(opa_dir: Path,
                 version: str = None,
                 verify: bool = False,
                 force: bool = False):

    """Download the OPA executable for the current operating system
    environment.

    :param Path opa_dir: directory where OPA executable will be located.
    :param str version: [optional] version number of a specific OPA release
        to download (version format vM.m.b). Downloads the latest OPA version
        if not specified.
    :param bool verify: [optional] if True, verifies the hash value of the
        OPA executable with the expected value for the release.
    :param bool force: [optional] if True, overwrites the OPA executable, if
        it currently exists in the target download location.
    :raises RuntimeError: for the case where the latest version number returned
        by OPA does not look like a version (vM.m.b).
    """

    # pylint: disable=too-many-branches

    if sys.maxsize <= 2 ** 32:
        raise UserRuntimeError('64-bit operating environment required for OPA')

    opa_base_url = 'https://github.com/open-policy-agent/opa/releases/'
    version_re = re.compile(r'v\d+(?:\.\d+){2}')

    if not version:
        latest_version_url = urljoin(opa_base_url, 'latest')
        log.debug('Querying latest version from OPA: %s', latest_version_url)
        request = Request(latest_version_url)

        with urlopen(request) as response:
            version = urlsplit(response.url).path.split('/')[-1]
        log.debug('  Version returned: %s', version)

        if not version_re.match(version):
            raise RuntimeError(f'? "{version}" - unrecognized version string '
                               'returned as "latest" OPA version')
    elif not version_re.match(version):
        if not version_re.match(f'v{version}'):
            raise UserRuntimeError(f'? "{version}" - unrecognized version '
                                   'string - expected "v<X>.<Y>.<Z>"')
        version = f'v{version}'

    file_name = opa_filespec()

    log.debug('Downloading %s to %s', file_name, str(opa_dir))

    download_url = urljoin(opa_base_url, f'download/{version}/{file_name}')
    output_file = opa_dir / file_name

    if output_file.exists():
        if not force:
            force = prompt_boolean(f'Overwrite existing file ({output_file})',
                                   False)
            if not force:
                return

        log.debug('Overwriting existing file: %s', str(output_file))
        output_file.unlink()

    log.debug('Download URL: %s', download_url)

    try:
        urlretrieve(download_url, output_file)
    except HTTPError as http_error:
        log.error('HTTP error %d returned trying to access %s',
                  http_error.code,
                  download_url)
        if http_error.code == 404:
            # I want the error I'm raising in this instance ONLY.
            # pylint: disable-next=raise-missing-from
            raise UserRuntimeError('Unable to download OPA executable for '
                                   f'version {version} - check version')
        raise UserRuntimeError('Failure downloading OPA executable') \
            from http_error
    finally:
        urlcleanup()

    mode = output_file.stat().st_mode
    new_mode = mode | stat.S_IXUSR | stat.S_IRUSR

    if new_mode != mode:
        log.debug('  Setting user execute/read permissions')
        output_file.chmod(new_mode)

    if verify:
        download_ok = verify_opa(download_url, output_file)
        if not download_ok:
            raise RuntimeError('Hash generated from downloaded file does NOT '
                      'match expected value')

    test_opa(output_file)


def opa_filespec(opa_dir: Path = None):

    """Returns the file name for the OPA executable that is EXPECTED to be
    the default for the current operating environment.  For example, on a
    macOS system with the ARM architecture, the default executable should
    be "opa_darwin_arm64_static", but the user may rename this to be
    simply "opa" or download the AMD architecture executable, which will
    run even in an ARM-based macOS environment.  This function simply
    returns the name of the expected executable.

    :param opa_dir: [optional] expected location of the OPA executable.
    :return: complete file specification (as a Path), if the OPA directory
        is provided; otherwise, the expected OPA file name (as a str) for
        the current environment.
    :rtype: Path or str
    """

    os_type = platform.system().lower()

    arch = platform.machine().lower()

    if arch == 'x86_64':
        arch = 'amd64'
    elif arch.startswith('arm'):
        arch = 'arm64'

    file_name = f'opa_{os_type}_{arch}'

    file_name += '.exe' if os_type == 'windows' else '_static'

    return opa_dir / file_name if opa_dir else file_name


def test_opa(opa_exe_file: Path):

    """Runs the OPA "version" command to check that the downloaded OPA
    successfully executes.

    :param Path opa_exe_file: OPA executable file specification.
    """

    log.info('Test run OPA executable')

    result = subprocess.run(f'{opa_exe_file} version'.split(),
                            capture_output = True,
                            check = False)

    if result.returncode != 0:
        log.error('Run OPA (%s) results in error: %d',
                  str(opa_exe_file),
                  result.returncode)
        log.debug('Standard error output: \n%s', result.stderr.decode())

    log.debug('OPA output: \n%s', result.stdout.decode())


def verify_opa(download_url: str, opa_exe_file: Path):

    """Verifies that the hash value of the downloaded OPA executable matches
    the value provided by OPA release.

    :param str download_url: URL for the OPA version release area.
    :param Path opa_exe_file: OPA executable file specification.

    :return: True if the hash value for the downloaded OPA executable matches
        the expected value for the release; False otherwise.
    :rtype: bool
    """

    log.info('Verifying downloaded OPA hash value')

    hash_suffix = '.sha256'
    hash_file_url = download_url + hash_suffix

    contents = opa_exe_file.read_bytes()
    file_hash_value = sha256(contents, usedforsecurity = False).hexdigest()

    with TemporaryDirectory('_opa_sha') as temp_dir:
        hash_file_name = opa_exe_file.name + hash_suffix
        hash_file = Path(temp_dir, hash_file_name)

        log.debug('  Downloading %s to %s', hash_file_name, temp_dir)
        log.debug('  Download URL: %s', download_url)

        try:
            urlretrieve(hash_file_url, hash_file)
        except HTTPError as http_error:
            log.error('HTTP error %d returned trying to access %s',
                      http_error.code,
                      download_url)
            raise UserRuntimeError('Failure downloading OPA hash file') \
                from http_error
        finally:
            urlcleanup()

        contents = hash_file.read_text(encoding = 'utf-8')

        expected_value = contents.split()[0]

    log.debug('  Expected hash value: %s', expected_value)
    log.debug('  Actual hash value:   %s', file_hash_value)

    return file_hash_value == expected_value
