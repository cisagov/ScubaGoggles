"""Implementation of ScubaGoggles OPA executable dowload.
"""

import argparse
import logging
import platform
import re
import stat
import subprocess

from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlcleanup, urlopen, urlretrieve

from scubagoggles.orchestrator import UserRuntimeError
from scubagoggles.user_setup import prompt_boolean

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
        answer = prompt_boolean(f'Create directory {opa_dir}')
        if not answer:
            log.error('OPA directory required')
            return

        opa_dir.mkdir(exist_ok = True)

    if arguments.opa_directory and not config.opa_dir:
        config.opa_dir = arguments.opa_directory
        config.write()

    verify = arguments.check
    force = arguments.force
    version = arguments.version

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

    opa_base_url = 'https://github.com/open-policy-agent/opa/releases/'

    if not version:
        latest_version_url = urljoin(opa_base_url, 'latest')
        log.debug('Querying latest version from OPA: %s', latest_version_url)
        request = Request(latest_version_url)

        with urlopen(request) as response:
            version = urlsplit(response.url).path.split('/')[-1]
        log.debug('  Version returned: %s', version)

        if not re.match(r'v\d+(?:\.\d+){2}', version):
            raise RuntimeError(f'? "{version}" - unrecognized version string '
                               'returned as "latest" OPA version')

    os_type = platform.system().lower()

    arch = platform.machine().lower()

    if arch == 'x86_64':
        arch = 'amd64'
    elif arch.startswith('arm'):
        arch = 'arm64'

    file_name = f'opa_{os_type}_{arch}'

    file_name += '.exe' if os_type == 'windows' else '_static'

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

    urlretrieve(download_url, output_file)
    urlcleanup()

    mode = output_file.stat().st_mode
    new_mode = mode | stat.S_IXUSR | stat.S_IRUSR

    if new_mode != mode:
        log.debug('  Setting user execute/read permissions')
        output_file.chmod(new_mode)

    if verify:
        download_ok = verify_opa(download_url, output_file)
        if not download_ok:
            log.error('Hash generated from downloaded file does NOT '
                      'match expected value')

    test_opa(output_file)

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

        log.debug('Downloading %s to %s', hash_file_name, temp_dir)
        urlretrieve(hash_file_url, hash_file)
        urlcleanup()

        contents = hash_file.read_text(encoding = 'utf-8')

        expected_value = contents.split()[0]

    log.debug('  Expected hash value: %s', expected_value)
    log.debug('  Actual hash value:   %s', file_hash_value)

    return file_hash_value == expected_value
