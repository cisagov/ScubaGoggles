"""
run_rego.py takes the opa executable and runs the provider JSON against the rego files

This module will differentiate between windows and mac OPA executables when running.
"""
import json
import logging
import os
import platform
import re
import subprocess

from collections.abc import Callable
from pathlib import Path

log = logging.getLogger(__name__)

# This will contain the OPA executable file specification.  It's global because
# it's only used by opa_eval() and once the executable is found, it's the only
# one used to run OPA.
# pylint: disable=global-statement
OPA_EXE = None

# This is used to parse the output of the OPA version command to get the
# version number of OPA being used in the run.
opa_version_re = re.compile(r'(?i)Version:\s+\d+(?:\.\d+)*')


def opa_eval(product_name: str,
             input_file: str,
             opa_path: Path,
             rego_path: Path,
             debug: bool):

    """Runs the rego scripts and outputs a json to out_path

    :param product_name: which product to run
    :param input_file: which file to look at
    :param opa_path: path to opa
    :param rego_path: path to the rego file to run
    :param debug: to print debug statements or not
    """

    global OPA_EXE

    if OPA_EXE is None:
        OPA_EXE = find_opa(opa_path)

    rego_file = rego_path / f'{product_name.capitalize()}.rego'
    utils_rego = rego_path / 'Utils.rego'

    command = [str(OPA_EXE),
               'eval',
               f'data.{product_name}.tests',
               '-i', str(input_file),
               '-d', str(rego_file),
               '-d', str(utils_rego),
               '--format=values']

    if debug:
        command.append('--explain=full')

    log.debug('Running OPA: %s', ' '.join(command))

    try:
        output = subprocess.run(command,
                                check = True,
                                stderr = subprocess.STDOUT,
                                stdout = subprocess.PIPE)
    except subprocess.CalledProcessError as cpe:
        log.error('OPA failed to execute from process:')
        log_rego_output(cpe.output)
        raise RuntimeError('OPA failure') from cpe
    except Exception as exc:
        log.error('OPA failed to execute from unexpected error:')
        log.error('  %s', str(exc))
        raise RuntimeError('Unexpected failure trying to run OPA') from exc

    if debug:
        log.debug('Rego output:')
        log_rego_output(output.stdout, log.debug)

    str_output = output.stdout.decode()
    ret_tests = json.loads(str_output)

    return ret_tests



def find_opa(opa_path: Path = None):

    """Finds the OPA executable using the given directory (if supplied) and
    the directories in the user's PATH.

    Locating the OPA executable should work in any operating environment.  The
    file name of the executable will differ depending on the OS.  For example,
    on Windows, it's downloaded from the OPA site as opa_windows_amd64.exe,
    but on Linux it may be opa_linux_amd64_static.  The user may also rename
    this to be simply opa.  On Windows, it's assumed to have an extension
    (aka file type) of .exe.

    If no valid OPA executable is found, an exception is raised because this
    executable is required for ScubaGoggles to run correctly.

    :param Path opa_path: [optional] directory where the OPA executable is
        located.

    :return: file specification of the OPA executable.
    :rtype: Path
    """

    path_dirs = [Path(opa_path)] if opa_path else []
    path_dirs.extend(Path(d) for d in os.environ['PATH'].split(os.pathsep))

    opa_filenames = []

    os_type = platform.system().lower()

    architectures = [platform.machine().lower()]
    if architectures[0] == 'x86_64':
        architectures.append('amd64')

    # An ARM-based Mac can supposedly run the AMD64 version
    # of OPA.
    if os_type == 'darwin' and 'amd64' not in architectures:
        architectures.append('amd64')

    for architecture in architectures:
        opa_filename = f'opa_{os_type}_{architecture}'
        opa_filenames.append(opa_filename)
        opa_filenames.append(f'{opa_filename}_static')

    extension = '.exe' if os_type == 'windows' else ''

    # The user may have renamed the "long" OPA executable name to shorten it,
    # or may have followed the instructions for downloading OPA, which includes
    # renaming it.  We'll look for the longer name first, but the search will
    # look for the shortened name, too.
    opa_filenames.append('opa')

    opa_exe = None

    log.debug('Searching for OPA executable:')

    for filename in opa_filenames:
        filename += extension

        for path_dir in path_dirs:
            current_exe = Path(path_dir) / filename
            log.debug('  Trying %s', current_exe)
            if current_exe.exists():
                if os.access(current_exe, os.X_OK):
                    opa_exe = current_exe
                    log.debug('    Valid executable')
                    break
                log.debug('    NO execute access')

        if opa_exe:
            break

    if opa_exe is None:
        raise FileNotFoundError('OPA executable not found in PATH')
    try:
        process = subprocess.run((opa_exe, 'version'),
                                 check = True,
                                 stderr = subprocess.STDOUT,
                                 stdout = subprocess.PIPE)
    except subprocess.CalledProcessError as cpe:
        if cpe.stderr:
            log.error('Error during OPA version check:')
            log_rego_output(cpe.output)
        raise RuntimeError('Error occurred during OPA version check - '
                           f'return code: {cpe.returncode}') from cpe

    match = opa_version_re.search(process.stdout.decode())
    if match:
        log.info('OPA %s', match[0])

    return opa_exe

def log_rego_output(stream: bytes, logger: Callable = log.error) -> None:

    """Writes the given error and/or output stream (in bytes) to the log.

    :param bytes stream: the contents of the error/output stream.
    :param Callable logger: logging function to write the output - defaults
        to the error log.
    """

    output = stream.decode().splitlines()

    for line in output:
        logger('  %s', line)
