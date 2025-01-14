#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Implementation of one-time user setup (output directory, credentials file
location, etc.).
"""

import argparse
import logging
import os

from collections import namedtuple
from pathlib import Path

from scubagoggles.getopa import download_opa, opa_filespec
from scubagoggles.run_rego import find_opa
from scubagoggles.utils import prompt_boolean, prompt_string

log = logging.getLogger(__name__)

# These are default names for files/folders, and this was originally defined
# in main.py.  Because the names may be referenced elsewhere in the code, to
# avoid hard-coding the names the defaults may be referenced here.  Perhaps
# they could be defined in a separate file, but I supposed this is as good
# a place as any (except main.py) to define them.

Defaults = namedtuple('Defaults',
                      ['json_output_name',
                       'output_folder_name',
                       'provider_output_name',
                       'rego_output_name',
                       'report_output_name'])


default_file_names = Defaults(json_output_name = 'ScubaResults',
                              output_folder_name = 'GWSBaselineConformance',
                              provider_output_name = 'ProviderSettingsExport',
                              rego_output_name = 'TestResults',
                              report_output_name = 'BaselineReports')


def user_setup(arguments: argparse.Namespace):

    """Main user setup function - this calls other functions in this module.
    If the user makes any setting changes, this will result in writing a
    user configuration file in the top-level user directory.

    :param arguments: arguments collected by the ArgumentParser.
    """

    config = arguments.user_config

    config.path_check = False

    modified = user_directory(arguments)

    modified |= opa_directory(arguments)

    modified |= credentials_file(arguments)

    if modified:
        config.write()


def user_directory(arguments: argparse.Namespace):

    """Sets the user's directory for Scubagoggles output files.

    :param arguments: arguments collected by the ArgumentParser.

    :return: True if the output directory was changed in the user's
        configuration; False otherwise.
    """

    # Gimme a break...
    # pylint: disable=too-many-branches

    print('Setup: output directory')

    config = arguments.user_config
    create_dir = arguments.mkdir
    prompt = not arguments.noprompt
    user_dir = arguments.work_directory

    if user_dir:

        # The user has explicitly specified an output directory to be used.
        # We only need to check whether the directory already exists, and
        # confirm with the user to create it if it doesn't.

        user_dir = user_dir.resolve()

        if not user_dir.exists():
            answer = (create_dir or (prompt
                      and prompt_boolean(f'Create directory {user_dir}')))

            if answer:
                print(f'  creating: {user_dir}')
                user_dir.mkdir(exist_ok = True)
        else:
            print(f'  specified directory: {user_dir}')

        config.output_dir = user_dir

        return True

    if not config.file_exists:

        # The user has no configuration file, so they're starting from scratch.
        # First, determine if this may be a "legacy" setup, where the user
        # has the Scubagoggles installation in their own directory (as opposed
        # to the Python "site packages" directory) and the output data and
        # credentials are mixed in with the code hierarchy.  If the user has
        # their environment set up this way, we don't want to force them into
        # a different configuration unless we can't find their "legacy" files.

        legacy_dir = find_legacy_dir(config)

        user_dir = legacy_dir or config.output_dir

        # Confirm with the user that this is the output directory they want
        # to use.  The user is also asked whether the directory should be
        # created if it doesn't exist.  We don't exit the loop until we
        # have a valid directory.  Because the user hasn't entered any
        # directory, we're forced to prompt (ignoring --noprompt).

        verified = False

        while not verified:
            answer = prompt_string('Scubagoggles output directory', user_dir)

            if not answer:
                continue

            user_dir = Path(os.path.expandvars(answer)).expanduser()

            if not user_dir.exists():
                answer = (create_dir
                          or prompt_boolean(f'Create directory {user_dir}'))
                if answer:
                    print(f'  creating: {user_dir}')
                    user_dir.mkdir(exist_ok = True)

            verified = user_dir.is_dir()

        user_dir = user_dir.resolve()

        print(f'  {user_dir}')

        if (not config.output_dir.exists()
           or not user_dir.samefile(config.output_dir)):
            config.output_dir = user_dir

            return True

        return False

    # At this point, the user has an existing Scubagoggles configuration
    # file.  We don't need to do anything other than ask to create the
    # directory if it doesn't exist, but we don't change the directory set
    # in the configuration file.

    user_dir = config.output_dir

    if not user_dir.exists():
        answer = create_dir or prompt_boolean(f'Create directory {user_dir}')
        if answer:
            print(f'  creating: {user_dir}')
            user_dir.mkdir(exist_ok = True)
    else:
        print(f'  {user_dir}')

    return False


def opa_directory(arguments: argparse.Namespace):

    """Sets the user's directory where the OPA executable is located.  The
    best location for the OPA executable is in one of the directories included
    in the user's PATH environment variable, but the user may also explicitly
    specify a location.

    :param arguments: arguments collected by the ArgumentParser.

    :return: True if the OPA executable directory was changed in the user's
        configuration; False otherwise.
    """

    print('Setup: OPA executable directory')

    check = not arguments.nocheck
    config = arguments.user_config
    download = not arguments.nodownload and check
    opa_dir = arguments.opa_directory

    if opa_dir:

        # The user has explicitly specified the OPA executable directory.
        # We only need to check whether the OPA executable is indeed in that
        # location.

        create_dir_download_opa(opa_dir, download)

        if check:
            validate_opa_dir(opa_dir)
        else:
            print(f'  {opa_dir}')

        config.opa_dir = opa_dir.resolve()

        return True

    if config.file_exists and config.opa_dir:

        # The user has established a configuration file and includes the OPA
        # executable directory.  We just validate the directory and don't
        # change anything.

        create_dir_download_opa(config.opa_dir, download)

        if check:
            validate_opa_dir(config.opa_dir)
        else:
            print(f'  {config.opa_dir}')

        return False

    # Either the user has no configuration file or the OPA executable directory
    # isn't specified in the configuration.  The OPA executable will hopefully
    # be located on the user's PATH, in which case there's nothing to do.

    if validate_opa_dir():
        return False

    # There's no OPA executable directory defined, and we haven't found the
    # executable in the User's PATH, so we use the default location defined
    # in config.py
    create_dir_download_opa(config.opa_dir, download)
    return True


def create_dir_download_opa(opa_dir: Path, download: bool):

    """Helper function that checks the given OPA executable directory,
    and creates it if it doesn't exist (and the user hasn't suppressed it).
    The OPA executable is downloaded to this directory, also if it doesn't
    exist and the user hasn't suppressed it.

    :param opa_dir: OPA executable directory.
    :param create_dir: create OPA directory (if needed) if True.
    :param download: if True, download the OPA executable if the directory
        exists and the OPA executable is missing.
    """

    if not opa_dir.exists():
        log.debug('  creating: %s', opa_dir)
        opa_dir.mkdir(exist_ok = True)

    if opa_dir.exists() and download:

        # The OPA directory exists and the user hasn't suppressed the
        # download (e.g., no internet).  Get the OPA executable if it's
        # not already there.

        opa = opa_filespec(opa_dir)
        if not opa.exists():
            print(f'  downloading: {opa.name}')
            download_opa(opa_dir, verify = True)


def validate_opa_dir(opa_dir: Path = None):

    """Validates that the OPA executable exists in the given directory or
    in a directory along the user's PATH.

    :param opa_dir: [optional] location of the OPA executable.

    :return: True if the OPA executable exists; False otherwise.
    """

    if opa_dir and not opa_dir.is_dir():
        log.warning('? %s - OPA directory not found', opa_dir)
        return False

    try:
        opa_exe = find_opa(opa_dir)

        if opa_exe:
            where = ('' if opa_dir and opa_dir.samefile(opa_exe.parent)
                     else ' from PATH')
            print(f'  OPA executable: {opa_exe}{where}')

    except FileNotFoundError:
        opa_exe = None

    if not opa_exe:
        where = opa_dir or 'PATH'
        log.warning('OPA executable not found in %s', where)

    return opa_exe is not None


def credentials_file(arguments: argparse.Namespace):

    """Sets the Google API credentials file in the user's configuration.

    :param arguments: arguments collected by the ArgumentParser.

    :return: True if the credentials file was changed in the user's
        configuration; False otherwise.
    """

    print('Setup: Google API credentials file')

    check = not arguments.nocheck
    config = arguments.user_config
    credentials = arguments.credentials
    prompt = not arguments.noprompt

    if credentials:

        # The user has explicitly specified the credentials file.  We only
        # need to check whether the file exists.

        if check and not credentials.is_file():
            raise FileNotFoundError(f'? {credentials} - credentials not found')

        print(f'  specified file: {credentials}')

        config.credentials_file = credentials.resolve()

        return True

    if not config.file_exists:

        # The user has no configuration file, so they're starting from scratch.
        # If the credentials file exists, it may be in the output directory
        # because of a "legacy" setup.

        legacy_credentials = config.output_dir / 'credentials.json'

        if legacy_credentials.is_file():
            print(f'  found: {legacy_credentials}')
            config.credentials_file = legacy_credentials
            return True

    elif config.credentials_file.is_file() or not check:
        print(f'  {config.credentials_file}')
        return False
    else:
        log.error('? %s - Google credential files missing',
                  config.credentials_file)
        if not prompt:
            return False

    # There's no configuration file found, so we have to ask for the location.

    while not credentials:
        answer = prompt_string('Google credentials (JSON) file',
                               config.credentials_file)

        if not answer:
            continue

        answer = Path(os.path.expandvars(answer)).expanduser().absolute()

        if not answer.exists():
            log.warning('Google credentials file not found in %s', answer)
        else:
            print(f'  {config.credentials_file}')

        credentials = answer

    config.credentials_file = credentials.resolve()

    return True


def find_legacy_dir(config):

    """Looks for a "legacy" setup directory and returns it, if found.
    Otherwise, None is returned.

    The initial setup for users was to have them unpack the Scubagoggles
    code into their own directory, where the credentials file, OPA executable,
    and output directories would also be located.  Users may now install
    Scubagoggles into the Python "site packages" directory, which is
    preferable because it separates the code from the user's data.

    This function attempts to find a legacy setup to avoid having to force
    the user to move to the newer configuration - Scubagoggles should just
    work with a legacy setup.

    :param UserConfig config: the user's configuration data.

    :return: a legacy directory (containing the credentials and/or
        Scubagoggles output files) or None if the directory wasn't found.
    """

    legacy_dir = None

    if not config.file_exists:

        log.debug('  no config file, checking for "legacy" output directory')

        baseline_dir_pattern = f'{default_file_names.output_folder_name}*'
        patterns = ('credentials.json', baseline_dir_pattern)

        # A legacy directory is either the user's current working directory
        # (because they were instructed to run Scubagoggles from the current
        # directory) or the Scubagoggles top directory.  If any of the typical
        # user files are found in the directory, assume it's a legacy directory.

        for curr_dir in (Path.cwd(), Path(__file__).parent.parent):

            is_legacy = any(len(list(curr_dir.glob(p))) for p in patterns)

            if is_legacy:
                log.debug('  found %s', curr_dir)
                legacy_dir = curr_dir
                break

    return legacy_dir
