#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Implementation of one-time user setup (output directory, credentials file
location, etc.).
"""

import argparse
import logging

from collections import namedtuple
from pathlib import Path

from scubagoggles.getopa import download_opa, opa_filespec
from scubagoggles.run_rego import find_opa

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
                       'action_plan_name',
                       'report_output_name'])


default_file_names = Defaults(json_output_name = 'ScubaResults',
                              output_folder_name = 'GWSBaselineConformance',
                              provider_output_name = 'ProviderSettingsExport',
                              rego_output_name = 'TestResults',
                              action_plan_name = 'ActionsPlan',
                              report_output_name = 'BaselineReports')


def user_setup(arguments: argparse.Namespace):

    """Main user setup function - this calls other functions in this module.
    If the user makes any setting changes, this will result in writing a
    user configuration file in the top-level user directory.

    :param arguments: arguments collected by the ArgumentParser.
    """

    config = arguments.user_config

    modified = user_directory(arguments)

    modified |= opa_directory(arguments)

    modified |= credentials_file(arguments)

    print("Configured default locations:")
    print(f' - Output directory: {config.output_dir}')
    print(f' - OPA executable: {config.opa_dir}')
    if config.credentials_file is None:
        print(' - API credentials file: Not configured yet')
    else:
        print(f' - API credentials file: {config.credentials_file}')

    if modified:
        config.write()
    else:
        logging.info("No changes made.")


def user_directory(arguments: argparse.Namespace):

    """Sets the user's directory for Scubagoggles output files.

    :param arguments: arguments collected by the ArgumentParser.

    :return: True if the output directory was changed in the user's
        configuration; False otherwise.
    """

    log.debug('Setup: output directory')

    config = arguments.user_config

    config_changed = False
    if arguments.outputpath:
        # The user has explicitly specified an output directory to be used.
        # We only need to check whether the directory already exists and
        # save to config
        if not arguments.nocheck and not arguments.outputpath.exists():
            log.debug('Creating output directory %s', arguments.outputpath)
            arguments.outputpath.mkdir(exist_ok = True)

        if not arguments.nocheck and not arguments.outputpath.is_dir():
            raise NotADirectoryError(f'? {arguments.outputpath} is not a directory.')

        print(f"Updating the default output location to {arguments.outputpath}")
        arguments.outputpath = arguments.outputpath.resolve()
        config.output_dir = arguments.outputpath
        config_changed = True

    return config_changed

def opa_directory(arguments: argparse.Namespace):

    """Sets the user's directory where the OPA executable is located.  The
    best location for the OPA executable is in one of the directories included
    in the user's PATH environment variable, but the user may also explicitly
    specify a location.

    :param arguments: arguments collected by the ArgumentParser.

    :return: True if the OPA executable directory was changed in the user's
        configuration; False otherwise.
    """

    log.debug('Setup: OPA executable directory')

    check = not arguments.nocheck
    config = arguments.user_config
    download = not arguments.nodownload and check
    opa_dir = arguments.opapath

    if opa_dir:

        # The user has explicitly specified the OPA executable directory.
        # We only need to check whether the OPA executable is indeed in that
        # location.

        print(f"Updating the default OPA location to {opa_dir}")
        create_dir_download_opa(opa_dir, check, download)

        if check:
            validate_opa_dir(opa_dir)
        else:
            log.debug('  %s', opa_dir)

        config.opa_dir = opa_dir.resolve()

        return True

    if config.file_exists and config.opa_dir:

        # The user has established a configuration file and includes the OPA
        # executable directory.  We just validate the directory and don't
        # change anything.

        create_dir_download_opa(config.opa_dir, check, download)

        if check:
            validate_opa_dir(config.opa_dir)
        else:
            log.debug('  %s', config.opa_dir)

        return False

    # Either the user has no configuration file or the OPA executable directory
    # isn't specified in the configuration.  The OPA executable will hopefully
    # be located on the user's PATH, in which case there's nothing to do.

    if validate_opa_dir():
        return False

    # There's no OPA executable directory defined, and we haven't found the
    # executable in the User's PATH, so we use the default location defined
    # in config.py
    create_dir_download_opa(config.opa_dir, check, download)
    return True


def create_dir_download_opa(opa_dir: Path, create_dir: bool, download: bool):

    """Helper function that checks the given OPA executable directory,
    and creates it if it doesn't exist (and the user hasn't suppressed it).
    The OPA executable is downloaded to this directory, also if it doesn't
    exist and the user hasn't suppressed it.

    :param opa_dir: OPA executable directory.
    :param create_dir: create OPA directory (if needed) if True.
    :param download: if True, download the OPA executable if the directory
        exists and the OPA executable is missing.
    """

    if create_dir:
        if not opa_dir.exists():
            log.debug('  creating: %s', opa_dir)
            opa_dir.mkdir(exist_ok = True)
        elif not opa_dir.is_dir():
            raise NotADirectoryError("The specified location for the OPA "
                f"executable, {opa_dir}, exists but is not a directory.")
    else:
        if not opa_dir.exists():
            log.debug("OPA directory does not exist but create_dir is false, "\
                "OPA will not be downloaded.")
        elif not opa_dir.is_dir():
            log.warning("The specified location for the OPA executable,"
                "%s, exists but is not a directory.", opa_dir)

    if opa_dir.exists() and opa_dir.is_dir() and download:
        # The OPA directory exists and the user hasn't suppressed the
        # download (e.g., no internet).  Get the OPA executable if it's
        # not already there.

        opa = opa_filespec(opa_dir)
        if not opa.exists():
            print(f'OPA executable not present, downloading: {opa.name}')
            download_opa(opa_dir, verify = True)

def validate_opa_dir(opa_dir: Path = None):

    """Validates that the OPA executable exists in the given directory or
    in a directory along the user's PATH.

    :param opa_dir: [optional] location of the OPA executable.

    :return: True if the OPA executable exists; False otherwise.
    """

    if opa_dir and opa_dir.exists() and not opa_dir.is_dir():
        log.warning('? %s - specified OPA path exists but is not a directory', opa_dir)
        return False

    try:
        opa_exe = find_opa(opa_dir)

        if opa_exe:
            where = ('' if opa_dir and opa_dir.samefile(opa_exe.parent)
                     else ' from PATH')
            log.info('  OPA executable: %s%s', opa_exe, where)

    except FileNotFoundError:
        opa_exe = None

    if not opa_exe:
        where = opa_dir or 'PATH'
        log.info('OPA executable not found in %s', where)

    return opa_exe is not None


def credentials_file(arguments: argparse.Namespace):

    """Sets the Google API credentials file in the user's configuration.

    :param arguments: arguments collected by the ArgumentParser.

    :return: True if the credentials file was changed in the user's
        configuration; False otherwise.
    """

    log.debug('Setup: Google API credentials file')

    check = not arguments.nocheck
    config = arguments.user_config
    credentials = arguments.credentials
    if credentials:
        # The user has explicitly specified the credentials file.  We only
        # need to check whether the file exists.
        print(f"Updating the default credentials file to {credentials}")
        if check and not credentials.is_file():
            raise FileNotFoundError(f'? {credentials} - file not found')

        log.debug('  specified file: %s', credentials)

        config.credentials_file = credentials.resolve()

        return True
    return False
