"""
main.py is the main entry point and takes in arguments for the scuba tool

This module takes arguments and will start the process to run the providers,
rego, and report creation stages for the automated SCuBA conformance assessment
"""

import argparse
import logging
import sys

from pathlib import Path

from google.auth.exceptions import RefreshError

from scubagoggles.config import UserConfig
from scubagoggles.getopa import getopa
from scubagoggles.orchestrator import Orchestrator, UserRuntimeError
from scubagoggles.purge import purge_reports
from scubagoggles.reporter.md_parser import MarkdownParserError
from scubagoggles.scuba_argument_parser import ScubaArgumentParser
from scubagoggles.user_setup import default_file_names, user_setup
from scubagoggles.utils import path_parser
from scubagoggles.version import Version
from scubagoggles.scuba_constants import NUMBER_OF_UUID_CHARACTERS_TO_TRUNCATE_CHOICES, OPA_VERSION

EXIT_FAILURE = 1

EXIT_SUCCESS = 0


def get_gws_args(parser: argparse.ArgumentParser, user_config: UserConfig):
    """Adds the arguments for the GWS parser

    :param argparse.ArgumentParser parser: argparse object
    :param UserConfig user_config: user configuration object
    """

    scuba_path = Path(__file__).parent

    gws = Orchestrator.gws_products()
    gws_baselines = tuple(sorted(gws['gws_baselines']))

    def gws_dispatch(args):
        Orchestrator(args).start_automation()

    parser.set_defaults(dispatch=gws_dispatch)

    help_msg = ('The location and name of the OAuth / service account '
            'credentials json file. ')
    if user_config.credentials_file is not None:
        help_msg += f'Defaults to {user_config.credentials_file}.'
        parser.add_argument('--credentials',
                            '-c',
                            default=Path(user_config.credentials_file),
                            metavar='<credentials-JSON-file>',
                            type=path_parser,
                            help=help_msg)
    else:
        help_msg += ('Required unless the credentials path '
            'has been saved using the ScubaGoggles setup utility.')
        parser.add_argument('--credentials',
                            '-c',
                            metavar='<credentials-JSON-file>',
                            default=None,
                            type=path_parser,
                            help=help_msg)

    help_msg = ('A list of one or more abbreviated GWS baseline names that the '
                'tool will assess. Defaults to all baselines. '
                f'Choices: {(", ".join(gws_baselines))}')
    parser.add_argument('--baselines',
                        '-b',
                        nargs='+',
                        default=gws_baselines,
                        choices=gws_baselines,
                        metavar='<baseline>',
                        help=help_msg)

    help_msg = ('The folder path where both the output JSON & HTML report will '
                f'be created. Defaults to "{user_config.output_dir}".')
    parser.add_argument('--outputpath',
                        '-o',
                        default=user_config.output_dir,
                        metavar='<directory>',
                        type=path_parser,
                        help=help_msg)

    default_json = default_file_names.json_output_name
    help_msg = ('The name of the file that encapsulates all assessment output. '
                f' Defaults to {default_json}.')
    parser.add_argument('--outjsonfilename',
                        default=default_json,
                        metavar='<output-JSON-file>',
                        help=help_msg)

    help_msg = ('Local file path to a YAML formatted configuration file. '
                'Configuration file parameters can be used in place of '
                'command-line parameters. Additional parameters and variables '
                'not available on the command line can also be included in '
                'the file that will be provided to the tool for use in '
                'specific tests.')
    parser.add_argument('--config',
                        metavar='<YAML-config-file>',
                        help=help_msg)

    help_msg = ('Only applicable when using a service account. The email '
                'address of a user the service account should act on '
                'behalf of. This user must have the necessary privileges '
                'to run scubagoggles.')
    parser.add_argument('--subjectemail',
                        metavar='<email-address>',
                        help=help_msg)

    help_msg = ('The customer ID the tool should run on. Defaults to '
                '"my_customer" which will be the domain of the '
                'user / service account authenticating.')
    parser.add_argument('--customerid',
                        default='my_customer',
                        metavar='<customer-id>',
                        help=help_msg)

    help_msg = ('The directory containing the OPA executable. '
                f'Defaults to {user_config.opa_dir}.')
    parser.add_argument('--opapath',
                        default=Path(user_config.opa_dir),
                        metavar='<opa-directory>',
                        type=path_parser,
                        help=help_msg)

    default_rego = scuba_path / 'rego'
    help_msg = ('The relative path to the directory contain the folder '
                f'containing the rego files. Defaults to {default_rego}.')
    parser.add_argument('--regopath',
                        default=default_rego,
                        metavar='<directory>',
                        type=path_parser,
                        help=help_msg)

    default_baselines = scuba_path / 'baselines'
    help_msg = ('The relative path to the directory containing the SCuBA '
                f'baseline documents. Defaults to {default_baselines}')
    parser.add_argument('--documentpath',
                        default=default_baselines,
                        metavar='<directory>',
                        type=path_parser,
                        help=help_msg)

    output_folder = default_file_names.output_folder_name
    help_msg = ('The name of the folder created in --outputpath where both '
                'the output JSON and the HTML report will be created. '
                f"Defaults to {output_folder}. The client's local timestamp "
                'will be appended to this name.')
    parser.add_argument('--outputfoldername',
                        default=output_folder,
                        metavar='<name>',
                        help=help_msg)

    provider_filename = default_file_names.provider_output_name
    help_msg = ('The name of the Provider output json in --outputpath. '
                f'Defaults to {provider_filename}.')
    parser.add_argument('--outputproviderfilename',
                        default=provider_filename,
                        metavar='<name>',
                        help=help_msg)

    actionplan_filename = default_file_names.action_plan_name
    help_msg = ('The name of the action plan output csv in --outputpath. '
                f'Defaults to {actionplan_filename}.')
    parser.add_argument('--outputactionplanfilename',
                        default=actionplan_filename,
                        metavar='<name>',
                        help=help_msg)

    rego_filename = default_file_names.rego_output_name
    help_msg = ('The name of the Rego output json in --outputpath. '
                f'Defaults to {rego_filename}.')
    parser.add_argument('--outputregofilename',
                        default=rego_filename,
                        metavar='<name>',
                        help=help_msg)

    report_filename = default_file_names.report_output_name
    help_msg = ('The name of the main html file homepage created in '
                '--outputpath. Defaults to '
                f'{report_filename}.')
    parser.add_argument('--outputreportfilename',
                        default=report_filename,
                        metavar='',
                        help=help_msg)

    help_msg = ('This switch suppresses automatically launching a web '
                'browser to open the html report output and the loading '
                'bar output.')
    parser.add_argument('--quiet', action='store_true', help=help_msg)

    default_uuid_chars_to_truncate = 18
    help_msg = ('Controls how many characters will be truncated '
                'from the report UUID when appended to the end of outjsonfilename. '
                'Valid values are 0, 13, 18, 36. '
                f'Defaults to {default_uuid_chars_to_truncate}.')
    parser.add_argument('--numberofuuidcharacterstotruncate',
                        default=default_uuid_chars_to_truncate,
                        choices=NUMBER_OF_UUID_CHARACTERS_TO_TRUNCATE_CHOICES,
                        type=int,
                        metavar='<number>',
                        help=help_msg)

    help_msg = 'This switch is used to print debugging information for OPA.'
    parser.add_argument('--debug', action='store_true', help=help_msg)

    group = parser.add_argument_group('Cached Mode options')

    help_msg = ('This switch when added will run in the tool in '
                '"RunCached mode". When combined with --skipexport allows '
                'the user to skip authentication and provider export.')
    group.add_argument('--runcached',
                       action='store_true',
                       help=help_msg)

    help_msg = ('This switch when added will skip the provider export. To be '
                'used in conjunction with --runcached.')
    group.add_argument('--skipexport',
                       action='store_true',
                       help=help_msg)


def get_opa_args(parser: argparse.ArgumentParser, user_config: UserConfig):
    """Adds the arguments for the "get OPA" parser.

    :param argparse.ArgumentParser parser: argparse object
    """

    parser.set_defaults(dispatch=getopa)

    parser.set_defaults(user_config=user_config)

    parser.add_argument('--nocheck',
                        '-nc',
                        default=False,
                        action='store_true',
                        help='Do not check hash code after download')

    parser.add_argument('--force',
                        '-f',
                        default=False,
                        action='store_true',
                        help='Overwrite existing OPA executable')

    parser.add_argument('--opa_directory',
                        '-r',
                        metavar='<directory>',
                        type=path_parser,
                        help='Directory containing OPA executable')

    version_group = parser.add_mutually_exclusive_group()

    version_group.add_argument('--latest',
                               '-l',
                               action='store_true',
                               help='Download latest OPA version')

    version_group.add_argument('--version',
                               '-v',
                               default = OPA_VERSION,
                               metavar = '<OPA-version>',
                               help = 'Version of OPA to download (default: '
                                   f'{OPA_VERSION})')

def get_setup_args(parser: argparse.ArgumentParser, user_config: UserConfig):
    """Adds the arguments for the setup parser

    :param argparse.ArgumentParser parser: argparse object
    :param UserConfig user_config: user configuration object
    """

    parser.set_defaults(dispatch=user_setup)

    parser.set_defaults(user_config=user_config)

    parser.add_argument('--credentials',
                        '-c',
                        metavar='<JSON-credentials-file>',
                        type=path_parser,
                        help='OAuth2 credentials file for Google APIs')

    parser.add_argument('--nocheck',
                        '-nc',
                        default=False,
                        action='store_true',
                        help='Do not check for directory or file existence')

    parser.add_argument('--nodownload',
                        '-nd',
                        default=False,
                        action='store_true',
                        help='Do not download OPA executable when it does '
                        'not exist')

    parser.add_argument('--opapath',
                        '-r',
                        metavar='<directory>',
                        type=path_parser,
                        help='Directory containing OPA executable')

    parser.add_argument('--outputpath',
                        '-o',
                        metavar='<directory>',
                        type=path_parser,
                        help='Scubagoggles output directory')


def get_purge_args(parser: argparse.ArgumentParser, user_config: UserConfig):
    """Adds the arguments for the purge parser

    :param argparse.ArgumentParser parser: argparse object
    :param UserConfig user_config: user configuration object
    """

    parser.set_defaults(dispatch=purge_reports)

    parser.set_defaults(user_config=user_config)

    parser.add_argument('--expire',
                        '-e',
                        metavar='<expire-days>',
                        type=int,
                        help='Days after which reports have expired')

    keep_default = 1
    parser.add_argument('--keep',
                        '-k',
                        metavar='<keep-report-count>',
                        type=int,
                        default=keep_default,
                        help='Number of recent reports to keep (default: '
                        f'{keep_default})')


def get_version_args(parser: argparse.ArgumentParser):
    """Adds the arguments for the version parser

    :param argparse.ArgumentParser parser: argparse object
    """

    parser.set_defaults(dispatch=Version.command_dispatch)

    group = parser.add_mutually_exclusive_group()

    pfx = '(developers)'

    group.add_argument('--check',
                       '-c',
                       default=False,
                       action='store_true',
                       help=f'{pfx} Check version number consistency in code')

    group.add_argument('--upgrade',
                       '-u',
                       metavar='<version>',
                       help=f'{pfx} Upgrade code to new version number')


def log_level(level):
    """Normalizes a given log level string.

    A complete upper-cased log level string is returned if the given string
    uniquely identifies one of the log levels.  The returned log level string
    may be passed to the logger routines.

    :param str level: abbreviation that uniquely identifies
        a log level (e.g., 'd', 'info', 'crit').

    :return: upper-cased log level string.
    """

    log_levels = ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')

    return_level = level.upper()

    if return_level not in log_levels:

        match_level = [x for x in log_levels if x.startswith(return_level)]

        if not match_level:
            raise RuntimeError(f'{level} - unrecognized log level')

        return_level = match_level[0]

    return return_level


def dive():
    """Takes in the arguments needed to run scubagoggles
    """

    overall_description = """SCuBA Security Baseline Conformance Automation Tool

    # Examples

    # run a conformance check against all GWS Security Baselines with defaults
    scubagoggles gws

    # run a conformance check against just the Gmail Security Baseline
    scubagoggles gws -b gmail

    # run a conformance check and output to a 'ScubaResults' folder
    scubagoggles gws -b calendar, gmail, groups -o ./ScubaResults

    # run gws with -h to see arguments for the gws subparser
    scubagoggles gws -h
    """

    helpFormatter = argparse.RawDescriptionHelpFormatter
    parser = argparse.ArgumentParser(description=overall_description,
                                     formatter_class=helpFormatter)

    parser.set_defaults(dispatch=lambda _: parser.print_help())

    log_levels = ('debug', 'info', 'warning', 'error', 'critical')

    default_log_level = 'warning'

    user_config = UserConfig()

    parser.add_argument('--log',
                        '-l',
                        choices=('d', 'i', 'w', 'e', 'c') + log_levels,
                        default=default_log_level,
                        help='Level for message log '
                        f'(default: {default_log_level})')

    subparsers = parser.add_subparsers(description='valid subcommands:',
                                       help='<subcommand> -h for help')

    help_msg = ('SCuBA automated conformance check for '
                'Google Workspace (GWS) products')
    gws_parser = subparsers.add_parser('gws',
                                       description=help_msg,
                                       help=help_msg)
    get_gws_args(gws_parser, user_config)

    help_msg = 'Download OPA executable'
    getopa_parser = subparsers.add_parser('getopa',
                                          description=help_msg,
                                          help=help_msg)
    get_opa_args(getopa_parser, user_config)

    help_msg = 'Purge old ScubaGoggles reports'
    purge_parser = subparsers.add_parser('purge',
                                         description=help_msg,
                                         help=help_msg)
    get_purge_args(purge_parser, user_config)

    help_msg = 'ScubaGoggles user setup'
    setup_parser = subparsers.add_parser('setup',
                                         description=help_msg,
                                         help=help_msg)
    get_setup_args(setup_parser, user_config)

    help_msg = 'ScubaGoggles version'
    setup_parser = subparsers.add_parser('version',
                                         description=help_msg,
                                         help=help_msg)
    get_version_args(setup_parser)

    scuba_parser = ScubaArgumentParser(parser)
    args = scuba_parser.parse_args_with_config()

    logging.basicConfig(format='(%(levelname)s): %(message)s')
    level = log_level(args.log)
    log = logging.root
    log.setLevel(level)

    # When trapping exceptions to suppress tracebacks (which users don't need
    # to see for obvious failures not related to the code), make sure the
    # process exits with an error code.

    error = False

    try:
        args.dispatch(args)
    except NotADirectoryError as nad:
        print(f'\n{nad}')
        error = True
    except FileNotFoundError as fnf:
        print(f'\n{fnf}')
        error = True
    except MarkdownParserError as mpe:
        print(f'\n{mpe}')
        error = True
    except UserRuntimeError as ure:
        print(f'\n{ure}')
        error = True
    except KeyboardInterrupt:
        print('\nUser interrupt')
    except RefreshError as rfe:
        print(f'\n{rfe}')
        error = True

    if error:
        sys.exit(EXIT_FAILURE)


if __name__ == '__main__':
    dive()
