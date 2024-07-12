"""
main.py is the main entry point and takes in arguments for the scuba tool

This module takes arguments and will start the process to run the providers,
rego, and report creation stages for the automated SCuBA conformance assessment
"""

import argparse
from scubagoggles.orchestrator import Orchestrator

def get_gws_args(parser):
    """
    Adds the arguments for the GWS parser

    :param parser: argparse object
    """
    gws = Orchestrator.gws_products()
    gws_baselines = gws["gws_baselines"]

    default_file_output_names = {
        "provider_output_name": "ProviderSettingsExport",
        "rego_output_name": "TestResults",
        "report_output_name": "BaselineReports",
        "output_folder_name": "GWSBaselineConformance",
        "json_output_name": "ScubaResults"
    }

    parser.add_argument('-b', '--baselines',
    type = str, nargs="+", default=gws_baselines, choices=gws_baselines, metavar='',
    help='A list of one or more abbreviated GWS baseline names that the tool will assess.' +
    f' Defaults to all baselines. Choices: {(", ".join(gws_baselines))}')

    parser.add_argument('-o','--outputpath', type=str,default='./', metavar='',
    help="The folder path where both the output JSON & HTML report will be created." +
    ' Defaults to "./" The current directory. ')

    parser.add_argument('-c','--credentials', type=str,default='./credentials.json', metavar='',
    help='The relative path and name of the OAuth / service account credentials json file. ' +
    'Defaults to "./credentials.json" which means the tool will look ' +
    'for the file named credentials.json in the current directory.')

    parser.add_argument('--outjsonfilename', type=str,
    default=default_file_output_names['json_output_name'], metavar='',
    help='The name of the file that encapsulates all assessment output.' +
    f" Defaults to {default_file_output_names['json_output_name']}.")

    parser.add_argument('--subjectemail', type=str, default=None, metavar='',
    help='Only applicable when using a service account. ' +
    'The email address of a user the service account should act on behalf of. ' +
    'This user must have the necessary privileges to run scubagoggles.')

    parser.add_argument("--customerid", type=str, default="my_customer", metavar='',
    help='The customer ID the tool should run on. Defaults to "my_customer" which will be' +
    ' the domain of the user / service account authenticating.')

    parser.add_argument('--opapath', type=str, default='./', metavar='',
    help='The relative path to the directory containing the OPA executable. ' +
    'Defaults to "./" the current executing directory.')

    parser.add_argument('--regopath', type=str, default='./rego', metavar='',
    help='The relative path to the directory contain the folder containing the rego files. ' +
    'Defaults to "./rego" the "rego" folder inside the current executing directory.')

    parser.add_argument('--documentpath', type=str, default='./baselines', metavar='',
    help='The relative path to the directory containing the SCuBA baseline documents. ' +
    'Defaults to "./baselines" the "baselines" folder inside the current executing directory.')

    parser.add_argument('--runcached', action='store_true',
    help='This switch when added will run in the tool in "RunCached mode". ' +
    'When combined with -sa allows to the user to skip authentication and provider export.')

    parser.add_argument('--skipexport', action = 'store_true',
    help='This switch when added will skip the provider export.' +
    'To be used in conjunction with --runcached.')

    parser.add_argument('--outputfoldername', type=str,
    default=default_file_output_names['output_folder_name'], metavar='',
    help='The name of the folder created in --outputpath where both the output JSON and' +
    ' the HTML report will be created.' +
    f" Defaults to {default_file_output_names['output_folder_name']}." +
    ' The client\'s local timestamp will be appended to this name.')

    parser.add_argument('--outputproviderfilename', type=str,
    default=default_file_output_names['provider_output_name'], metavar='',
    help='The name of the Provider output json in --outputpath.' +
    f" Defaults to {default_file_output_names['provider_output_name']}.")

    parser.add_argument('--outputregofilename', type=str,
    default=default_file_output_names['rego_output_name'], metavar='',
    help='The name of the Rego output json in --outputpath.' +
    f" Defaults to {default_file_output_names['rego_output_name']}.")

    parser.add_argument('--outputreportfilename', type=str,
    default=default_file_output_names['report_output_name'], metavar='',
    help='The name of the main html file homepage created in --outputpath.' +
    f" Defaults to {default_file_output_names['report_output_name']}.")

    parser.add_argument('--omitsudo', action = 'store_true',
    help='This switch prevents running the OPA executable with sudo.')

    parser.add_argument('--quiet', action = 'store_true',
    help='This switch suppresses automatically launching a web browser to open' +
    ' the html report output and the loading bar output.')

    parser.add_argument('--debug', action = 'store_true',
    help='This switch is used to print debugging information for OPA.')

def dive():
    """
    Takes in the arguments need to run scubagoggles
    """

    overall_description = """ SCuBA Security Baseline Conformance Automation Tool

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

    parser = argparse.ArgumentParser(add_help=True, description=overall_description,
    formatter_class=argparse.RawDescriptionHelpFormatter)

    subparsers = parser.add_subparsers(dest='scuba_cmd')

    gws_parser_help = "Run the SCuBA automated conformance " \
    "check against one or more Google Workspace products"
    gws_parser = subparsers.add_parser('gws', help=gws_parser_help)
    get_gws_args(gws_parser)

    args = parser.parse_args()

    if args.scuba_cmd == 'gws':
        Orchestrator(args).start_automation()
    else:
        raise Exception("Invalid subparser. Run scubagoggles -h to see a list of valid subparsers")
