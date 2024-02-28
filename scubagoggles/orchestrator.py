"""
orchestrator.py is the main module that starts and handles the output of the
provider, rego, and report modules of the SCuBA tool
"""
import shutil
import os
import json
import webbrowser
from pathlib import Path
from datetime import datetime
from tqdm import tqdm
from googleapiclient.discovery import build

from scubagoggles.auth import gws_auth
from scubagoggles.provider import Provider
from scubagoggles.run_rego import opa_eval
from scubagoggles.reporter import reporter, md_parser
from scubagoggles.utils import rel_abs_path

def gws_products() -> dict:
    """
    Dictionary of the SCuBA GWS baselines short names plus full names
    """
    gws_baselines = [
        "gmail",
        "calendar",
        "groups",
        "chat",
        "drive",
        "meet",
        "sites",
        "commoncontrols",
        "rules",
        "classroom"
    ]
    prod_to_fullname = {
        "gmail": "Gmail",
        "calendar": "Google Calendar",
        "groups": "Groups for Business",
        "chat": "Google Chat",
        "drive": "Google Drive and Docs",
        "meet": "Google Meet",
        "sites": "Google Sites",
        "commoncontrols": "Common Controls",
        "rules": "Rules",
        "classroom": "Google Classroom"
    }
    gws = {
        "gws_baselines": gws_baselines,
        "prod_to_fullname": prod_to_fullname
    }
    return gws

def run_gws_providers(args, services : dict):
    """
    Runs the provider scripts and outputs a json to path

    :param args: the command line arguments to this script
    :param services: a dictionary of Google API service objects
    """

    products = args.baselines
    out_folder = args.outputpath
    provider_dict = {}

    provider = Provider(services, args.customerid)
    provider_dict = provider.call_gws_providers(products, args.quiet)
    provider_dict['successful_calls'] = list(provider.successful_calls)
    provider_dict['unsuccessful_calls'] = list(provider.unsuccessful_calls)

    settings_json = json.dumps(provider_dict, indent = 4)
    out_path = out_folder + f'/{args.outputproviderfilename}.json'
    with open(out_path, mode="w", encoding='UTF-8') as outfile:
        outfile.write(settings_json)

def rego_eval(args):
    """
    Executes the OPA executable with provider json input against
    specified rego files and outputs a json to path

    :param args: the command line arguments to this script
    """

    products = args.baselines
    products_bar = tqdm(products, leave=False, disable=args.quiet)
    out_folder = args.outputpath
    results = []
    for product in products_bar:
        product_name = product
        input_file = f'{out_folder}/{args.outputproviderfilename}.json'
        opa_path = args.opapath
        rego_path = args.regopath

        products_bar.set_description(f"Running Rego verification for {product}...")
        product_tests = opa_eval(
        product_name=product_name,
        input_file=input_file,
        opa_path=opa_path,
        rego_path=rego_path,
        omit_sudo=args.omitsudo,
        debug=args.debug
        )
        try:
            results.extend(product_tests[0])
        except Exception as exc:
            raise Exception("run_rego error") from exc

    settings_json = json.dumps(results,sort_keys=True ,indent = 4)
    out_path = out_folder + f'/{args.outputregofilename}.json'
    with open(out_path, mode="w", encoding='UTF-8') as outfile:
        outfile.write(settings_json)

def pluralize(singular : str, plural : str, count : int) -> str:
    """
    If count is 1, returns the singular version of the word.
    Else returns the plural version.
    :param singular: string value in singular tense
    :param plural: string value in plural tense
    :param count: how many of string value
    """
    if count == 1:
        return singular
    return plural

def generate_summary(stats : dict) -> str:
    """
    Craft the html-formatted summary from the stats dictionary.
    """
    n_success = stats["Pass"]
    n_warn = stats["Warning"]
    n_fail = stats["Fail"]
    n_manual = stats["N/A"] + stats["No events found"]
    n_error = stats["Error"]

    pass_summary = (f"<div class='summary pass'>{n_success}"
    f" {pluralize('test', 'tests', n_success)} passed</div>")

    # The warnings, failures, and manuals are only shown if they are
    # greater than zero. Reserve the space for them here. They will
    # be filled next if needed.
    warning_summary = "<div class='summary'></div>"
    failure_summary = "<div class='summary'></div>"
    manual_summary = "<div class='summary'></div>"
    error_summary = "<div class='summary'></div>"

    if n_warn > 0:
        warning_summary = (f"<div class='summary warning'>{n_warn}"
        f" {pluralize('warning', 'warnings', n_warn)}</div>")
    if n_fail > 0:
        failure_summary = (f"<div class='summary failure'>{n_fail}"
        f" {pluralize('test', 'tests', n_fail)} failed</div>")
    if n_manual > 0:
        manual_summary = (f"<div class='summary manual'>{n_manual} manual"
        f" {pluralize('check', 'checks', n_manual)} needed</div>")
    if n_error > 0:
        error_summary = (f"<div class='summary error'>{n_error}"
        f" {pluralize('error', 'errors', n_error)}</div>")

    return f"{pass_summary}{warning_summary}{failure_summary}{manual_summary}{error_summary}"

def run_reporter(args):
    """
    Creates the indvididual reports and the front page
    :param args: list of arguments to run report on
    """

    # Make the report output folders
    out_folder = args.outputpath
    individual_reports_path = out_folder + "/IndividualReports"
    reports_images_path = individual_reports_path + "/images"
    Path(individual_reports_path).mkdir(parents=True, exist_ok=True)
    Path(reports_images_path).mkdir(parents=True, exist_ok=True)

    # Copy the CISA logo to the repo folder so that it can be accessed
    # from there
    cisa_logo = str(rel_abs_path(__file__,"./reporter/images/cisa_logo.png"))
    triangle_svg = str(rel_abs_path(__file__,"./reporter/images/triangle-exclamation-solid.svg"))
    shutil.copy2(cisa_logo, reports_images_path)
    shutil.copy2(triangle_svg, reports_images_path)

    # we should load the testresults json here
    products = args.baselines
    prod_to_fullname = args.fullnamesdict
    test_results_json = out_folder + f'/{args.outputregofilename}.json'
    with open(test_results_json, mode='r', encoding='UTF-8') as file:
        test_results_data = json.load(file)

    # Get the successful/unsuccessful commands
    settings_name = f'{out_folder}/{args.outputproviderfilename}.json'
    with open(settings_name, mode='r', encoding='UTF-8') as file:
        settings_data = json.load(file)
    successful_calls = set(settings_data['successful_calls'])
    unsuccessful_calls = set(settings_data['unsuccessful_calls'])

    # baseline_path
    subset_prod_to_fullname = {
        key: prod_to_fullname[key]
        for key in args.baselines
        if key in prod_to_fullname
    }

    baseline_policies = md_parser.read_baseline_docs(args.documentpath,subset_prod_to_fullname)

    if 'rules' in args.baselines:
        # System-defined rules, which are part of the common controls baseline,
        # are separated into their own category for reporting purposes.  Here
        # we move any system-defined rules group(s) from the common controls
        # list to the rules list.  In practice, there may only be one group,
        # but multiple groups will be handled correctly.

        commoncontrols = baseline_policies['commoncontrols']
        rules = baseline_policies['rules'] = []
        rules_indices = [i for i, group in enumerate(commoncontrols)
                         if group['GroupName'] == 'System-defined Rules']

        for index in reversed(rules_indices):
            rule_group = commoncontrols.pop(index)
            rules.insert(0, rule_group)

        if not rules:
            raise RuntimeError("Unable to process 'rules' as no policy group "
                               "named 'System-defined Rules' found in the "
                               'Common Controls baseline.')

    # Load Org metadata from provider
    with open(f'{out_folder}/{args.outputproviderfilename}.json',
    mode='r',encoding='UTF-8') as file:
        tenant_info = json.load(file)['tenant_info']
        tenant_domain = tenant_info['domain']


    # Create the the individual report files
    report_stats = {}
    main_report_name = args.outputreportfilename
    products_bar = tqdm(products, leave=False, disable=args.quiet)

    for product in products_bar:
        products_bar.set_description(f"Creating the Report for {product}...")
        report_stats[product] = reporter.rego_json_to_html(
            test_results_data,
            product,
            out_folder,
            tenant_domain,
            main_report_name,
            prod_to_fullname,
            baseline_policies[product],
            successful_calls,
            unsuccessful_calls
        )

    # Make the report front page
    report_path = out_folder + "/" + f'{args.outputreportfilename}.html'
    abs_report_path = os.path.abspath(report_path)

    fragments = []
    table_data = []
    for product, stats in report_stats.items():
        ## Build the "Baseline Conformance Reports" column
        product_capitalize = product.capitalize()
        full_name = prod_to_fullname[product]
        link_path =  "./IndividualReports/" f"{product_capitalize}Report.html"
        link = f"<a class=\"individual_reports\" href={link_path}>{full_name}</a>"
        table_data.append({
            "Baseline Conformance Reports": link,
            "Details": generate_summary(stats)
        })

    fragments.append(reporter.create_html_table(table_data))
    with open(f"{report_path}", mode='w', encoding='UTF-8') as file:
        file.write(reporter.build_front_page_html(fragments, tenant_info))

    # suppress opening the report in the browser
    if args.quiet:
        return
    # Open the report in the client's default web browser
    # pylint: disable=E1101
    if os.name == 'nt':
        os.startfile(abs_report_path)
    else:
        report_path = "file:///" + abs_report_path
        webbrowser.get().open(report_path, new=2)

def run_cached(args):
    """
    Has the ability to run scuba on a cached provider json

    :param args: argparse object containing arguments to run
    """

    args.outputpath = str(rel_abs_path(__file__,args.outputpath))
    Path(args.outputpath).mkdir(parents=True, exist_ok=True)
    args.outputpath = os.path.abspath(args.outputpath)

    if not args.skipexport:
        creds = gws_auth(args.credentials)
        services = {}
        services['reports'] = build('admin', 'reports_v1', credentials=creds)
        services['directory'] = build('admin', 'directory_v1', credentials=creds)
        services['groups'] = build('groupssettings', 'v1', credentials=creds)
        run_gws_providers(args, services)
    rego_eval(args)
    run_reporter(args)

def start_automation(args):
    """
    Main orchestration function

    :param args: argparse object containing arguments to run
    """

    if "commoncontrols" in args.baselines and "rules" not in args.baselines:
        args.baselines.append("rules")
    if "rules" in args.baselines and "commoncontrols" not in args.baselines:
        args.baselines.append("commoncontrols")
    args.baselines.sort()

    # get the absolute paths relative to this directory
    args.outputpath = (Path.cwd() / args.outputpath).resolve()
    args.credentials = (Path.cwd() / args.credentials).resolve()
    args.opapath = Path(args.opapath).resolve()
    args.regopath = Path(args.regopath).resolve()
    args.documentpath = Path(args.documentpath).resolve()

    # add any additional variables to args
    gws_params = gws_products()
    additional_args = vars(args)
    additional_args['fullnamesdict'] = gws_params["prod_to_fullname"]

    if args.skipexport and not args.runcached:
        exc = 'Used --skipexport without --runcached' \
        'please rerun scubagoggles with --runcached as well'
        raise Exception(exc)

    if not args.runcached:
        # create a timestamped output folder
        now = datetime.now()
        folder_time = now.strftime("%Y_%m_%d_%H_%M_%S")
        timestamped_folder = f'{args.outputfoldername}_{folder_time}'
        args.outputpath = (args.outputpath / timestamped_folder).resolve()
        Path(args.outputpath).mkdir(parents=True, exist_ok=True)
        args.outputpath = os.path.abspath(args.outputpath)

        # authenticate
        creds = gws_auth(args.credentials, args.subjectemail)
        services = {}
        services['reports'] = build('admin', 'reports_v1', credentials=creds)
        services['directory'] = build('admin', 'directory_v1', credentials=creds)
        services['groups'] = build('groupssettings', 'v1', credentials=creds)

        run_gws_providers(args, services)
        rego_eval(args)
        run_reporter(args)
    else:
        run_cached(args)
