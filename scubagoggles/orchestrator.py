"""
orchestrator.py is the main module that starts and handles the output of the
provider, rego, and report modules of the SCuBA tool
"""
import argparse
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
from scubagoggles.reporter import md_parser
from scubagoggles.reporter.reporter import Reporter
from scubagoggles.utils import rel_abs_path


class Orchestrator:

    """The Orchestrator class runs the provider to get the GWS configuration
    data, then runs OPA on the configuration data, and finally invokes the
    reporter to produce the conformance reports.
    """

    # Dictionary of the SCuBA GWS baselines short names plus full names.
    _gws_baselines = [
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
    _prod_to_fullname = {
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
    _gws = {
        "gws_baselines": _gws_baselines,
        "prod_to_fullname": _prod_to_fullname
    }

    def __init__(self, args: argparse.Namespace):

        """Orchestrator class initialization

        :param args: command arguments parsed by the argparse module.  See
            the GWS parser definition (get_gws_args()) in main.py for
            information about the arguments.
        """

        self._args = args

    @classmethod
    def gws_products(cls) -> dict:
        """
        Dictionary of the SCuBA GWS baselines short names plus full names
        """
        return cls._gws

    def _run_gws_providers(self, services: dict):
        """
        Runs the provider scripts and outputs a json to path

        :param services: a dictionary of Google API service objects
        """

        args = self._args
        products = args.baselines
        out_folder = args.outputpath

        provider = Provider(services, args.customerid)
        provider_dict = provider.call_gws_providers(products, args.quiet)
        provider_dict['successful_calls'] = list(provider.successful_calls)
        provider_dict['unsuccessful_calls'] = list(provider.unsuccessful_calls)

        settings_json = json.dumps(provider_dict, indent = 4)
        out_path = out_folder + f'/{args.outputproviderfilename}.json'
        with open(out_path, mode="w", encoding='UTF-8') as outfile:
            outfile.write(settings_json)

    def _rego_eval(self):
        """
        Executes the OPA executable with provider json input against
        specified rego files and outputs a json to path
        """

        args = self._args
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

    @staticmethod
    def _pluralize(singular: str, plural: str, count: int) -> str:
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

    @classmethod
    def _generate_summary(cls, stats: dict) -> str:
        """
        Craft the html-formatted summary from the stats dictionary.
        """
        n_success = stats["Passes"]
        n_warn = stats["Warnings"]
        n_fail = stats["Failures"]
        n_manual = stats["Manual"]
        n_error = stats["Errors"]
        n_omit = stats['Omit']

        pass_summary = (f"<div class='summary pass'>{n_success}"
        f" {cls._pluralize('pass', 'passes', n_success)}</div>")

        # The warnings, failures, and manuals are only shown if they are
        # greater than zero. Reserve the space for them here. They will
        # be filled next if needed.
        warning_summary = "<div class='summary'></div>"
        failure_summary = "<div class='summary'></div>"
        manual_summary = "<div class='summary'></div>"
        error_summary = "<div class='summary'></div>"
        omit_summary = "<div class='summary'></div>"

        if n_warn > 0:
            warning_summary = (f"<div class='summary warning'>{n_warn}"
            f" {cls._pluralize('warning', 'warnings', n_warn)}</div>")
        if n_fail > 0:
            failure_summary = (f"<div class='summary failure'>{n_fail}"
            f" {cls._pluralize('failure', 'failures', n_fail)}</div>")
        if n_manual > 0:
            manual_summary = (f"<div class='summary manual'>{n_manual} manual"
            f" {cls._pluralize('check', 'checks', n_manual)}</div>")
        if n_error > 0:
            error_summary = (f"<div class='summary error'>{n_error}"
            f" {cls._pluralize('error', 'errors', n_error)}</div>")
        if n_omit > 0:
            omit_summary = (f"<div class='summary manual'>{n_omit}"
            " omitted</div>")

        return f"{pass_summary}{warning_summary}{failure_summary}" \
            f"{manual_summary}{omit_summary}{error_summary}"

    def _run_reporter(self):
        """
        Creates the individual reports and the front page
        """

        # Make the report output folders
        args = self._args
        out_folder = args.outputpath
        individual_reports_path = out_folder + "/IndividualReports"
        reports_images_path = individual_reports_path + "/images"
        Path(individual_reports_path).mkdir(parents=True, exist_ok=True)
        Path(reports_images_path).mkdir(parents=True, exist_ok=True)

        # Copy the CISA logo to the repo folder so that it can be accessed
        # from there
        images_dir = Path(__file__).parent / 'reporter' / 'images'
        cisa_logo = images_dir / 'cisa_logo.png'
        triangle_svg = images_dir / 'triangle-exclamation-solid.svg'
        shutil.copy2(cisa_logo, reports_images_path)
        shutil.copy2(triangle_svg, reports_images_path)

        # we should load the test results json here
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

        baseline_policies = md_parser.read_baseline_docs(args.documentpath,
                                                         subset_prod_to_fullname)

        if "rules" in args.baselines:
            # There's no baseline specific to rules, so this case
            # needs to be handled separately
            baseline_policies["rules"] = []
            for group in baseline_policies['commoncontrols']:
                if group['GroupName'] == 'System-defined Rules':
                    baseline_policies["rules"].append(group)
                    break
            else:
                raise RuntimeError("Unable to process 'rules' as no policy group named "
                    "'System-defined Rules' found in the Common Controls baseline.")

        # Load Org metadata from provider
        with open(f'{out_folder}/{args.outputproviderfilename}.json',
        mode='r',encoding='UTF-8') as file:
            tenant_info = json.load(file)['tenant_info']
            tenant_domain = tenant_info['domain']

        # Determine if any controls were omitted in the config file
        omissions = {}
        if 'omitpolicy' in args and args.omitpolicy is not None:
            omissions = args.omitpolicy

        # Create the individual report files
        out_jsonfile = args.outjsonfilename
        summary = {}
        results = {}
        total_output = {}
        stats_and_data = {}

        products_assessed = [prod_to_fullname[product] for product in products
                             if product in prod_to_fullname]
        product_abbreviation_mapping = {fullname: shortname for shortname,
                                        fullname in prod_to_fullname.items()}

        timestamp_utc = datetime.utcnow()
        timestamp_zulu = timestamp_utc.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

        report_metadata = {
            "TenantId":  None,
            "DisplayName":  None,
            "DomainName":  tenant_domain,
            "ProductSuite":  "GWS",
            "ProductsAssessed": products_assessed,
            "ProductAbbreviationMapping": product_abbreviation_mapping,
            "Tool":  "ScubaGoggles",
            "ToolVersion":  "0.3.0",
            "TimeStampZulu": timestamp_zulu
        }

        total_output.update({"MetaData": report_metadata})

        main_report_name = args.outputreportfilename
        products_bar = tqdm(products, leave=False, disable=args.quiet)
        for product in products_bar:
            products_bar.set_description(f"Creating the HTML and JSON Report for {product}...")
            reporter = Reporter(product,
                                tenant_domain,
                                main_report_name,
                                prod_to_fullname,
                                baseline_policies[product],
                                successful_calls,
                                unsuccessful_calls,
                                omissions,
                                products_bar)
            stats_and_data[product] = \
                reporter.rego_json_to_ind_reports(test_results_data,
                                                  out_folder)
            baseline_product_summary = {product:stats_and_data[product][0]}
            baseline_product_results_json = {product:stats_and_data[product][1]}
            summary.update(baseline_product_summary)
            results.update(baseline_product_results_json)
            total_output.update({"Summary": summary})
            total_output.update({"Results": results})

        # Create the ScubaResults files
        with open(f'{out_folder}/{args.outputproviderfilename}.json', encoding='UTF-8') as file:
            raw_data = json.load(file)
        total_output.update({"Raw": raw_data})
        report = json.dumps(total_output, indent = 4)
        with open(f"{out_folder}/{out_jsonfile}.json", mode='w', encoding='UTF-8') as results_file:
            results_file.write(report)

        # Delete the ProviderOutput file as it's now encapsulated in the ScubaResults file
        os.remove(f"{out_folder}/{args.outputproviderfilename}.json")

        # Make the report front page
        report_path = out_folder + "/" + f'{args.outputreportfilename}.html'
        abs_report_path = os.path.abspath(report_path)

        fragments = []
        table_data = []
        for product, stats in stats_and_data.items():
            ## Build the "Baseline Conformance Reports" column
            product_capitalize = product.capitalize()
            full_name = prod_to_fullname[product]
            link_path =  "./IndividualReports/" f"{product_capitalize}Report.html"
            link = f"<a class=\"individual_reports\" href={link_path}>{full_name}</a>"
            table_data.append({
                "Baseline Conformance Reports": link,
                "Details": self._generate_summary(stats[0])
            })

        fragments.append(Reporter.create_html_table(table_data))
        with open(f"{report_path}", mode='w', encoding='UTF-8') as file:
            file.write(Reporter.build_front_page_html(fragments, tenant_info))

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

    def _run_cached(self):
        """
        Has the ability to run scuba on a cached provider json
        """

        args = self._args
        args.outputpath = str(rel_abs_path(__file__,args.outputpath))
        Path(args.outputpath).mkdir(parents=True, exist_ok=True)
        args.outputpath = os.path.abspath(args.outputpath)

        if not args.skipexport:
            creds = gws_auth(args.credentials)
            services = {}
            services['reports'] = build('admin', 'reports_v1', credentials=creds)
            services['directory'] = build('admin', 'directory_v1', credentials=creds)
            services['groups'] = build('groupssettings', 'v1', credentials=creds)
            self._run_gws_providers(services)

        if not os.path.exists(f'{args.outputpath}/{args.outputproviderfilename}.json'):
            # When running run_cached, the provider output might not exist as a stand-alone
            # file depending what version of ScubaGoggles created the output. If the provider
            # output doesn't exist as a standalone file, create it from the scuba results
            # file so the other functions can execute as normal.
            with open(f'{args.outputpath}/{args.outjsonfilename}.json', 'r',
                    encoding='UTF-8') as scuba_results:
                provider_output = json.load(scuba_results)['Raw']
            with open(f'{args.outputpath}/{args.outputproviderfilename}.json', 'w',
                    encoding='UTF-8') as provider_file:
                json.dump(provider_output, provider_file)
        self._rego_eval()
        self._run_reporter()

    def start_automation(self):
        """
        Main orchestration function
        """

        args = self._args
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
        gws_params = self.gws_products()
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

            self._run_gws_providers(services)
            self._rego_eval()
            self._run_reporter()
        else:
            self._run_cached()
