"""
Class for parsing the config file and command-line arguments.
"""

import argparse
import logging

from pathlib import Path

import yaml

from scubagoggles.reporter.md_parser import MarkdownParser
from scubagoggles.utils import path_parser


log = logging.getLogger(__name__)

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

class ScubaArgumentParser:
    """
    Class for parsing the config file and command-line arguments.
    """

    # Create a mapping of the long form of parameters to their short aliases
    _param_to_alias = {
        'baselines': 'b',
        'outputpath': 'o',
        'credentials': 'c'
    }

    def __init__(self, parser):
        self.parser = parser

    def parse_args(self) -> argparse.Namespace:
        """
        Parse the arguments without loading config file.
        """
        return self.parser.parse_args()

    def parse_args_with_config(self) -> argparse.Namespace:
        """
        Parse the arguments and the config file, if provided, resolving any
        differences between the two.
        """
        args = self.parse_args()

        logging.basicConfig(format='(%(levelname)s): %(message)s',
                            level=log_level(args.log))

        if 'breakglassaccounts' not in args or args.breakglassaccounts is None:
            args.breakglassaccounts = []

        if 'imapexclusions' not in args or args.imapexclusions is None:
            args.imapexclusions = []

        if 'sitesexclusions' not in args or args.sitesexclusions is None:
            args.sitesexclusions = []

        if not 'config' in args or not args.config:
            return args

        # Create a mapping of the short param aliases to the long form
        alias_to_param = {
            value: key for key, value in self._param_to_alias.items()
        }

        # Get the args explicitly specified on the command-line so we know
        # what should override the config file
        cli_args = self._get_explicit_cli_args(args)

        with open(args.config, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        config_params = list(config)
        for param in config_params:
            # If the short form of a param was provided in the config,
            # translate it to the long form
            if param in alias_to_param:
                config[alias_to_param[param]] = config[param]
                param = alias_to_param[param]
            # If the param was specified in the command-line, the
            # command-line arg takes precedence
            if param in cli_args:
                continue
            vars(args)[param] = config[param]

        # Check for logical errors in the resulting configuration
        self.validate_config(args)

        # Return the args (argparse.Namespace)
        return args

    @classmethod
    def _get_explicit_cli_args(cls, args : argparse.Namespace) -> dict:
        """
        Return the list of arguments that were explicitly specified on the
        command-line.
        """
        # Build a secondary parser, configure the secondary parser to
        # suppress the default values so the secondary parser will only
        # contain the values explicitly specified on the command-line.
        aux_parser = argparse.ArgumentParser(argument_default=argparse.SUPPRESS)
        for arg, val in vars(args).items():
            dests = [f'--{arg}']
            # If the arg has a short form alias, add the short form as well
            if arg in cls._param_to_alias:
                dests.append(f'-{cls._param_to_alias[arg]}')
            # If the arg is a boolean, need to specify the store action
            # otherwise the boolean args will cause an error
            if isinstance(val, bool):
                aux_parser.add_argument(*dests, action='store_false')
            else:
                aux_parser.add_argument(*dests)
        cli_args, _ = aux_parser.parse_known_args()
        return cli_args

    @staticmethod
    def validate_config(args : argparse.Namespace) -> None:
        """
        Check for an logical errors in the advanced ScubaGoggles configuration
        options.
        """

        # Options read in from the configuration file must be converted to the
        # same data type that's defined in the corresponding command parser
        # definition (see the main module).  The following option values are
        # read as strings but are converted to Path.

        path_value_options = ('credentials',
                              'documentpath',
                              'opapath',
                              'outputpath',
                              'regopath')

        for option_name in path_value_options:
            if option_name in args:
                option_value = getattr(args, option_name)
                if not isinstance(option_value, Path) and option_value is not None:
                    setattr(args, option_name, path_parser(option_value))

        if 'omitpolicy' in args:
            ScubaArgumentParser.validate_omissions(args)

        if 'annotatepolicy' in args:
            ScubaArgumentParser.validate_annotations(args)

        if 'imapexclusions' in args:
            ScubaArgumentParser.validate_imap_exclusions(args)

        if 'sitesexclusions' in args:
            ScubaArgumentParser.validate_sites_exclusions(args)

        # We want OrgName to be in PascalCase for consistency with ScubaGear.
        # But as all other options for ScubaGoggles are all lowercase, make
        # ScubaGoggles accept either orgname or OrgName to make things more
        # user friendly
        if 'orgname' in args:
            vars(args)['OrgName'] = args.orgname
            del vars(args)['orgname']

        if 'orgunitname' in args:
            vars(args)['OrgUnitName'] = args.orgunitname
            del vars(args)['orgunitname']

    @staticmethod
    def validate_omissions(args : argparse.Namespace) -> None:
        """
        Warn for any control IDs configured for omission that aren't in the
        set of IDs covered by the baselines specificied in --baselines.
        """

        md_products = set(args.baselines)

        # Parse the baselines to determine the set of valid control IDs
        md_parser = MarkdownParser(args.documentpath)
        baseline_policies = md_parser.parse_baselines(md_products)

        control_ids = set()
        for product_baseline in baseline_policies.values():
            for group in product_baseline:
                for control in group['Controls']:
                    control_ids.add(control['Id'].lower())

        # Warn for any unexpected IDs
        for control_id in args.omitpolicy:
            if control_id.lower() not in control_ids:
                log.warning('Config file indicates omitting %s but %s is not one of the '
                            'controls encompassed by the baselines indicated by the baselines '
                            'parameter. Control will not be omitted.', control_id, control_id)

    @staticmethod
    def validate_annotations(args : argparse.Namespace) -> None:
        """
        Warn for any control IDs configured for annotation that aren't in the
        set of IDs covered by the baselines specified in --baselines.
        """

        md_products = set(args.baselines)

        # Parse the baselines to determine the set of valid control IDs
        md_parser = MarkdownParser(args.documentpath)
        baseline_policies = md_parser.parse_baselines(md_products)

        control_ids = set()
        for product_baseline in baseline_policies.values():
            for group in product_baseline:
                for control in group['Controls']:
                    control_ids.add(control['Id'].lower())

        # Warn for any unexpected IDs
        for control_id in args.annotatepolicy:
            if control_id.lower() not in control_ids:
                log.warning('Config file adds annotations for %s, but %s is not one of the '
                            'controls encompassed by the baselines indicated by the baselines '
                            'parameter.', control_id, control_id)


    @staticmethod
    def validate_imap_exclusions(args: argparse.Namespace) -> None:
        """
        Validate and standardize structure of the IMAP exceptions.
        """

        if args.imapexclusions is None:
            args.imapexclusions = []

        for i, exception in enumerate(args.imapexclusions):
            args.imapexclusions[i] = {
                'ou': exception.get('ou', ''),
                'group': exception.get('group', ''),
                'justification': exception.get('justification', '')
            }
            if args.imapexclusions[i]['ou'] == '' and args.imapexclusions[i]['group'] == '':
                log.warning('Invalid entry in config file "imapexclusions": each entry must '
                            'specify at least an OU or a group.')

    @staticmethod
    def validate_sites_exclusions(args: argparse.Namespace) -> None:
        """
        Validate and standardize structure of the sites exceptions.
        """

        if args.sitesexclusions is None:
            args.sitesexclusions = []

        for i, exception in enumerate(args.sitesexclusions):
            args.sitesexclusions[i] = {
                'ou': exception.get('ou', ''),
                'group': exception.get('group', ''),
                'justification': exception.get('justification', '')
            }
            if args.sitesexclusions[i]['ou'] == '' and args.sitesexclusions[i]['group'] == '':
                log.warning('Invalid entry in config file "sitesexclusions": each entry must '
                            'specify at least an OU or a group.')
