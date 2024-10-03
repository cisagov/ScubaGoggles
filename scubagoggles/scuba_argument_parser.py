"""
Class for parsing the config file and command-line arguments.
"""

import argparse
import yaml

class ScubaArgumentParser:
    """
    Class for parsing the config file and command-line arguments.
    """

    # Create a mapping of the long form of parameters to their short aliases
    _param_to_alias = {
        "baselines": "b",
        "outputpath": "o",
        "credentials": "c"
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

        # Create a mapping of the short param aliases to the long form
        alias_to_param = {
            value: key for key, value in self._param_to_alias.items()
        }

        # Get the args explicitly specified on the command-line so we know
        # what should override the config file
        cli_args = self._get_explicit_cli_args(args)

        # If a config file is not specified, just return the args unchanged.
        if args.config is not None:
            with open(args.config, 'r', encoding="utf-8") as f:
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
        # Return the args (argparse.Namespace) as a dictionary
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
            dests = [f"--{arg}"]
            # If the arg has a short form alias, add the short form as well
            if arg in cls._param_to_alias:
                dests.append(f"-{cls._param_to_alias[arg]}")
            # If the arg is a boolean, need to specify the store action
            # otherwise the boolean args will cause an error
            if isinstance(val, bool):
                aux_parser.add_argument(*dests, action="store_false")
            else:
                aux_parser.add_argument(*dests)
        cli_args, _ = aux_parser.parse_known_args()
        return cli_args
