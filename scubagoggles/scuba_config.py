"""
Class for parsing the config file and command-line arguments.
"""

import argparse
import yaml

class ScubaConfig:
    """
    Class for parsing the config file and command-line arguments.
    """

    # Create a mapping of the long form of parameters to their short aliases
    _aliases_long = {
        "baselines": "b",
        "outputpath": "o",
        "credentials": "c"
    }

    def __init__(self, parser):
        self.__dict__.update(ScubaConfig._resolve_config(parser))

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
            if arg in cls._aliases_long:
                dests.append(f"-{cls._aliases_long[arg]}")
            # If the arg is a boolean, need to specify the store action
            # otherwise the boolean args will cause an error
            if isinstance(val, bool):
                aux_parser.add_argument(*dests, action="store_false")
            else:
                aux_parser.add_argument(*dests)
        cli_args, _ = aux_parser.parse_known_args()
        return cli_args

    @classmethod
    def _resolve_config(cls, parser : argparse.ArgumentParser) -> dict:
        """
        Parse the arguments and the config file, if provided, resolving any
        differences between the two.
        """
        args = parser.parse_args()

        # Create a mapping of the short param aliases to the long form
        aliases_short = {
            cls._aliases_long[key]: key for key in cls._aliases_long
        }

        # Get the args explicitly specified on the command-line so we know
        # what should override the config file
        cli_args = cls._get_explicit_cli_args(args)

        # If a config file is not specified, just return the args unchanged.
        if args.config is not None:
            with open(args.config, 'r', encoding="utf-8") as f:
                config = yaml.safe_load(f)
            config_params = list(config)
            for param in config_params:
                # If the short form of a param was provided in the config,
                # translate it to the long form
                if param in aliases_short:
                    config[aliases_short[param]] = config[param]
                    param = aliases_short[param]
                # If the param was specified in the command-line, the
                # command-line arg takes precedence
                if param in cli_args:
                    continue
                vars(args)[param] = config[param]
        # Return the args (argparse.Namespace) as a dictionary
        return vars(args)
