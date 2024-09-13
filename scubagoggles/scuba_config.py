import argparse
import yaml
import sys


class ScubaConfig:
    # TODO add class documentation

    _aliases = {
        "baselines": "b",
        "outputpath": "o",
        "credentials": "c"
    }

    def __init__(self, parser):
        self.__dict__.update(ScubaConfig._resolve_config(parser))

    @classmethod
    def _resolve_config(cls, parser) -> dict:
        """
        Parse the arguments and the config file, if provided, resolving any differences
        between the two.
        """
        args = parser.parse_args()

        # Build a secondary parser to determine what parameters were actually
        # specified on the commandline, so as to know what the config file
        # should and should not override.
        aux_parser = argparse.ArgumentParser(argument_default=argparse.SUPPRESS)
        for arg, val in vars(args).items():
            dests = [f"--{arg}"]
            if arg in cls._aliases:
                dests.append(f"-{cls._aliases[arg]}")
            if isinstance(val, bool):
                aux_parser.add_argument(*dests, action="store_true")
            else:
                aux_parser.add_argument(*dests)
        cli_args, _ = aux_parser.parse_known_args()

        # If a config file is not specified, just return the args unchanged.
        if args.config is not None:
            with open(args.config, 'r') as f:
                config = yaml.safe_load(f)
            for param in config:
                if param in cli_args:
                    # Command-line args take precedence
                    continue
                else:
                    vars(args)[param] = config[param]
        return vars(args)