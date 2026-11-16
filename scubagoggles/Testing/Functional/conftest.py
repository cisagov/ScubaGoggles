"""
    conftest.py serves as a configuration file for pytest.

    Command-line options for every functional test suite are registered here,
    because pytest only reads options from conftest files it loads at startup.
    Fixtures live with the suite that uses them (SmokeTests/, Products/).
"""

from pathlib import Path

import pytest


def pytest_addoption(parser):
    """
        Add custom cli arguments when running `pytest`.

        Args:
            parser: An instance of "argparse.ArgumentParser"
    """
    parser.addoption("--subjectemail", action="store",
                     help="Delegated user email for service account auth "
                          "(smoke tests and --collect).")
    parser.addoption("--customerdomain", action="store")

    group = parser.getgroup("product functional tests")
    group.addoption("--test-driver", choices=("cached", "live"), default="cached",
                    help="Run the test plan cases with this test_driver (default: cached).")
    group.addoption("--collect", action="store_true", default=False,
                    help="Collect one read-only provider export for this session. "
                         "Cannot be combined with --export-file.")
    group.addoption("--export-file", type=Path, metavar="JSON_FILE",
                    help="Replay a ProviderSettingsExport or ScubaResults JSON file. "
                         "Cannot be combined with --collect.")
    group.addoption("--credentials", type=Path,
                    help="Google credentials file for --collect. "
                         "Defaults to the file saved by `scubagoggles setup`.")
    group.addoption("--customerid", help="Google customer ID for --collect.")
    group.addoption("--opapath", type=Path,
                    help="Directory containing the OPA executable. "
                         "Defaults to the directory saved by `scubagoggles setup`.")


def pytest_configure(config):
    """
        Reject option combinations the product tests cannot run with.
    """
    if config.getoption("--collect") and config.getoption("--export-file") is not None:
        raise pytest.UsageError("Choose --collect or --export-file, not both.")
    if config.getoption("--collect") and getattr(config.option, "numprocesses", None):
        raise pytest.UsageError("Fresh collection runs serially; omit pytest-xdist -n.")
    if config.getoption("--test-driver") == "live":
        raise pytest.UsageError("The live test driver is not implemented yet.")
