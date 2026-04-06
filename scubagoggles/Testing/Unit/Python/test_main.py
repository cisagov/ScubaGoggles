"""
test_main.py tests the main function.
"""
import argparse
from pathlib import Path
from types import SimpleNamespace
import sys
import pytest
from scubagoggles import main
from scubagoggles.main import (
    get_gws_args,
    get_opa_args,
    get_setup_args,
    get_purge_args,
    get_version_args,
)

# These tests intentionally inspect argparse internals.
# pylint: disable=protected-access

# Dummy classes are used for testing. Don't need to add unused code for pylint.
# pylint: disable=too-few-public-methods
# pylint: disable=unnecessary-pass

class TestMain:
    """ Test class for the main function."""

    def test_get_gws_args_adds_expected_arguments(self, monkeypatch):
        """ Test that get_gws_args adds expected arguments """

        # Patch dependencies used inside get_gws_args
        def path_parser_sentinel(value):
            return value

        monkeypatch.setattr(main, "path_parser", path_parser_sentinel)

        # default_file_names is treated like an object with attributes
        monkeypatch.setattr(
            main,
            "default_file_names",
            SimpleNamespace(
                json_output_name="out.json",
                output_folder_name="scuba-output",
                provider_output_name="provider.json",
                action_plan_name="action_plan.csv",
                rego_output_name="rego.json",
                report_output_name="report.html",
            ),
        )

        uuid_choices = (0, 13, 18, 36)
        monkeypatch.setattr(main, "NUMBER_OF_UUID_CHARACTERS_TO_TRUNCATE_CHOICES", uuid_choices)

        created = {"orchestrator_args": None, "start_called": 0}

        class DummyOrchestrator:
            """ Dummy Orchestrator """

            @staticmethod
            def gws_products():
                """ Unsorted input to verify sorting occurs in get_gws_args """

                return {"gws_baselines": ["zbaseline", "abaseline"]}

            def __init__(self, args):
                created["orchestrator_args"] = args

            def start_automation(self):
                """ Dummy start automation """

                created["start_called"] += 1

        monkeypatch.setattr(main, "Orchestrator", DummyOrchestrator)

        # Run both branches of credentials handling in a single pytest test
        for credentials_file in ("creds.json", None):
            user_config = SimpleNamespace(
                credentials_file=credentials_file,
                output_dir="OUTDIR",
                opa_dir="OPADIR",
            )
            parser = argparse.ArgumentParser()
            get_gws_args(parser, user_config)

            # Assert: dispatch is set and calls Orchestrator(args).start_automation()
            dispatch = parser.get_default("dispatch")
            assert callable(dispatch)
            args_obj = object()
            dispatch(args_obj)
            assert created["orchestrator_args"] is args_obj
            assert created["start_called"] == 1
            created["start_called"] = 0

            # Common expected baselines (sorted tuple)
            expected_baselines = ("abaseline", "zbaseline")
            baselines = parser._option_string_actions["--baselines"]
            assert baselines.nargs == "+"
            assert baselines.default == expected_baselines
            assert baselines.choices == expected_baselines
            assert baselines.metavar == "<baseline>"

            # Credentials branch
            cred = parser._option_string_actions["--credentials"]
            assert cred.option_strings == ["--credentials", "-c"]
            assert cred.metavar == "<credentials-JSON-file>"
            assert cred.type is path_parser_sentinel
            if credentials_file is None:
                assert cred.default is None
                assert "Required unless" in cred.help
            else:
                assert cred.default == Path(credentials_file)
                assert f"Defaults to {credentials_file}." in cred.help

            # Spot-check a few other arguments and defaults/types
            outputpath = parser._option_string_actions["--outputpath"]
            assert outputpath.option_strings == ["--outputpath", "-o"]
            assert outputpath.default == user_config.output_dir
            assert outputpath.type is path_parser_sentinel

            opapath = parser._option_string_actions["--opapath"]
            assert opapath.default == Path(user_config.opa_dir)
            assert opapath.type is path_parser_sentinel
            assert opapath.metavar == "<opa-directory>"

            reportname = parser._option_string_actions["--outputreportfilename"]
            assert reportname.default == "report.html"
            assert reportname.metavar == ""

            trunc = parser._option_string_actions["--numberofuuidcharacterstotruncate"]
            assert trunc.default == 18
            assert trunc.type is int
            assert trunc.choices == uuid_choices
            assert trunc.metavar == "<number>"

            # Cached Mode options argument group contains runcached and skipexport
            cached_groups = [g for g in parser._action_groups if g.title == "Cached Mode options"]
            assert len(cached_groups) == 1
            cached_group = cached_groups[0]
            cached_opts = {opt for a in cached_group._group_actions for opt in a.option_strings}
            assert "--runcached" in cached_opts
            assert "--skipexport" in cached_opts

    def test_get_opa_args_adds_expected_arguments(self, monkeypatch):
        """ Test get_opa_args adds expected arguments """

        # Arrange: patch globals so we can assert the exact objects used
        def getopa_sentinel():
            raise AssertionError("Should not be called in this test")

        def path_parser_sentinel(value):
            return value

        monkeypatch.setattr(main, "getopa", getopa_sentinel)
        monkeypatch.setattr(main, "path_parser", path_parser_sentinel)

        opa_version_sentinel = "9.9.9-test"
        monkeypatch.setattr(main, "OPA_VERSION", opa_version_sentinel)

        user_config = object()
        parser = argparse.ArgumentParser()

        # Act
        get_opa_args(parser, user_config)

        # Assert defaults
        assert parser.get_default("dispatch") is getopa_sentinel
        assert parser.get_default("user_config") is user_config

        # Lookup actions by long option
        nocheck = parser._option_string_actions["--nocheck"]
        force = parser._option_string_actions["--force"]
        opa_dir = parser._option_string_actions["--opa_directory"]
        latest = parser._option_string_actions["--latest"]
        version = parser._option_string_actions["--version"]

        # --nocheck / -nc
        assert nocheck.option_strings == ["--nocheck", "-nc"]
        assert nocheck.default is False
        assert nocheck.const is True
        assert nocheck.help == "Do not check hash code after download"

        # --force / -f
        assert force.option_strings == ["--force", "-f"]
        assert force.default is False
        assert force.const is True
        assert force.help == "Overwrite existing OPA executable"

        # --opa_directory / -r
        assert opa_dir.option_strings == ["--opa_directory", "-r"]
        assert opa_dir.metavar == "<directory>"
        assert opa_dir.type is path_parser_sentinel
        assert opa_dir.help == "Directory containing OPA executable"

        # --latest / -l
        assert latest.option_strings == ["--latest", "-l"]
        assert latest.default is False
        assert latest.const is True
        assert latest.help == "Download latest OPA version"

        # --version / -v
        assert version.option_strings == ["--version", "-v"]
        assert version.default == opa_version_sentinel
        assert version.metavar == "<OPA-version>"
        assert version.help == f"Version of OPA to download (default: {opa_version_sentinel})"

        # Mutually exclusive group contains latest and version
        assert len(parser._mutually_exclusive_groups) == 1
        group = parser._mutually_exclusive_groups[0]
        assert latest in group._group_actions
        assert version in group._group_actions

    def test_get_setup_args_adds_expected_arguments(self, monkeypatch):
        """ Test get_setup_args adds expected arguments """

        # Arrange: patch globals referenced by get_setup_args so we can assert identity
        def user_setup_sentinel():
            raise AssertionError("Should not be called in this test")

        def path_parser_sentinel(value):
            return value

        monkeypatch.setattr(main, "user_setup", user_setup_sentinel)
        monkeypatch.setattr(main, "path_parser", path_parser_sentinel)

        user_config = object()
        parser = argparse.ArgumentParser()

        # Act
        get_setup_args(parser, user_config)

        # Assert defaults
        assert parser.get_default("dispatch") is user_setup_sentinel
        assert parser.get_default("user_config") is user_config

        # Lookup created actions
        credentials = parser._option_string_actions["--credentials"]
        nocheck = parser._option_string_actions["--nocheck"]
        nodownload = parser._option_string_actions["--nodownload"]
        opapath = parser._option_string_actions["--opapath"]
        outputpath = parser._option_string_actions["--outputpath"]

        # --credentials / -c
        assert credentials.option_strings == ["--credentials", "-c"]
        assert credentials.metavar == "<JSON-credentials-file>"
        assert credentials.type is path_parser_sentinel
        assert credentials.help == "OAuth2 credentials file for Google APIs"

        # --nocheck / -nc
        assert nocheck.option_strings == ["--nocheck", "-nc"]
        assert nocheck.default is False
        assert nocheck.const is True  # store_true sets const=True
        assert nocheck.help == "Do not check for directory or file existence"

        # --nodownload / -nd
        assert nodownload.option_strings == ["--nodownload", "-nd"]
        assert nodownload.default is False
        assert nodownload.const is True
        assert nodownload.help == "Do not download OPA executable when it does not exist"

        # --opapath / -r
        assert opapath.option_strings == ["--opapath", "-r"]
        assert opapath.metavar == "<directory>"
        assert opapath.type is path_parser_sentinel
        assert opapath.help == "Directory containing OPA executable"

        # --outputpath / -o
        assert outputpath.option_strings == ["--outputpath", "-o"]
        assert outputpath.metavar == "<directory>"
        assert outputpath.type is path_parser_sentinel
        assert outputpath.help == "Scubagoggles output directory"

    def test_get_purge_args_adds_expected_arguments(self, monkeypatch):
        """ Test get_purge_args adds expected arguments """

        # Arrange
        def purge_reports_sentinel():
            raise AssertionError("Should not be called in this test")

        monkeypatch.setattr(main, "purge_reports", purge_reports_sentinel)

        user_config = object()
        parser = argparse.ArgumentParser()

        # Act
        get_purge_args(parser, user_config)

        # Assert defaults
        assert parser.get_default("dispatch") is purge_reports_sentinel
        assert parser.get_default("user_config") is user_config

        # Find actions
        expire_action = next(a for a in parser._actions if "--expire" in a.option_strings)
        keep_action = next(a for a in parser._actions if "--keep" in a.option_strings)

        # --expire / -e
        assert expire_action.option_strings == ["--expire", "-e"]
        assert expire_action.metavar == "<expire-days>"
        assert expire_action.type is int
        assert expire_action.default is None
        assert expire_action.help == "Days after which reports have expired"

        # --keep / -k
        assert keep_action.option_strings == ["--keep", "-k"]
        assert keep_action.metavar == "<keep-report-count>"
        assert keep_action.type is int
        assert keep_action.default == 1
        assert keep_action.help == "Number of recent reports to keep (default: 1)"

    def test_get_version_args_adds_expected_arguments(self, monkeypatch):
        """ Test get_version_args adds expected arguments """

        dispatch_sentinel = object()

        class DummyVersion:
            """ Dummy version """

            command_dispatch = dispatch_sentinel

        monkeypatch.setattr(main, "Version", DummyVersion)

        parser = argparse.ArgumentParser()
        get_version_args(parser)

        # set_defaults(dispatch=...)
        assert parser.get_default("dispatch") is dispatch_sentinel

        # Find actions by option string
        check_action = next(a for a in parser._actions if "--check" in a.option_strings)
        upgrade_action = next(a for a in parser._actions if "--upgrade" in a.option_strings)

        # --check / -c
        assert check_action.option_strings == ["--check", "-c"]
        assert check_action.default is False
        assert check_action.const is True
        assert check_action.help == "(developers) Check version number consistency in code"

        # --upgrade / -u
        assert upgrade_action.option_strings == ["--upgrade", "-u"]
        assert upgrade_action.metavar == "<version>"
        assert upgrade_action.help == "(developers) Upgrade code to new version number"

        # They should be in the same mutually exclusive group
        assert len(parser._mutually_exclusive_groups) == 1
        group = parser._mutually_exclusive_groups[0]
        assert check_action in group._group_actions
        assert upgrade_action in group._group_actions



    @pytest.fixture
    def main_module(self):
        """ Reuse the globally-imported module """

        return main

    @pytest.fixture
    def patched_main(self, monkeypatch, main_module):
        """ Patch main function """

        class DummyUserConfig:
            """ Dummy class for testing"""

            pass

        monkeypatch.setattr(main_module, "UserConfig", DummyUserConfig)

        class DummyScubaArgumentParser:
            """ Dummy class for testing """

            def __init__(self, parser):
                self._parser = parser

            def parse_args_with_config(self):
                """ Dummy function for testing """

                return self._parser.parse_args()

        monkeypatch.setattr(main_module, "ScubaArgumentParser", DummyScubaArgumentParser)

        return main_module

    @pytest.mark.parametrize("subcommand", ["getopa", "gws", "purge", "setup", "version"])
    def test_dive_dispatches_to_each_subcommand(self, monkeypatch, patched_main, subcommand):
        """ Test dive dispatches to each subcommand """

        main_module = patched_main

        dispatch_calls = {name: [] for name in ["getopa", "gws", "purge", "setup", "version"]}

        def make_dispatch(name):
            def _dispatch(*args, **kwargs):
                dispatch_calls[name].append((args, kwargs))

            return _dispatch

        def fake_get_gws_args(parser, _user_config):
            parser.set_defaults(dispatch=make_dispatch("gws"))

        def fake_get_opa_args(parser, _user_config):
            parser.set_defaults(dispatch=make_dispatch("getopa"))

        def fake_get_purge_args(parser, _user_config):
            parser.set_defaults(dispatch=make_dispatch("purge"))

        def fake_get_setup_args(parser, _user_config):
            parser.set_defaults(dispatch=make_dispatch("setup"))

        def fake_get_version_args(parser):
            parser.set_defaults(dispatch=make_dispatch("version"))

        monkeypatch.setattr(main_module, "get_gws_args", fake_get_gws_args)
        monkeypatch.setattr(main_module, "get_opa_args", fake_get_opa_args)
        monkeypatch.setattr(main_module, "get_purge_args", fake_get_purge_args)
        monkeypatch.setattr(main_module, "get_setup_args", fake_get_setup_args)
        monkeypatch.setattr(main_module, "get_version_args", fake_get_version_args)

        monkeypatch.setattr(sys, "argv", ["scubagoggles", subcommand])

        main_module.dive()

        assert len(dispatch_calls[subcommand]) == 1
        for name in dispatch_calls:
            if name != subcommand:
                assert len(dispatch_calls[name]) == 0
