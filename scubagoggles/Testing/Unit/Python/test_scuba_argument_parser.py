"""Tests for config-file argument validation."""

import argparse
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest
import yaml

from scubagoggles.main import get_gws_args
from scubagoggles.scuba_argument_parser import ScubaArgumentParser


BOOLEAN_ARGUMENTS = (
    'quiet',
    'silencebodwarnings',
    'skipdoh',
    'debug',
    'runcached',
    'skipexport',
)

NARGS_PLUS_ARGUMENTS = (
    'baselines',
    'preferreddnsresolvers',
    'preferreddohservers',
)

PATH_ARGUMENTS = (
    'credentials',
    'outputpath',
    'opapath',
    'regopath',
    'documentpath',
)

STRING_ARGUMENTS = (
    'accesstoken',
    'outjsonfilename',
    'subjectemail',
    'customerid',
    'outputfoldername',
    'outputproviderfilename',
    'outputactionplanfilename',
    'outputregofilename',
    'outputreportfilename',
)


class ScubaArgumentParserTest:
    """Test config values against the real GWS argparse actions."""

    @staticmethod
    def _parser(tmp_path):
        parser = argparse.ArgumentParser()
        parser.add_argument('--log', default='warning')
        subparsers = parser.add_subparsers()
        gws_parser = subparsers.add_parser('gws')
        user_config = SimpleNamespace(
            credentials_file=None,
            output_dir=tmp_path / 'default-output',
            opa_dir=tmp_path / 'default-opa',
        )
        get_gws_args(gws_parser, user_config)
        return ScubaArgumentParser(parser)

    @staticmethod
    def _write_config(tmp_path, config):
        config_file = tmp_path / 'config.yaml'
        config_file.write_text(yaml.safe_dump(config), encoding='utf-8')
        return config_file

    def _parse_config(self, tmp_path, monkeypatch, config):
        config_file = self._write_config(tmp_path, config)
        monkeypatch.setattr(
            sys,
            'argv',
            ['scubagoggles', 'gws', '--config', str(config_file)],
        )
        return self._parser(tmp_path).parse_args_with_config()

    def test_all_valid_gws_argument_forms_are_loaded(self, tmp_path,
                                                     monkeypatch):
        """Valid values for every GWS argument form retain CLI semantics."""
        config = {
            'credentials': 'credentials.json',
            'darkmode': 'true',
            'cicdtestingmode': 'false',
            'accesstoken': 'access-token',
            'baselines': ['calendar', 'chat'],
            'outputpath': 'reports',
            'outjsonfilename': 'results.json',
            'subjectemail': 'admin@example.gov',
            'customerid': 'customer-id',
            'opapath': 'opa',
            'regopath': 'rego',
            'documentpath': 'baselines',
            'outputfoldername': 'output',
            'outputproviderfilename': 'provider.json',
            'outputactionplanfilename': 'action-plan.csv',
            'outputregofilename': 'rego.json',
            'outputreportfilename': 'report.html',
            'preferreddnsresolvers': ['1.1.1.1', '8.8.8.8'],
            'preferreddohservers': ['cloudflare-dns.com'],
            'quiet': True,
            'silencebodwarnings': True,
            'skipdoh': True,
            'numberofuuidcharacterstotruncate': 13,
            'debug': True,
            'runcached': True,
            'skipexport': True,
        }

        args = self._parse_config(tmp_path, monkeypatch, config)

        assert args.baselines == ['calendar', 'chat']
        assert args.numberofuuidcharacterstotruncate == 13
        for param in PATH_ARGUMENTS:
            assert isinstance(getattr(args, param), Path)
        for param in BOOLEAN_ARGUMENTS:
            assert getattr(args, param) is True
        for param in STRING_ARGUMENTS:
            assert getattr(args, param) == config[param]

    @pytest.mark.parametrize('value', ['18', 18.0, True])
    def test_integer_type_must_match(self, tmp_path, monkeypatch, value):
        """The integer GWS argument rejects every representative wrong type."""
        config = {'numberofuuidcharacterstotruncate': value}

        with pytest.raises(RuntimeError, match=(
                '"numberofuuidcharacterstotruncate" must be of type int')):
            self._parse_config(tmp_path, monkeypatch, config)

    @pytest.mark.parametrize(
        ('param', 'value'),
        (
            ('darkmode', 'True'),
            ('cicdtestingmode', 'invalid'),
            ('baselines', ['fakebaseline']),
            ('baselines', ['Chat']),
            ('numberofuuidcharacterstotruncate', 3),
        ),
    )
    def test_all_choices_are_validated(self, tmp_path, monkeypatch, param,
                                       value):
        """Every GWS action declaring choices rejects an invalid choice."""
        with pytest.raises(RuntimeError,
                           match=f'Invalid choice.*"{param}"'):
            self._parse_config(tmp_path, monkeypatch, {param: value})

    @pytest.mark.parametrize('param', NARGS_PLUS_ARGUMENTS)
    def test_all_nargs_plus_arguments_require_a_list(self, tmp_path,
                                                     monkeypatch, param):
        """Every nargs='+' GWS argument rejects a YAML scalar."""
        with pytest.raises(RuntimeError, match=f'"{param}" must be a list'):
            self._parse_config(tmp_path, monkeypatch, {param: 'value'})

    @pytest.mark.parametrize('param', NARGS_PLUS_ARGUMENTS)
    def test_all_nargs_plus_arguments_require_a_value(self, tmp_path,
                                                      monkeypatch, param):
        """Every nargs='+' GWS argument rejects an empty YAML list."""
        with pytest.raises(RuntimeError,
                           match=f'"{param}" must contain at least one value'):
            self._parse_config(tmp_path, monkeypatch, {param: []})

    @pytest.mark.parametrize('param', NARGS_PLUS_ARGUMENTS)
    def test_all_nargs_plus_elements_must_be_strings(self, tmp_path,
                                                     monkeypatch, param):
        """Every nargs='+' GWS argument rejects non-string list elements."""
        with pytest.raises(RuntimeError,
                           match=f'"{param}" must be of type str'):
            self._parse_config(tmp_path, monkeypatch, {param: [123]})

    @pytest.mark.parametrize('param', BOOLEAN_ARGUMENTS)
    def test_all_boolean_actions_require_booleans(self, tmp_path, monkeypatch,
                                                  param):
        """Every GWS boolean action rejects a string representation."""
        with pytest.raises(RuntimeError,
                           match=f'"{param}" must be of type bool'):
            self._parse_config(tmp_path, monkeypatch, {param: 'true'})

    @pytest.mark.parametrize('param', PATH_ARGUMENTS)
    def test_all_path_actions_require_path_strings(self, tmp_path, monkeypatch,
                                                   param):
        """Every GWS path action rejects a non-path YAML value."""
        with pytest.raises(RuntimeError,
                           match=f'"{param}" must be a path string'):
            self._parse_config(tmp_path, monkeypatch, {param: 123})

    @pytest.mark.parametrize('param', STRING_ARGUMENTS)
    def test_all_string_actions_require_strings(self, tmp_path, monkeypatch,
                                                param):
        """Every ordinary string GWS action rejects a non-string value."""
        with pytest.raises(RuntimeError,
                           match=f'"{param}" must be of type str'):
            self._parse_config(tmp_path, monkeypatch, {param: 123})

    def test_config_only_parameters_remain_supported(self, tmp_path,
                                                     monkeypatch):
        """Parameters without argparse actions pass through unchanged."""
        args = self._parse_config(
            tmp_path, monkeypatch, {'description': 'Agency configuration'}
        )

        assert args.description == 'Agency configuration'
