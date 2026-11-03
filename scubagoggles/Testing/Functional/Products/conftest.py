"""Fixtures for the product test plan cases run by test_products.py."""

import pytest

from scubagoggles.Testing.Functional.Products.framework.cached_runner import (
    CachedRunner, collect_export, load_export,
)
from scubagoggles.Testing.Functional.Products.framework.plan_model import PolicyCase, TestDriver


def selected_cases(items) -> list[PolicyCase]:
    """Plan cases still selected after -k/-m, whatever the parameter is called."""
    return [value for item in items if hasattr(item, 'callspec')
            for value in item.callspec.params.values() if isinstance(value, PolicyCase)]


def gws_cli_args(config, *options: str) -> list[str]:
    """Forward the given options, when set, to `scubagoggles gws`.  Unset
    options fall back to the CLI's own defaults (e.g. `scubagoggles setup`)."""
    args = []
    for option in options:
        value = config.getoption(option)
        if value is not None:
            args += [option, str(value)]
    return args


@pytest.fixture(scope='session', name='provider_export')
def provider_export_fixture(pytestconfig, tmp_path_factory, request):
    """Load or collect exactly one source export for all selected cached cases."""
    path = pytestconfig.getoption('--cached-export')
    if path:
        return load_export(path)
    if not pytestconfig.getoption('--cached-collect'):
        pytest.skip('Pass --cached-export or --cached-collect to run cached cases.')

    products = sorted({case.product for case in selected_cases(request.session.items)
                       if case.test_driver is TestDriver.CACHED})
    cli_args = gws_cli_args(pytestconfig, '--opapath', '--credentials',
                            '--subjectemail', '--customerid')
    return collect_export(tmp_path_factory.mktemp('cached-source'), products, cli_args)


@pytest.fixture(scope='session')
def cached_runner(provider_export, pytestconfig):
    """Share the source export; CachedRunner.run deep-copies it per case."""
    return CachedRunner(provider_export, gws_cli_args(pytestconfig, '--opapath'))


@pytest.fixture
def runner(case, request):
    """The runner for this case's test_driver, e.g. the cached_runner fixture."""
    return request.getfixturevalue(f'{case.test_driver}_runner')
