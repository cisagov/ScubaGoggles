"""Run every test plan case for the selected --test-driver.

Cases are data in TestPlans/<product>.yaml; this module should not need to
change when cases are added.
"""

from pathlib import Path

from scubagoggles.Testing.Functional.Products.framework.plan_loader import load_plans

TEST_PLANS_DIR = Path(__file__).parent / 'TestPlans'


def pytest_generate_tests(metafunc):
    """Create one test per plan case whose test_driver matches --test-driver."""
    if 'case' not in metafunc.fixturenames:
        return
    driver = metafunc.config.getoption('--test-driver')
    cases = [case for plan in load_plans(TEST_PLANS_DIR) for case in plan.cases
             if case.test_driver == driver]
    metafunc.parametrize('case', cases, ids=[case.test_id for case in cases])


def test_policy(case, runner, tmp_path):
    """Assert the report result for one plan case."""
    runner.run(case, tmp_path).assert_expected(case)
