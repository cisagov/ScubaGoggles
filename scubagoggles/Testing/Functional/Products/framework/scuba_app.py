"""Run ScubaGoggles the way `scubagoggles gws` does, for the test runners.

Runners go through the real argument parser and Orchestrator, so functional
tests exercise the same export, Rego, and report code that users run.  This
module only adds what tests need around them: skipping the release check,
finding the results file, and reading one policy's report row.
"""

from dataclasses import dataclass
from functools import cache
import json
from pathlib import Path
import re

import scubagoggles
from scubagoggles.main import create_parser
from scubagoggles.orchestrator import Orchestrator
from scubagoggles.reporter.md_parser import MarkdownParser
from scubagoggles.scuba_argument_parser import ScubaArgumentParser
from scubagoggles.Testing.Functional.Products.framework.plan_model import PolicyCase

PACKAGE_DIR = Path(scubagoggles.__file__).parent
PROVIDER_FILE_NAME = 'ProviderSettingsExport'
RESULTS_FILE_NAME = 'ScubaResults'
_VERSION_SUFFIX_RE = re.compile(r'v[\d.]+$')


class FunctionalTestOrchestrator(Orchestrator):
    """The real Orchestrator without the PyPI release check, which would
    otherwise run once per case and needs network access."""

    def notify_user_if_new_release_is_available(self):
        """Skip the release check."""


def run_scubagoggles(*argv: str):
    """Run `scubagoggles gws <argv>` in-process, without opening a browser."""
    parser = ScubaArgumentParser(create_parser())
    args = parser.parse_args_with_config(
        ['gws', *argv, '--quiet', '--silencebodwarnings',
         '--outputproviderfilename', PROVIDER_FILE_NAME,
         '--outjsonfilename', RESULTS_FILE_NAME])
    FunctionalTestOrchestrator(args).start_automation()


def find_results_file(output_dir: Path) -> Path:
    """The single ScubaResults JSON file a run wrote under output_dir."""
    files = list(output_dir.rglob(f'{RESULTS_FILE_NAME}*.json'))
    if len(files) != 1:
        raise RuntimeError(f'Expected one {RESULTS_FILE_NAME} file under {output_dir}, '
                           f'found {len(files)}.')
    return files[0]


@dataclass(frozen=True)
class PolicyResult:
    """User-facing result and the report to inspect when an assertion fails."""

    policy_id: str
    outcome: str
    details: str
    report_path: Path

    def assert_expected(self, case: PolicyCase):
        """Assert the report result, including useful failure diagnostics."""
        assert self.outcome == case.expected_result, (
            f'{case.test_id}: expected {case.expected_result}, '
            f'got {self.outcome}. {self.details} Report: {self.report_path}'
        )


def read_policy_result(output_dir: Path, case: PolicyCase) -> PolicyResult:
    """Read the case's policy row from the run's ScubaResults file."""
    results_file = find_results_file(output_dir)
    results = json.loads(results_file.read_text(encoding='utf-8'))
    rows = [row for group in results['Results'][case.product] for row in group['Controls']
            if unversioned(row['Control ID']) == case.policy_id]
    if len(rows) != 1:
        raise RuntimeError(f'Expected one report row for {case.policy_id}, got {len(rows)}.')
    row = rows[0]
    return PolicyResult(
        policy_id=row['Control ID'], outcome=row['Result'], details=row['Details'],
        report_path=(results_file.parent / 'IndividualReports'
                     / f'{case.product.capitalize()}Report.html'),
    )


def unversioned(policy_id: str) -> str:
    """GWS.COMMONCONTROLS.4.1v1 -> GWS.COMMONCONTROLS.4.1"""
    return _VERSION_SUFFIX_RE.sub('', policy_id)


@cache
def _baseline(product: str) -> tuple[list, str, dict]:
    """Baseline groups, default version suffix, and per-policy versions."""
    parser = MarkdownParser(PACKAGE_DIR / 'baselines')
    groups = parser.parse_baselines({product})[product]
    return groups, parser.default_version, parser.policy_version_map


def baseline_policy_ids(product: str) -> set[str]:
    """Unversioned policy IDs in this checkout's baseline for product."""
    groups, _, _ = _baseline(product)
    return {unversioned(control['Id']) for group in groups for control in group['Controls']}


def baseline_versions(product: str) -> tuple[str, dict]:
    """This checkout's default version suffix and per-policy versions."""
    _, suffix, versions = _baseline(product)
    return suffix, versions
