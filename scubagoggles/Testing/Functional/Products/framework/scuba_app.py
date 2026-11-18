"""Adapt ScubaGoggles execution and report output to product test cases.

run_scubagoggles accepts GWS command arguments and returns the directory written
by Orchestrator. It supplies noninteractive options and fixed JSON filename
prefixes, while allowing execution errors to propagate to pytest. The test
orchestrator disables the PyPI update check so cached replay needs no network.

Report helpers require exactly one ScubaResults file and one matching control
row. They preserve the reported outcome and attach an HTML report path to
assertion failures. Policy IDs are matched without their version suffixes.

Baseline helpers cache MarkdownParser output for plan validation and for
updating replayed exports to the policy versions in the current checkout.
"""

from dataclasses import dataclass
from functools import cache
from pathlib import Path

import scubagoggles
from scubagoggles.diff import load_report, split_version
from scubagoggles.main import create_parser
from scubagoggles.orchestrator import Orchestrator
from scubagoggles.reporter.md_parser import MarkdownParser
from scubagoggles.scuba_argument_parser import ScubaArgumentParser
from scubagoggles.Testing.Functional.Products.framework.plan_model import PolicyCase

PACKAGE_DIR = Path(scubagoggles.__file__).parent
PROVIDER_FILE_NAME = 'ProviderSettingsExport'
RESULTS_FILE_NAME = 'ScubaResults'

class FunctionalTestOrchestrator(Orchestrator):
    """The real Orchestrator without the PyPI release check, which would
    otherwise run once per case and needs network access."""

    def notify_user_if_new_release_is_available(self):
        """Skip the release check."""

def run_scubagoggles(*argv: str) -> Path:
    """Run `scubagoggles gws <argv>` quietly and return its report directory."""
    parser = ScubaArgumentParser(create_parser())
    args = parser.parse_args_with_config(
        ['gws', *argv, '--quiet', '--silencebodwarnings',
         '--outputproviderfilename', PROVIDER_FILE_NAME,
         '--outjsonfilename', RESULTS_FILE_NAME])
    FunctionalTestOrchestrator(args).start_automation()
    return args.outputpath

def find_results_file(output_dir: Path) -> Path:
    """The single ScubaResults JSON file in this run's report directory."""
    files = list(output_dir.glob(f'{RESULTS_FILE_NAME}*.json'))
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
    results = load_report(results_file)
    rows = [row for group in results['Results'][case.product] for row in group['Controls']
            if split_version(row['Control ID'])[0] == case.policy_id]
    if len(rows) != 1:
        raise RuntimeError(f'Expected one report row for {case.policy_id}, got {len(rows)}.')
    row = rows[0]
    return PolicyResult(
        policy_id=row['Control ID'], outcome=row['Result'], details=row['Details'],
        report_path=(results_file.parent / 'IndividualReports'
                     / f'{case.product.capitalize()}Report.html'),
    )

@cache
def _baseline(product: str) -> tuple[list, str, dict]:
    """Baseline groups, default version suffix, and per-policy versions."""
    parser = MarkdownParser(PACKAGE_DIR / 'baselines')
    groups = parser.parse_baselines({product})[product]
    return groups, parser.default_version, parser.policy_version_map

def baseline_policy_ids(product: str) -> set[str]:
    """Unversioned policy IDs in this checkout's baseline for product."""
    groups, _, _ = _baseline(product)
    return {split_version(control['Id'])[0] for group in groups for control in group['Controls']}

def baseline_versions(product: str) -> tuple[str, dict]:
    """This checkout's default version suffix and per-policy versions."""
    _, suffix, versions = _baseline(product)
    return suffix, versions
