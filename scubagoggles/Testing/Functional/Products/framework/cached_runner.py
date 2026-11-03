"""The cached test driver: patch a private copy of one provider export per
case, then run `scubagoggles gws --runcached --skipexport` on it."""

from copy import deepcopy
import json
from pathlib import Path

from scubagoggles.Testing.Functional.Products.framework.patch_helpers import (
    PATCH_HELPERS, set_setting,
)
from scubagoggles.Testing.Functional.Products.framework.plan_model import PolicyCase
from scubagoggles.Testing.Functional.Products.framework.scuba_app import (
    PROVIDER_FILE_NAME, PolicyResult, baseline_versions, find_results_file,
    read_policy_result, run_scubagoggles,
)


def load_export(path: Path) -> dict:
    """Read a provider export or the Raw section of a ScubaResults file."""
    with path.open(encoding='utf-8') as stream:
        data = json.load(stream)
    if isinstance(data, dict) and 'Raw' in data:
        data = data['Raw']
    if not isinstance(data, dict):
        raise ValueError('The provider export must be a JSON object.')
    required = {
        'policies': dict,
        'tenant_info': dict,
        'successful_calls': list,
        'unsuccessful_calls': list,
        'missing_policies': list,
        'report_uuid': str,
    }
    for key, kind in required.items():
        if not isinstance(data.get(key), kind):
            raise ValueError(f'Provider export requires {key} ({kind.__name__}).')
    if not data['tenant_info'].get('topLevelOU'):
        raise ValueError('Provider export requires tenant_info.topLevelOU.')
    return data


def collect_export(output_dir: Path, products: list[str], cli_args: list[str]) -> dict:
    """Run a normal `scubagoggles gws` once and return the export it made."""
    run_scubagoggles('--baselines', *products, '--outputpath', str(output_dir), *cli_args)
    return load_export(find_results_file(output_dir))


def apply_case(data: dict, case: PolicyCase):
    """Apply the case's settings, then its patches, to an export in place."""
    for key, value in case.settings.items():
        set_setting(data, key, value)
    for patch in case.patches:
        PATCH_HELPERS[patch.helper](data, **patch.args)


# One run method is the intended public interface.
# pylint: disable-next=too-few-public-methods
class CachedRunner:
    """Run cached cases against a private copy of one provider export."""

    def __init__(self, provider_export: dict, cli_args: list[str] | None = None):
        """:param cli_args: extra `scubagoggles gws` arguments, e.g. --opapath."""
        self._source = deepcopy(provider_export)
        self._cli_args = list(cli_args or [])

    def run(self, case: PolicyCase, output_dir: Path) -> PolicyResult:
        """Patch a copy of the export, run ScubaGoggles, read the report row."""
        data = deepcopy(self._source)
        apply_case(data, case)
        # Bind replayed exports to this checkout's baseline versions.
        data['baseline_suffix'], data['baseline_versions'] = baseline_versions(case.product)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / f'{PROVIDER_FILE_NAME}.json').write_text(json.dumps(data),
                                                              encoding='utf-8')
        run_scubagoggles('--baselines', case.product, '--outputpath', str(output_dir),
                         '--runcached', '--skipexport', *self._cli_args)
        return read_policy_result(output_dir, case)
