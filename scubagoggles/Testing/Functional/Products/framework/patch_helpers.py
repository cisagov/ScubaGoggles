"""Functions that edit a provider export for cached cases.

set_setting applies a case's "settings".  Functions decorated with
@patch_helper can be named in a case's "patch" list; they handle data that
isn't a Policy API setting (log events, DNS records, directory data, failed
API calls).  Each receives the export followed by the case's args and edits
the export in place.
"""

from collections.abc import Callable
from copy import deepcopy

PATCH_HELPERS: dict[str, Callable[..., None]] = {}


def patch_helper(func: Callable[..., None]) -> Callable[..., None]:
    """Register func so test plans can name it in a case's patch list."""
    PATCH_HELPERS[func.__name__] = func
    return func


def set_setting(data: dict, key: str, value):
    """Set setting_type.fieldName the way the tenant would report it.

    The value goes on the top-level OU, which every other OU inherits from,
    and on any OU or group that already overrides that setting type.  Views
    that inherit are left alone, so the export stays one the tenant could
    produce.  Only this key's missing/invalid marker is cleared.
    """
    setting, field_name = key.split('.')
    top_ou = data['tenant_info']['topLevelOU']
    if top_ou not in data['policies']:
        raise ValueError(f'The export has no policies for the top-level OU {top_ou!r}.')
    for view, settings in data['policies'].items():
        if view == top_ou or setting in settings:
            settings.setdefault(setting, {})[field_name] = deepcopy(value)
    data['missing_policies'] = [item for item in data['missing_policies'] if item != key]


@patch_helper
def missing_setting(data: dict, setting: str):
    """Make setting_type.fieldName look missing or invalid, as the provider
    reports it when the Policy API omits the field for the top-level OU."""
    section, field_name = setting.split('.')
    top_ou = data['tenant_info']['topLevelOU']
    data['policies'].get(top_ou, {}).get(section, {}).pop(field_name, None)
    if setting not in data['missing_policies']:
        data['missing_policies'].append(setting)
