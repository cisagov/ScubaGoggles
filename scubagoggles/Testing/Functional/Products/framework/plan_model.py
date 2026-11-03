"""The test plan vocabulary shared by the loader and the runners.

A product's test plan (Products/TestPlans/<product>.yaml) has one PolicyPlan
per baseline policy: its coverage decision and its PolicyCases.  See
Testing/Functional/README.md for the YAML format.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Outcome(StrEnum):
    """Result labels shown in the ScubaGoggles report."""

    PASS = 'Pass'
    FAIL = 'Fail'
    WARNING = 'Warning'
    NO_EVENTS = 'No events found'
    NOT_IMPLEMENTED = 'N/A'
    ERROR = 'Error'


class TestDriver(StrEnum):
    """How a case runs: against a patched export copy, or the live tenant."""

    __test__ = False  # Not a pytest test class, despite the name.

    CACHED = 'cached'
    LIVE = 'live'


class LiveTesting(StrEnum):
    """Team decision: whether this policy's settings may change in the tenant."""

    ALLOWED = 'allowed'
    DENIED = 'denied'


class WriteApi(StrEnum):
    """API that can change the policy's settings, if any."""

    NONE = 'none'
    UNKNOWN = 'unknown'
    POLICY_API = 'policy_api'
    DIRECTORY_API = 'directory_api'
    CLOUD_IDENTITY_API = 'cloud_identity_api'
    GROUP_SETTINGS_API = 'group_settings_api'


class Scope(StrEnum):
    """Where the policy's settings can be applied in the tenant."""

    OU_GROUP = 'ou_group'
    OU = 'ou'
    TENANT = 'tenant'
    UNKNOWN = 'unknown'


class PlanError(ValueError):
    """A test plan is malformed; the message lists every problem found."""


@dataclass(frozen=True)
class Patch:
    """One named patch helper call from a case."""

    helper: str
    args: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyCase:
    """One scenario from a test plan."""

    policy_id: str
    product: str
    name: str
    test_driver: TestDriver
    expected_result: Outcome
    settings: Mapping[str, Any] = field(default_factory=dict)
    patches: tuple[Patch, ...] = ()
    description: str = ''

    @property
    def test_id(self) -> str:
        """Pytest ID, e.g. GWS.COMMONCONTROLS.4.1-session_12h."""
        return f'{self.policy_id}-{self.name}'


@dataclass(frozen=True)
class PolicyPlan:
    """One policy's coverage decision and cases."""

    policy_id: str
    product: str
    live_testing: LiveTesting
    write_api: tuple[WriteApi, ...]
    scope: Scope
    cases: tuple[PolicyCase, ...]
    reason: str = ''
