"""The test plan vocabulary shared by the loader and the runners.

A product's test plan (Products/TestPlans/<product>.yaml) has one PolicyPlan
per baseline policy: its live configuration and its PolicyCases.  See
Testing/Functional/README.md for the YAML format.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TypeAlias


# Values written into provider JSON, including nested settings and patch data.
JsonValue: TypeAlias = (
    str | int | float | bool | None | list['JsonValue'] | dict[str, 'JsonValue']
)


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


class WriteApi(StrEnum):
    """API used to change settings for a live case."""

    POLICY_API = 'policy_api'
    DIRECTORY_API = 'directory_api'
    CLOUD_IDENTITY_API = 'cloud_identity_api'
    GROUP_SETTINGS_API = 'group_settings_api'


class Scope(StrEnum):
    """The concrete target scope of a live case."""

    OU = 'ou'
    GROUP = 'group'
    TENANT = 'tenant'


class PlanError(ValueError):
    """A test plan is malformed; the message lists every problem found."""


@dataclass(frozen=True)
class LiveDefaults:
    """Optional shared live settings, also used for partial case overrides."""

    write_api: tuple[WriteApi, ...] | None = None
    scope: Scope | None = None


@dataclass(frozen=True)
class LiveConfig:
    """A live case's complete configuration after resolving defaults."""

    write_api: tuple[WriteApi, ...]
    scope: Scope


@dataclass(frozen=True)
class Patch:
    """One named patch helper call from a case."""

    helper: str
    args: Mapping[str, JsonValue] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyCase:
    """One scenario from a test plan."""

    policy_id: str
    product: str
    name: str
    test_driver: TestDriver
    expected_result: Outcome
    settings: Mapping[str, JsonValue] = field(default_factory=dict)
    patches: tuple[Patch, ...] = ()
    description: str = ''
    live: LiveConfig | None = None

    @property
    def test_id(self) -> str:
        """Identify the policy, driver and descriptive scenario name in pytest."""
        return f'{self.policy_id}-{self.test_driver}-{self.name}'


@dataclass(frozen=True)
class PolicyPlan:
    """One policy's live configuration and cases."""

    policy_id: str
    product: str
    live_testing: bool
    cases: tuple[PolicyCase, ...]
    live: LiveDefaults | None = None
