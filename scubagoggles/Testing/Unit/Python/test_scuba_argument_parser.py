"""Unit tests for the ScubaArgumentParser class."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

import scubagoggles.scuba_argument_parser as scap
from scubagoggles.scuba_argument_parser import ScubaArgumentParser

# pylint: disable=too-few-public-methods
class NamespaceWithContains(argparse.Namespace):
    """argparse.Namespace with membership checks for ScubaArgumentParser."""

    credentials: str | Path | None = None
    documentpath: str | Path | None = None
    opapath: str | Path | None = None
    outputpath: str | Path | None = None
    regopath: str | Path | None = None
    OrgName: str | None = None
    OrgUnitName: str | None = None
    baselines: list[str] | None = None
    omitpolicy: list[str] | None = None
    annotatepolicy: list[str] | None = None
    imapexclusions: list[dict] | None = None
    sitesexclusions: list[dict] | None = None

    def __contains__(self, item: object) -> bool:
        """Return True when the namespace has the requested attribute."""
        return hasattr(self, str(item))

# pylint: disable=too-few-public-methods
class FakeParser:
    """Small parser stub used to drive ScubaArgumentParser.parse_args()."""

    def __init__(self, parsed_args: argparse.Namespace) -> None:
        """Store the parsed args and initialize the call counter."""
        self.parsed_args = parsed_args
        self.parse_args_calls = 0

    def parse_args(self) -> argparse.Namespace:
        """Return the stored namespace and count how many times it was used."""
        self.parse_args_calls += 1
        return self.parsed_args

# pylint: disable=too-few-public-methods
class FakeMarkdownParser:
    """Stub Markdown parser used by validate_omissions/annotations tests."""

    def __init__(self, baseline_policies: dict[str, list[dict]]) -> None:
        """Store the baseline policies for later lookup."""
        self._baseline_policies = baseline_policies

    def parse_baselines(self, md_products: set[str]) -> dict[str, list[dict]]:
        """Return only the requested baseline policies."""
        return {
            product: groups
            for product, groups in self._baseline_policies.items()
            if product in md_products
        }


class TestScubaArgumentParser:
    """Unit tests for ScubaArgumentParser."""

    def test_parse_args(self) -> None:
        """Verify parse_args returns the parser's namespace unchanged."""
        expected = argparse.Namespace(alpha="beta")
        parser = ScubaArgumentParser(FakeParser(expected))

        result = parser.parse_args()

        assert result is expected

    def test_parse_args_with_config(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,) -> None:
        """Verify config values merge with CLI overrides as expected."""
        monkeypatch.chdir(tmp_path)

        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "\n".join(
                [
                    "baselines:",
                    "  - config-baseline",
                    "outputpath: config-output",
                    "credentials: config-creds.json",
                ]
            ),
            encoding="utf-8",
        )

        args = NamespaceWithContains(
            log="INFO",
            outputlog=None,
            config=str(config_file),
            baselines=["cli-baseline"],
            outputpath=None,
            credentials="cli-creds.json",
            breakglassaccounts=None,
            imapexclusions=None,
            sitesexclusions=None,
            documentpath=None,
            opapath=None,
            regopath=None,
            omitpolicy=None,
            annotatepolicy=None,
            orgname=None,
            orgunitname=None,
        )

        parser = ScubaArgumentParser(FakeParser(args))

        monkeypatch.setattr(ScubaArgumentParser, "_start_logging", lambda *_: None)
        monkeypatch.setattr(
            ScubaArgumentParser,
            "_get_explicit_cli_args",
            classmethod(lambda _cls, _args: {"baselines", "credentials"}),
        )
        monkeypatch.setattr(ScubaArgumentParser, "validate_omissions", lambda *_: None)
        monkeypatch.setattr(ScubaArgumentParser, "validate_annotations", lambda *_: None)
        monkeypatch.setattr(ScubaArgumentParser, "validate_imap_exclusions", lambda *_: None)
        monkeypatch.setattr(ScubaArgumentParser, "validate_sites_exclusions", lambda *_: None)

        result = parser.parse_args_with_config()

        assert result.baselines == ["cli-baseline"]
        assert result.credentials.name == "cli-creds.json"
        assert result.outputpath.name == "config-output"

    def test__get_explicit_cli_args(self, monkeypatch: pytest.MonkeyPatch, ) -> None:
        """Verify explicit CLI arguments are detected correctly."""
        created_parsers: list["FakeArgumentParser"] = []

        class FakeArgumentParser:
            """Stub argparse.ArgumentParser used by the helper test."""

            def __init__(self, argument_default: object = None) -> None:
                """Store the default and record the created parser."""
                self.argument_default = argument_default
                self.added_arguments: list[tuple[tuple[str, ...], dict[str, object]]] = []
                created_parsers.append(self)

            def add_argument(self, *dests: str, **kwargs: object) -> None:
                """Record every added argument."""
                self.added_arguments.append((dests, kwargs))

            def parse_known_args(self) -> tuple[argparse.Namespace, list[str]]:
                """Return a namespace that marks a couple of arguments as explicit."""
                return argparse.Namespace(baselines="from-cli", verbose=False), []

        monkeypatch.setattr(scap.argparse, "ArgumentParser", FakeArgumentParser)

        args = NamespaceWithContains(
            baselines="from-cli",
            outputpath="from-cli-output",
            credentials="from-cli-creds",
            verbose=True,
            retries=3,
        )

        result = ScubaArgumentParser._get_explicit_cli_args(args)  # pylint: disable=protected-access

        assert result.baselines == "from-cli"
        assert result.verbose is False

        assert len(created_parsers) == 1
        added = created_parsers[0].added_arguments

        assert (("--baselines", "-b"), {}) in added
        assert (("--outputpath", "-o"), {}) in added
        assert (("--credentials", "-c"), {}) in added
        assert (("--verbose",), {"action": "store_false"}) in added
        assert (("--retries",), {}) in added

    def test_validate_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify validation converts paths and normalizes org fields."""
        args = NamespaceWithContains(
            credentials="creds.json",
            documentpath="docs/baselines",
            opapath="bin/opa",
            outputpath="reports/out",
            regopath="rego/policies",
            omitpolicy=["GWS.TEST.1"],
            annotatepolicy=["GWS.TEST.2"],
            imapexclusions=[
                {"ou": "OU-1", "group": "", "justification": "imap"},
            ],
            sitesexclusions=[
                {"ou": "", "group": "GROUP-1", "justification": "sites"},
            ],
            orgname="example org",
            orgunitname="example unit",
        )

        converted: list[Path] = []

        def fake_path_parser(value: str) -> Path:
            """Record path conversion input and return a predictable path."""
            converted.append(Path(value))
            return Path(f"/converted/{Path(value).name}")

        validator_calls: list[str] = []

        monkeypatch.setattr(scap, "path_parser", fake_path_parser)
        monkeypatch.setattr(
            ScubaArgumentParser,
            "validate_omissions",
            lambda _args: validator_calls.append("omissions"),
        )
        monkeypatch.setattr(
            ScubaArgumentParser,
            "validate_annotations",
            lambda _args: validator_calls.append("annotations"),
        )
        monkeypatch.setattr(
            ScubaArgumentParser,
            "validate_imap_exclusions",
            lambda _args: validator_calls.append("imap"),
        )
        monkeypatch.setattr(
            ScubaArgumentParser,
            "validate_sites_exclusions",
            lambda _args: validator_calls.append("sites"),
        )

        ScubaArgumentParser.validate_config(args)

        assert args.credentials == Path("/converted/creds.json")
        assert args.documentpath == Path("/converted/baselines")
        assert args.opapath == Path("/converted/opa")
        assert args.outputpath == Path("/converted/out")
        assert args.regopath == Path("/converted/policies")

        assert args.OrgName == "example org"
        assert args.OrgUnitName == "example unit"
        assert not hasattr(args, "orgname")
        assert not hasattr(args, "orgunitname")

        assert validator_calls == ["omissions", "annotations", "imap", "sites"]
        assert converted == [
            Path("creds.json"),
            Path("docs/baselines"),
            Path("bin/opa"),
            Path("reports/out"),
            Path("rego/policies"),
        ]

    def test_validate_omissions(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify invalid omissions generate a warning."""
        warnings: list[str] = []
        baseline_policies = {
            "gmail": [
                {
                    "Controls": [
                        {"Id": "GMAIL.1"},
                        {"Id": "GMAIL.2"},
                    ]
                }
            ]
        }

        monkeypatch.setattr(
            scap,
            "MarkdownParser",
            lambda _documentpath: FakeMarkdownParser(baseline_policies),
        )
        monkeypatch.setattr(
            scap.log,
            "warning",
            lambda message, *args: warnings.append(message % args),
        )

        args = NamespaceWithContains(
            baselines=["gmail"],
            documentpath=Path("docs"),
            omitpolicy=["gmail.1", "gmail.9"],
        )

        ScubaArgumentParser.validate_omissions(args)

        assert len(warnings) == 1
        assert "gmail.9" in warnings[0]

    def test_validate_annotations(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify invalid annotations generate a warning."""
        warnings: list[str] = []
        baseline_policies = {
            "groups": [
                {
                    "Controls": [
                        {"Id": "GROUPS.10"},
                        {"Id": "GROUPS.11"},
                    ]
                }
            ]
        }

        monkeypatch.setattr(
            scap,
            "MarkdownParser",
            lambda _documentpath: FakeMarkdownParser(baseline_policies),
        )
        monkeypatch.setattr(
            scap.log,
            "warning",
            lambda message, *args: warnings.append(message % args),
        )

        args = NamespaceWithContains(
            baselines=["groups"],
            documentpath=Path("docs"),
            annotatepolicy=["groups.10", "groups.99"],
        )

        ScubaArgumentParser.validate_annotations(args)

        assert len(warnings) == 1
        assert "groups.99" in warnings[0]
