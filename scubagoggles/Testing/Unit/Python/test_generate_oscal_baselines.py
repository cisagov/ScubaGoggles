"""Unit tests for OSCAL baseline catalog generation."""

import importlib.util
import json
import re
from pathlib import Path

from scubagoggles.scuba_constants import DEFAULT_OSCAL_VERSION


REPO_ROOT = Path(__file__).resolve().parents[4]
GENERATOR_PATH = REPO_ROOT / "scubagoggles" / "utils" / "generate_oscal_baselines.py"
OSCAL_GROUP_PART_NAMES = {"instruction", "overview"}
OSCAL_CONTROL_PART_NAMES = {
    "assessment",
    "assessment-method",
    "assessment-objective",
    "example",
    "guidance",
    "objective",
    "overview",
    "statement",
}


def load_generator():
    """Load the OSCAL generator module by path."""

    spec = importlib.util.spec_from_file_location("generate_oscal_baselines", GENERATOR_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {GENERATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_policy_count(path):
    """Return the number of unique SCuBA policy IDs in a Markdown file."""

    text = path.read_text(encoding="utf-8")
    ids = re.findall(
        r"^#### (GWS\.[A-Z]+(?:CONTROLS)?\.\d+\.\d+v\d+)\s*$",
        text,
        re.M,
    )
    return len(ids)


def source_mapping_count(path):
    """Return the total count of source NIST mapping entries."""

    text = path.read_text(encoding="utf-8")
    mapping_lines = re.findall(
        r"NIST SP 800-53 Rev\. 5 FedRAMP High Baseline Mapping:_\s*([^\r\n]+)",
        text,
    )
    return sum(len(line.split(",")) for line in mapping_lines)


def catalog_controls(catalog):
    """Yield every control from the generated catalog."""

    for baseline_group in catalog["groups"]:
        for section_group in baseline_group.get("groups", []):
            yield from section_group.get("controls", [])


def prop_values(props, name):
    """Return all values for a property name."""

    return [prop["value"] for prop in props if prop["name"] == name]


def assert_prop_order(props):
    """Assert generated properties read as name, value, then namespace."""

    for prop in props:
        assert list(prop) == ["name", "value", "ns"]


def iter_prose(value):
    """Yield every prose string from a generated OSCAL object."""

    if isinstance(value, dict):
        if "prose" in value:
            yield value["prose"]
        for child in value.values():
            yield from iter_prose(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_prose(child)


def part_values(parts, name, title=None):
    """Return all prose values for a part name."""

    return [
        part["prose"]
        for part in parts
        if part["name"] == name and (title is None or part.get("title") == title)
    ]


class GenerateOscalBaselinesTest:
    """Tests for converting Markdown baselines to one OSCAL catalog."""

    def test_policy_ids_become_catalog_control_ids(self):
        """SCuBA policy IDs should become stable catalog control IDs."""

        generator = load_generator()

        assert (
            generator.control_id_from_policy("GWS.COMMONCONTROLS.1.1v1")
            == "gws.commoncontrols.1.1v1"
        )

    def test_catalog_filename_includes_relevant_versions(self):
        """Release catalog filenames should show source and OSCAL versions."""

        generator = load_generator()
        expected_default = (
            f"scubagoggles-oscal-catalog-oscal-{generator.DEFAULT_OSCAL_VERSION}.json"
        )
        expected_release = (
            f"scubagoggles-v1.0.0-oscal-catalog-oscal-"
            f"{generator.DEFAULT_OSCAL_VERSION}.json"
        )

        assert generator.catalog_file_name() == expected_default
        assert generator.catalog_file_name("1.0.0") == expected_release
        assert generator.catalog_file_name("v1.0.0") == expected_release

    def test_catalog_metadata_version_marks_ad_hoc_runs(self):
        """Ad hoc catalog metadata should distinguish non-release generation."""

        generator = load_generator()

        assert generator.catalog_metadata_version("1.0.0") == "1.0.0"
        assert generator.catalog_metadata_version() == (
            f"{generator.SCUBAGOGGLES_VERSION} "
            f"({generator.DEVELOPMENT_VERSION_LABEL})"
        )

    def test_clean_text_resolves_relative_links_in_prose(self):
        """Relative Markdown links copied into OSCAL prose should be portable."""

        generator = load_generator()

        prose = generator.clean_text(
            (
                "See [Limitations](../../docs/usage/Limitations.md"
                "#log-based-policy-checks) and [this section](#key-terminology)."
            ),
            "assuredcontrols.md",
        )

        assert (
            "Limitations "
            "(https://github.com/cisagov/ScubaGoggles/blob/main/"
            "docs/usage/Limitations.md#log-based-policy-checks)"
        ) in prose
        assert (
            "this section "
            "(https://github.com/cisagov/ScubaGoggles/blob/main/"
            "scubagoggles/baselines/assuredcontrols.md#key-terminology)"
        ) in prose

    def test_generation_covers_readme_baselines(self, tmp_path):
        """Every README-listed baseline should be represented in one catalog."""

        generator = load_generator()
        input_dir = REPO_ROOT / "scubagoggles" / "baselines"
        output_dir = tmp_path / "oscal-baseline-catalog"
        release_version = "0.0.0-test"
        expected_catalog_file = generator.catalog_file_name(release_version)

        summary = generator.generate_baselines(input_dir, output_dir, release_version)
        discovered = generator.parse_baselines_readme(input_dir)
        catalog_path = output_dir / expected_catalog_file
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))["catalog"]
        controls = list(catalog_controls(catalog))

        assert generator.DEFAULT_OSCAL_VERSION == DEFAULT_OSCAL_VERSION
        assert summary["output"] == expected_catalog_file
        assert f"v{release_version}" in catalog_path.name
        assert generator.DEFAULT_OSCAL_VERSION in catalog_path.name
        assert summary["baselines"] == len(discovered)
        assert summary["source_policies"] == sum(
            source_policy_count(input_dir / file_name) for _, file_name in discovered
        )
        assert summary["source_mappings"] == sum(
            source_mapping_count(input_dir / file_name) for _, file_name in discovered
        )
        assert (output_dir / "generation-summary.json").exists()
        assert not list(output_dir.glob("*-oscal-component-definition.json"))

        assert catalog["metadata"]["oscal-version"] == generator.DEFAULT_OSCAL_VERSION
        assert catalog["metadata"]["version"] == release_version
        assert_prop_order(catalog["metadata"]["props"])
        assert len(catalog["groups"]) == len(discovered)
        assert len(controls) == summary["source_policies"]
        for prose in iter_prose(catalog):
            assert not any(
                marker in prose
                for marker in ("(../../", "(../", "(./", "(images/", "(#")
            )

        for baseline_group in catalog["groups"]:
            assert_prop_order(baseline_group["props"])
            assert all(
                part["name"] in OSCAL_GROUP_PART_NAMES
                for part in baseline_group.get("parts", [])
            )
            source_baseline = prop_values(baseline_group["props"], "source-baseline")[0]
            group_controls = [
                control
                for section_group in baseline_group.get("groups", [])
                for control in section_group.get("controls", [])
            ]
            assert len(group_controls) == source_policy_count(input_dir / source_baseline)
            for section_group in baseline_group.get("groups", []):
                assert_prop_order(section_group["props"])
                assert all(
                    part["name"] in OSCAL_GROUP_PART_NAMES
                    for part in section_group.get("parts", [])
                )

        assured_controls = next(
            group
            for group in catalog["groups"]
            if prop_values(group["props"], "source-baseline") == ["assuredcontrols.md"]
        )
        common_controls = next(
            group
            for group in catalog["groups"]
            if prop_values(group["props"], "source-baseline") == ["commoncontrols.md"]
        )
        mfa_section = next(
            section
            for section in common_controls["groups"]
            if prop_values(section["props"], "source-section") == ["1"]
        )
        assert "Assured Controls Plus add-on" in part_values(
            assured_controls["parts"],
            "overview",
            "Assumptions",
        )[0]
        assert 'The key words "MUST,"' in part_values(
            assured_controls["parts"],
            "overview",
            "Key Terminology",
        )[0]
        assert part_values(mfa_section["parts"], "overview")
        assert "FIDO2-compliant security keys" in part_values(
            mfa_section["parts"],
            "instruction",
            "Prerequisites",
        )[0]
        assert "Policy 1 Common Instructions" in part_values(
            mfa_section["parts"],
            "instruction",
            "Implementation",
        )[0]

        for control in controls:
            assert_prop_order(control["props"])
            policy_ids = prop_values(control["props"], "source-policy-id")
            mappings = prop_values(
                control["props"],
                "nist-sp800-53-rev5-fedramp-high-mapping",
            )
            assert len(policy_ids) == 1
            assert control["id"] == generator.control_id_from_policy(policy_ids[0])
            assert len(mappings) == 1
            assert any(part["name"] == "statement" for part in control["parts"])
            assert all(
                part["name"] in OSCAL_CONTROL_PART_NAMES
                for part in control.get("parts", [])
            )
            link_keys = [
                (link["rel"], link["href"]) for link in control.get("links", [])
            ]
            assert len(link_keys) == len(set(link_keys))
            assert not {
                "section-prerequisites",
                "source-note",
                "source-policy-detail",
                "source-section-overview",
            }.intersection(prop["name"] for prop in control["props"])

        phishing_resistant_mfa = next(
            control
            for control in controls
            if prop_values(control["props"], "source-policy-id")
            == ["GWS.COMMONCONTROLS.1.1v1"]
        )
        assert part_values(phishing_resistant_mfa["parts"], "statement") == [
            "Phishing-Resistant MFA SHALL be required for all users."
        ]
        statement_part = next(
            part
            for part in phishing_resistant_mfa["parts"]
            if part["name"] == "statement"
        )
        assert list(statement_part) == ["name", "id", "prose"]
        phishing_implementation = part_values(
            phishing_resistant_mfa["parts"],
            "guidance",
            "Implementation",
        )[0]
        implementation_part = next(
            part
            for part in phishing_resistant_mfa["parts"]
            if part["name"] == "guidance"
            and part.get("title") == "Implementation"
        )
        assert list(implementation_part) == ["name", "title", "id", "prose"]
        assert "Under Authentication" in phishing_implementation
        assert "Sign in to" not in phishing_implementation
        assert "FIDO2 Security Key" in part_values(
            phishing_resistant_mfa["parts"],
            "guidance",
            "Policy Detail",
        )[0]
