"""Unit tests for OSCAL baseline generation."""

import importlib.util
import json
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[4]
GENERATOR_PATH = REPO_ROOT / "scubagoggles" / "utils" / "generate_oscal_baselines.py"


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


class GenerateOscalBaselinesTest:
    """Tests for converting Markdown baselines to OSCAL component definitions."""

    def test_statement_level_mapping_helpers(self):
        """Statement-letter mappings should not become fake control IDs."""

        generator = load_generator()

        assert generator.normalize_control_id("IA-2(1)") == "ia-2.1"
        assert generator.statement_id("IA-2(1)", "ia-2.1") == "ia-2.1_smt"

        assert generator.normalize_control_id("IA-5c") == "ia-5"
        assert generator.statement_id("IA-5c", "ia-5") == "ia-5_smt.c"

        assert generator.normalize_control_id("SC-7(10)(a)") == "sc-7.10"
        assert generator.statement_id("SC-7(10)(a)", "sc-7.10") == "sc-7.10_smt.a"

        assert generator.normalize_control_id("SC-7(10)a") == "sc-7.10"
        assert generator.statement_id("SC-7(10)a", "sc-7.10") == "sc-7.10_smt.a"

    def test_generation_covers_readme_baselines(self, tmp_path):
        """Every README-listed baseline should produce valid OSCAL JSON."""

        generator = load_generator()
        input_dir = REPO_ROOT / "scubagoggles" / "baselines"
        output_dir = tmp_path / "oscal-baselines"

        summary = generator.generate_baselines(input_dir, output_dir, "0.0.0-test")
        discovered = generator.parse_baselines_readme(input_dir)

        assert len(summary) == len(discovered)
        assert (output_dir / "generation-summary.json").exists()

        for item in summary:
            source_path = input_dir / item["source"]
            output_path = output_dir / item["output"]
            doc = json.loads(output_path.read_text(encoding="utf-8"))
            component_definition = doc["component-definition"]
            requirements = component_definition["components"][0][
                "control-implementations"
            ][0]["implemented-requirements"]

            assert item["source_policies"] == source_policy_count(source_path)
            assert item["implemented_requirements"] == source_mapping_count(source_path)
            assert len(requirements) == item["implemented_requirements"]
            assert component_definition["metadata"]["oscal-version"] == "1.1.2"

            for requirement in requirements:
                mapping_props = [
                    prop
                    for prop in requirement["props"]
                    if prop["name"] == "source-control-mapping"
                ]
                policy_props = [
                    prop
                    for prop in requirement["props"]
                    if prop["name"] == "source-policy-id"
                ]
                assert requirement["control-id"] != "unknown"
                assert len(mapping_props) == 1
                assert len(policy_props) == 1
