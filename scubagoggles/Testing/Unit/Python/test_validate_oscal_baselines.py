"""Unit tests for generated OSCAL baseline catalog validation."""

import importlib.util
import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[4]
GENERATOR_PATH = REPO_ROOT / "scubagoggles" / "utils" / "generate_oscal_baselines.py"
VALIDATOR_PATH = REPO_ROOT / "scubagoggles" / "utils" / "validate_oscal_baselines.py"


def load_module(path, name):
    """Load a module by path."""

    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_validate_release_catalog_output(tmp_path):
    """Release catalog output should pass validation."""

    generator = load_module(GENERATOR_PATH, "generate_oscal_baselines")
    validator = load_module(VALIDATOR_PATH, "validate_oscal_baselines")
    output_dir = tmp_path / "oscal-baseline-catalog"

    generator.generate_baselines(
        REPO_ROOT / "scubagoggles" / "baselines",
        output_dir,
        "1.0.0",
    )

    catalog_path = validator.validate_catalog_output(output_dir, "1.0.0")

    assert catalog_path.name == validator.expected_catalog_file_name("1.0.0")


def test_validate_ad_hoc_catalog_output(tmp_path):
    """Ad hoc catalog output should pass validation."""

    generator = load_module(GENERATOR_PATH, "generate_oscal_baselines")
    validator = load_module(VALIDATOR_PATH, "validate_oscal_baselines")
    output_dir = tmp_path / "oscal-baseline-catalog"

    generator.generate_baselines(
        REPO_ROOT / "scubagoggles" / "baselines",
        output_dir,
    )

    catalog_path = validator.validate_catalog_output(output_dir)

    assert catalog_path.name == validator.expected_catalog_file_name()


def test_validate_catalog_output_rejects_unexpected_filename(tmp_path):
    """Validation should fail when the summary points to the wrong filename."""

    validator = load_module(VALIDATOR_PATH, "validate_oscal_baselines")
    output_dir = tmp_path / "oscal-baseline-catalog"
    output_dir.mkdir()
    (output_dir / "unexpected.json").write_text(
        json.dumps(
            {
                "catalog": {
                    "metadata": {
                        "oscal-version": validator.DEFAULT_OSCAL_VERSION,
                        "version": validator.expected_metadata_version(),
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (output_dir / "generation-summary.json").write_text(
        json.dumps({"output": "unexpected.json"}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Expected generated catalog"):
        validator.validate_catalog_output(output_dir)
