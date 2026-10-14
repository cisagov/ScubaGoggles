"""Validate generated SCuBA OSCAL baseline catalog outputs."""

# pylint: disable=wrong-import-position

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import TypeAlias

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scubagoggles import __version__ as SCUBAGOGGLES_VERSION
from scubagoggles.scuba_constants import DEFAULT_OSCAL_VERSION


JsonValue: TypeAlias = (
    str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
)
JsonObject: TypeAlias = dict[str, JsonValue]

DEVELOPMENT_VERSION_LABEL = "development build"
SUMMARY_FILE = "generation-summary.json"


def version_filename_fragment(version: str) -> str:
    """Return a safe version fragment for generated filenames."""

    fragment = re.sub(r"[^a-z0-9.-]+", "-", version.strip().lower()).strip("-")
    if fragment.startswith("v"):
        fragment = fragment[1:]
    return fragment or "unversioned"


def expected_catalog_file_name(release_version: str | None = None) -> str:
    """Return the expected generated OSCAL catalog filename."""

    if release_version:
        source_version = version_filename_fragment(release_version)
        return (
            f"scubagoggles-v{source_version}-oscal-catalog-"
            f"oscal-{DEFAULT_OSCAL_VERSION}.json"
        )
    return f"scubagoggles-oscal-catalog-oscal-{DEFAULT_OSCAL_VERSION}.json"


def expected_metadata_version(release_version: str | None = None) -> str:
    """Return the expected OSCAL metadata version."""

    if release_version:
        return release_version
    return f"{SCUBAGOGGLES_VERSION} ({DEVELOPMENT_VERSION_LABEL})"


def read_json_object(path: Path) -> JsonObject:
    """Read a JSON file and require its top-level value to be an object."""

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def require_json_object(value: JsonValue | None, label: str) -> JsonObject:
    """Require a JSON value to be an object."""

    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def require_string(value: JsonValue | None, label: str) -> str:
    """Require a JSON value to be a string."""

    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    return value


def validate_catalog_output(
    output_dir: Path,
    release_version: str | None = None,
) -> Path:
    """Validate generated catalog summary and metadata, returning catalog path."""

    summary_path = output_dir / SUMMARY_FILE
    if not summary_path.exists():
        raise FileNotFoundError(f"Missing OSCAL generation summary: {summary_path}")

    summary = read_json_object(summary_path)
    output_name = require_string(summary.get("output"), "summary.output")
    expected_output_name = expected_catalog_file_name(release_version)
    if output_name != expected_output_name:
        raise ValueError(
            f"Expected generated catalog {expected_output_name}, got {output_name}"
        )

    catalog_path = output_dir / output_name
    if not catalog_path.exists():
        raise FileNotFoundError(f"Missing generated OSCAL catalog: {catalog_path}")

    catalog_json = read_json_object(catalog_path)
    catalog = require_json_object(catalog_json.get("catalog"), "catalog")
    metadata = require_json_object(catalog.get("metadata"), "catalog.metadata")

    oscal_version = require_string(
        metadata.get("oscal-version"),
        "catalog.metadata.oscal-version",
    )
    if oscal_version != DEFAULT_OSCAL_VERSION:
        raise ValueError(
            f"Generated OSCAL catalog uses OSCAL {oscal_version}; "
            f"expected {DEFAULT_OSCAL_VERSION}"
        )

    metadata_version = require_string(
        metadata.get("version"),
        "catalog.metadata.version",
    )
    expected_version = expected_metadata_version(release_version)
    if metadata_version != expected_version:
        raise ValueError(
            f"Generated OSCAL catalog metadata.version is {metadata_version}; "
            f"expected {expected_version}"
        )

    return catalog_path


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description="Validate a generated SCuBA OSCAL baseline catalog."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "dist" / "oscal-baseline-catalog",
        help="Directory containing generated OSCAL catalog files.",
    )
    parser.add_argument(
        "--release-version",
        default=None,
        help="Release version expected in the generated OSCAL catalog.",
    )
    parser.add_argument(
        "--print-catalog-path",
        action="store_true",
        help="Print only the validated catalog path.",
    )
    return parser.parse_args()


def main() -> None:
    """Run the validator."""

    args = parse_args()
    catalog_path = validate_catalog_output(args.output_dir, args.release_version)
    if args.print_catalog_path:
        print(catalog_path)
    else:
        print(f"Validated OSCAL catalog JSON: {catalog_path}")


if __name__ == "__main__":
    main()
