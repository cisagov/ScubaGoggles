"""Generate one OSCAL catalog from SCuBA baseline Markdown.

The Markdown files in ``scubagoggles/baselines`` remain the source of truth.
This utility creates a machine-readable OSCAL ``catalog`` JSON file that
represents every README-listed SCuBA Google Workspace baseline together in the
OSCAL control layer.
"""

# pylint: disable=too-many-branches,too-many-lines,too-many-positional-arguments,wrong-import-position

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeAlias

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scubagoggles.scuba_constants import DEFAULT_OSCAL_VERSION


JsonValue: TypeAlias = (
    str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
)
JsonObject: TypeAlias = dict[str, JsonValue]

DEFAULT_CATALOG_FILE = (
    f"scubagoggles-oscal-catalog-oscal-{DEFAULT_OSCAL_VERSION}.json"
)
CATALOG_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL,
    "https://cisa.gov/scuba/google-workspace/catalog",
)
GITHUB_BROWSER_BASE = (
    "https://github.com/cisagov/ScubaGoggles/blob/main/scubagoggles/baselines"
)
GITHUB_RAW_BASE = (
    "https://raw.githubusercontent.com/cisagov/ScubaGoggles/main/scubagoggles/baselines"
)
OSCAL_CATALOG_REFERENCE = (
    "https://pages.nist.gov/OSCAL-Reference/models/"
    f"v{DEFAULT_OSCAL_VERSION}/catalog/json-reference/"
)
SCUBA_NS = "https://cisa.gov/scuba"

BASELINE_OVERRIDES = {
    "assuredcontrols.md": {
        "area": "Assured Controls",
        "service": "Google Workspace Assured Controls and Assured Controls Plus",
    },
    "commoncontrols.md": {
        "area": "Common Controls",
        "service": "Google Workspace Common Controls",
    },
    "drive.md": {
        "area": "Google Drive and Docs",
        "service": "Google Drive and Docs",
    },
}


def version_filename_fragment(version: str) -> str:
    """Return a safe version fragment for generated filenames."""

    fragment = re.sub(r"[^a-z0-9.-]+", "-", version.strip().lower()).strip("-")
    if fragment.startswith("v"):
        fragment = fragment[1:]
    return fragment or "unversioned"


def catalog_file_name(release_version: str | None = None) -> str:
    """Return the generated OSCAL catalog filename."""

    if release_version:
        source_version = version_filename_fragment(release_version)
        return (
            f"scubagoggles-v{source_version}-oscal-catalog-"
            f"oscal-{DEFAULT_OSCAL_VERSION}.json"
        )
    return DEFAULT_CATALOG_FILE


def stable_uuid(namespace: uuid.UUID, label: str) -> str:
    """Return a deterministic UUID for a generated OSCAL object."""

    return str(uuid.uuid5(namespace, label))


def clean_text(value: str) -> str:
    """Convert Markdown-heavy snippets into compact OSCAL prose."""

    if not value:
        return ""
    value = value.replace("\r\n", "\n")
    value = value.replace("\u201c", '"').replace("\u201d", '"').replace("\u2019", "'")
    value = re.sub(r"\[!\[[^\]]+\]\([^)]+\)\]\([^)]+\)", "", value)
    value = re.sub(r"!\[([^\]]*)\]\([^)]+\)", r"\1", value)
    value = re.sub(r"<img[^>]*>", "", value)
    value = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", value)
    value = value.replace("**", "").replace("_", "")
    value = re.sub(r"^[ \t]*[-*][ \t]+", "", value, flags=re.MULTILINE)
    value = re.sub(r"[ \t]+", " ", value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()


def resolve_href(href: str) -> str:
    """Resolve repository-relative Markdown links to durable GitHub URLs."""

    href = href.strip()
    if href.startswith(("http://", "https://", "mailto:")):
        return href
    if href.startswith("../../README.md"):
        return "https://raw.githubusercontent.com/cisagov/ScubaGoggles/main/README.md"
    if href.startswith("../../docs/usage/Limitations.md"):
        suffix = href.split("Limitations.md", 1)[1]
        return (
            "https://raw.githubusercontent.com/cisagov/ScubaGoggles/main/"
            f"docs/usage/Limitations.md{suffix}"
        )
    if href.startswith("../../docs/usage/Config.md"):
        suffix = href.split("Config.md", 1)[1]
        return (
            "https://raw.githubusercontent.com/cisagov/ScubaGoggles/main/"
            f"docs/usage/Config.md{suffix}"
        )
    if href.startswith("images/"):
        return f"{GITHUB_RAW_BASE}/{href}"
    return href


def extract_links(markdown: str) -> list[tuple[str, str]]:
    """Extract Markdown links and image links."""

    links = []
    for label, href in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", markdown):
        links.append((clean_text(label), resolve_href(href)))
    for href in re.findall(r"<img\s+src=\"([^\"]+)\"", markdown):
        links.append(("Embedded baseline image", resolve_href(href)))
    return links


def extract_policy_field(block: str, label: str) -> str:
    """Extract a Markdown policy metadata field."""

    pattern = rf"- _{re.escape(label)}:_\s*(.*?)(?=\n- _[^_]+:_|\n- MITRE ATT&CK|\Z)"
    match = re.search(pattern, block, re.S)
    if not match:
        pattern = rf"- _{re.escape(label)}_:\s*(.*?)(?=\n- _[^_]+:_|\n- MITRE ATT&CK|\Z)"
        match = re.search(pattern, block, re.S)
    return clean_text(match.group(1)) if match else ""


def extract_mapping(block: str) -> list[str]:
    """Extract all NIST/FedRAMP mappings from a policy block."""

    match = re.search(
        r"- _NIST SP 800-53 Rev\. 5 FedRAMP High Baseline Mapping:_\s*(.+)",
        block,
    )
    if not match:
        return []
    return [item.strip() for item in match.group(1).split(",") if item.strip()]


def extract_recommendation(title: str) -> str:
    """Extract the RFC 2119-style recommendation level from a policy title."""

    terms = (
        "SHALL NOT",
        "SHOULD NOT",
        "MUST NOT",
        "SHALL",
        "SHOULD",
        "MUST",
        "MAY",
        "REQUIRED",
        "RECOMMENDED",
        "OPTIONAL",
    )
    for term in terms:
        if re.search(rf"\b{term}\b", title):
            return term
    return "UNSPECIFIED"


def slug(value: str) -> str:
    """Return a stable OSCAL-friendly identifier fragment."""

    result = re.sub(r"[^a-z0-9.-]+", "-", value.lower()).strip("-")
    return result or "item"


def control_id_from_policy(policy_id: str) -> str:
    """Return the OSCAL control ID for a SCuBA policy ID."""

    return slug(policy_id)


def split_section_blocks(section_text: str) -> dict[str, str]:
    """Split a baseline section into overview/policy/resource blocks."""

    blocks = {}
    markers = list(
        re.finditer(
            r"^### (Policies|Resources|Prerequisites|Implementation)\s*$",
            section_text,
            re.M,
        )
    )
    for idx, marker in enumerate(markers):
        name = marker.group(1).lower()
        start = marker.end()
        end = markers[idx + 1].start() if idx + 1 < len(markers) else len(section_text)
        blocks[name] = section_text[start:end].strip()
    policies_start = markers[0].start() if markers else len(section_text)
    blocks["overview"] = section_text[:policies_start].strip()
    return blocks


def baseline_preamble_parts(preamble: str, baseline_id: str) -> list[JsonObject]:
    """Return OSCAL parts for baseline-level Markdown before policy sections."""

    parts = []
    heading_matches = list(re.finditer(r"^##\s+(.+?)\s*$", preamble, re.M))
    overview_end = heading_matches[0].start() if heading_matches else len(preamble)
    overview = clean_text(preamble[:overview_end])
    if overview:
        parts.append(make_part("overview", overview, f"{baseline_id}_overview"))

    for index, heading in enumerate(heading_matches):
        heading_title = heading.group(1).strip()
        start = heading.end()
        end = (
            heading_matches[index + 1].start()
            if index + 1 < len(heading_matches)
            else len(preamble)
        )
        prose = clean_text(preamble[start:end])
        if prose:
            part_name = slug(heading_title)
            parts.append(
                make_part(
                    "overview",
                    prose,
                    f"{baseline_id}_{part_name}",
                    heading_title,
                )
            )
    return parts


def parse_instructions(implementation: str) -> tuple[dict[str, str], str]:
    """Parse policy-specific and shared implementation instructions."""

    specific = {}
    common = []
    headings = list(re.finditer(r"^#### (.+?)\s*$", implementation, re.M))
    for idx, heading in enumerate(headings):
        heading_title = heading.group(1).strip()
        start = heading.end()
        end = headings[idx + 1].start() if idx + 1 < len(headings) else len(implementation)
        body = clean_text(implementation[start:end])
        if not body:
            continue
        policy_match = re.search(
            r"(GWS\.[A-Z]+(?:CONTROLS)?\.\d+\.\d+v\d+)",
            heading_title,
        )
        if policy_match:
            specific[policy_match.group(1)] = body
        else:
            common.append(f"{heading_title}: {body}")
    return specific, "\n\n".join(common)


def make_prop(name: str, value: JsonValue, ns: str = SCUBA_NS) -> dict[str, str]:
    """Create an OSCAL property object."""

    return {"name": name, "ns": ns, "value": str(value)}


def make_part(
    name: str,
    prose: str,
    part_id: str | None = None,
    title: str | None = None,
) -> JsonObject:
    """Create an OSCAL part object when prose is available."""

    part = {"name": name, "prose": prose}
    if part_id:
        part["id"] = part_id
    if title:
        part["title"] = title
    return part


def parse_baselines_readme(input_dir: Path) -> list[tuple[str, str]]:
    """Read the baseline README and return title/file pairs."""

    readme = input_dir / "README.md"
    text = readme.read_text(encoding="utf-8")
    baselines = []
    for title, file_name in re.findall(r"\[([^\]]+)\]\(([^)]+\.md)\)", text):
        if file_name.lower() != "readme.md":
            baselines.append((title, file_name))
    return baselines


def add_resource(
    resources: list[JsonObject],
    resource_map: dict[str, str],
    namespace: uuid.UUID,
    title: str,
    href: str,
    description: str,
    media_type: str | None = None,
    baseline_file: str | None = None,
) -> str:
    """Add a back-matter resource and return its UUID."""

    href = resolve_href(href)
    if href.startswith("#") and baseline_file:
        href = f"{GITHUB_BROWSER_BASE}/{baseline_file}{href}"
    if href in resource_map:
        return resource_map[href]
    resource_uuid = stable_uuid(namespace, "resource:" + href)
    resource_map[href] = resource_uuid
    rlink = {"href": href}
    if media_type:
        rlink["media-type"] = media_type
    resources.append(
        {
            "uuid": resource_uuid,
            "title": title,
            "description": description,
            "rlinks": [rlink],
        }
    )
    return resource_uuid


def baseline_metadata(title: str, file_name: str) -> tuple[str, str]:
    """Return display metadata for a baseline."""

    override = BASELINE_OVERRIDES.get(file_name, {})
    area = override.get("area", title)
    service = override.get("service", f"Google Workspace {title}")
    return area, service


def oscal_timestamp() -> str:
    """Return an OSCAL-friendly UTC timestamp."""

    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parties(namespace: uuid.UUID) -> list[JsonObject]:
    """Return OSCAL metadata parties."""

    return [
        {
            "uuid": stable_uuid(namespace, "party:cisa"),
            "type": "organization",
            "name": "Cybersecurity and Infrastructure Security Agency",
            "short-name": "CISA",
            "links": [
                {"href": "https://www.cisa.gov/", "rel": "website", "text": "CISA"},
                {
                    "href": "https://github.com/cisagov/ScubaGoggles",
                    "rel": "repository",
                    "text": "SCuBA Goggles repository",
                },
            ],
        },
        {
            "uuid": stable_uuid(namespace, "party:google"),
            "type": "organization",
            "name": "Google LLC",
            "short-name": "Google",
            "links": [
                {
                    "href": "https://workspace.google.com/",
                    "rel": "website",
                    "text": "Google Workspace",
                }
            ],
        },
    ]


def catalog_metadata(
    namespace: uuid.UUID,
    version: str,
    generated_at: str,
    baseline_count: int,
    policy_count: int,
) -> JsonObject:
    """Return metadata for the combined SCuBA catalog."""

    return {
        "title": "Google Workspace SCuBA Baselines - OSCAL Catalog",
        "published": generated_at,
        "last-modified": generated_at,
        "version": version,
        "oscal-version": DEFAULT_OSCAL_VERSION,
        "props": [
            make_prop("source-baseline-count", baseline_count),
            make_prop("source-policy-count", policy_count),
            make_prop("source-format", "markdown"),
            make_prop("target-service", "Google Workspace"),
        ],
        "links": [
            {
                "href": f"{GITHUB_BROWSER_BASE}/README.md",
                "rel": "source",
                "text": "SCuBA Goggles baseline Markdown README",
            },
            {
                "href": OSCAL_CATALOG_REFERENCE,
                "rel": "derived-from",
                "text": f"OSCAL Catalog Model {DEFAULT_OSCAL_VERSION} JSON reference",
            },
        ],
        "roles": [
            {"id": "creator", "title": "Source Content Creator"},
            {"id": "provider", "title": "Service Provider"},
        ],
        "parties": parties(namespace),
        "responsible-parties": [
            {
                "role-id": "creator",
                "party-uuids": [stable_uuid(namespace, "party:cisa")],
            },
            {
                "role-id": "provider",
                "party-uuids": [stable_uuid(namespace, "party:google")],
            },
        ],
        "remarks": (
            "This catalog represents CISA SCuBA Google Workspace baseline "
            "Markdown content in the OSCAL control layer. It does not assert "
            "implementation status, assessment plans, or assessment results."
        ),
    }


def build_catalog(
    input_dir: Path,
    release_version: str | None = None,
) -> tuple[JsonObject, JsonObject]:
    """Build one OSCAL catalog from all README-listed baseline Markdown files."""

    namespace = CATALOG_NAMESPACE
    resources: list[JsonObject] = []
    resource_map: dict[str, str] = {}
    add_standard_resources(resources, resource_map, namespace)

    groups = []
    baseline_summaries = []
    for title, file_name in parse_baselines_readme(input_dir):
        group, summary = build_baseline_group(
            input_dir,
            title,
            file_name,
            resources,
            resource_map,
            namespace,
        )
        groups.append(group)
        baseline_summaries.append(summary)

    generated_at = oscal_timestamp()
    policy_count = sum(item["source_policies"] for item in baseline_summaries)
    version = release_version if release_version else "scuba-google-workspace-baselines"
    output_file = catalog_file_name(release_version)
    catalog = {
        "catalog": {
            "uuid": stable_uuid(namespace, "catalog"),
            "metadata": catalog_metadata(
                namespace,
                version,
                generated_at,
                len(baseline_summaries),
                policy_count,
            ),
            "groups": groups,
            "back-matter": {"resources": resources},
        }
    }
    summary = {
        "output": output_file,
        "baselines": len(baseline_summaries),
        "source_policies": policy_count,
        "source_mappings": sum(item["source_mappings"] for item in baseline_summaries),
        "resources": len(resources),
        "baseline_summaries": baseline_summaries,
    }
    return catalog, summary


def add_standard_resources(
    resources: list[JsonObject],
    resource_map: dict[str, str],
    namespace: uuid.UUID,
) -> None:
    """Add back-matter resources shared by all baselines."""

    add_resource(
        resources,
        resource_map,
        namespace,
        "SCuBA Goggles Documentation",
        "../../README.md",
        "SCuBA Goggles project documentation referenced by source check badges.",
        "text/markdown",
    )
    add_resource(
        resources,
        resource_map,
        namespace,
        "SCuBA Goggles Limitations",
        "../../docs/usage/Limitations.md#log-based-policy-checks",
        "SCuBA Goggles limitations documentation referenced by log-based check badges.",
        "text/markdown",
    )
    add_resource(
        resources,
        resource_map,
        namespace,
        "SCuBA Goggles Config Documentation",
        "../../docs/usage/Config.md#break-glass-accounts",
        "SCuBA Goggles configuration documentation referenced by configurable policy badges.",
        "text/markdown",
    )


def build_baseline_group(
    input_dir: Path,
    title: str,
    file_name: str,
    resources: list[JsonObject],
    resource_map: dict[str, str],
    namespace: uuid.UUID,
) -> tuple[JsonObject, JsonObject]:
    """Build one top-level catalog group for a source baseline."""

    source_path = input_dir / file_name
    text = source_path.read_text(encoding="utf-8")
    area, service = baseline_metadata(title, file_name)
    baseline_id = f"gws-{slug(source_path.stem)}"
    source_resource = add_resource(
        resources,
        resource_map,
        namespace,
        f"SCuBA Goggles {area} Baseline",
        f"{GITHUB_RAW_BASE}/{file_name}",
        "Source Markdown baseline transformed into this OSCAL catalog group.",
        "text/markdown",
    )

    section_groups = []
    source_policy_count = 0
    source_mapping_count = 0
    section_matches = list(re.finditer(r"^## (\d+)\.\s+(.+?)\s*$", text, re.M))
    for section_idx, _ in enumerate(section_matches):
        section_group, section_summary = build_section_group(
            text,
            section_matches,
            section_idx,
            resources,
            resource_map,
            namespace,
            area,
            file_name,
            baseline_id,
        )
        section_groups.append(section_group)
        source_policy_count += section_summary["source_policies"]
        source_mapping_count += section_summary["source_mappings"]

    preamble_parts = baseline_preamble_parts(
        text.split("# Baseline Policies", 1)[0],
        baseline_id,
    )
    group = {
        "id": baseline_id,
        "class": "scuba-baseline",
        "title": f"Google Workspace {area} Baseline",
        "props": [
            make_prop("source-baseline", file_name),
            make_prop("target-service", service),
            make_prop("source-policy-count", source_policy_count),
            make_prop("source-mapping-count", source_mapping_count),
        ],
        "links": [
            {
                "href": "#" + source_resource,
                "rel": "source",
                "text": f"SCuBA Goggles {area} baseline Markdown",
            }
        ],
    }
    if preamble_parts:
        group["parts"] = preamble_parts
    group["groups"] = section_groups

    summary = {
        "baseline": title,
        "source": file_name,
        "source_policies": source_policy_count,
        "source_mappings": source_mapping_count,
        "sections": len(section_groups),
    }
    return group, summary


def build_section_group(
    text: str,
    section_matches: list[re.Match[str]],
    section_idx: int,
    resources: list[JsonObject],
    resource_map: dict[str, str],
    namespace: uuid.UUID,
    area: str,
    file_name: str,
    baseline_id: str,
) -> tuple[JsonObject, dict[str, int]]:
    """Build a nested catalog group for one numbered Markdown section."""

    section_match = section_matches[section_idx]
    section_id = section_match.group(1)
    section_title = section_match.group(2).strip()
    start = section_match.end()
    end = (
        section_matches[section_idx + 1].start()
        if section_idx + 1 < len(section_matches)
        else len(text)
    )
    section_body = text[start:end]
    blocks = split_section_blocks(section_body)
    overview = clean_text(blocks.get("overview", ""))
    prerequisites = clean_text(blocks.get("prerequisites", ""))
    instructions_by_policy, common_instructions = parse_instructions(
        blocks.get("implementation", "")
    )
    section_resource_links = build_section_resource_links(
        blocks,
        resources,
        resource_map,
        namespace,
        area,
        section_id,
        section_title,
        file_name,
    )

    controls = []
    source_mapping_count = 0
    policies_text = blocks.get("policies", "")
    policy_matches = list(
        re.finditer(
            r"^#### (GWS\.[A-Z]+(?:CONTROLS)?\.\d+\.\d+v\d+)\s*$",
            policies_text,
            re.M,
        )
    )
    for policy_idx, _ in enumerate(policy_matches):
        control, mapping_count = build_policy_control(
            policies_text,
            policy_matches,
            policy_idx,
            section_title,
            section_id,
            instructions_by_policy,
            section_resource_links,
            file_name,
        )
        controls.append(control)
        source_mapping_count += mapping_count

    group_id = f"{baseline_id}-section-{slug(section_id)}"
    section_group = {
        "id": group_id,
        "class": "scuba-baseline-section",
        "title": f"{section_id}. {section_title}",
        "props": [
            make_prop("source-baseline", file_name),
            make_prop("source-section", section_id),
            make_prop("source-policy-count", len(controls)),
            make_prop("source-mapping-count", source_mapping_count),
        ],
    }
    parts = []
    if overview:
        parts.append(make_part("overview", overview, f"{group_id}_overview"))
    if prerequisites:
        parts.append(
            make_part(
                "instruction",
                prerequisites,
                f"{group_id}_prerequisites",
                "Prerequisites",
            )
        )
    if common_instructions:
        parts.append(
            make_part(
                "instruction",
                common_instructions,
                f"{group_id}_implementation",
                "Implementation",
            )
        )
    if parts:
        section_group["parts"] = parts
    section_group["controls"] = controls

    return section_group, {
        "source_policies": len(controls),
        "source_mappings": source_mapping_count,
    }


def build_section_resource_links(
    blocks: dict[str, str],
    resources: list[JsonObject],
    resource_map: dict[str, str],
    namespace: uuid.UUID,
    area: str,
    section_id: str,
    section_title: str,
    file_name: str,
) -> list[dict[str, str]]:
    """Build links from a catalog control to section resources."""

    links = []
    reference_blocks = blocks.get("resources", "") + "\n" + blocks.get("overview", "")
    for link_title, href in extract_links(reference_blocks):
        resource_uuid = add_resource(
            resources,
            resource_map,
            namespace,
            link_title,
            href,
            f"Reference resource from {area} section {section_id}: {section_title}.",
            baseline_file=file_name,
        )
        links.append({"href": "#" + resource_uuid, "rel": "reference", "text": link_title})
    return links


def unique_links(links: list[dict[str, str]]) -> list[dict[str, str]]:
    """Return links with duplicate rel and href pairs removed."""

    unique = []
    seen: set[tuple[str, str]] = set()
    for link in links:
        key = (link["rel"], link["href"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(link)
    return unique


def build_policy_control(
    policies_text: str,
    policy_matches: list[re.Match[str]],
    policy_idx: int,
    section_title: str,
    section_id: str,
    instructions_by_policy: dict[str, str],
    section_resource_links: list[dict[str, str]],
    file_name: str,
) -> tuple[JsonObject, int]:
    """Build one OSCAL catalog control from one SCuBA policy block."""

    policy_match = policy_matches[policy_idx]
    policy_id = policy_match.group(1)
    policy_start = policy_match.end()
    policy_end = (
        policy_matches[policy_idx + 1].start()
        if policy_idx + 1 < len(policy_matches)
        else len(policies_text)
    )
    policy_block = policies_text[policy_start:policy_end].strip()
    title_line = next(
        (
            line.strip()
            for line in policy_block.splitlines()
            if line.strip() and not line.strip().startswith("[![")
        ),
        policy_id,
    )
    before_rationale = re.split(r"\n- _Rationale_?:", policy_block, maxsplit=1)[0]
    before_rationale = before_rationale.replace(title_line, "", 1)
    policy_detail = clean_text(before_rationale)
    rationale = extract_policy_field(policy_block, "Rationale")
    last_modified = extract_policy_field(policy_block, "Last modified")
    note = extract_policy_field(policy_block, "Note")
    mappings = extract_mapping(policy_block)
    instructions = instructions_by_policy.get(policy_id, "")

    control_id = control_id_from_policy(policy_id)
    props = base_policy_props(
        policy_id,
        policy_block,
        title_line,
        section_title,
        section_id,
        last_modified,
        mappings,
        file_name,
    )
    if mappings:
        props.append(make_prop("nist-sp800-53-rev5-fedramp-high-mapping", ", ".join(mappings)))

    parts = [make_part("statement", title_line, f"{control_id}_statement")]
    if policy_detail:
        parts.append(
            make_part(
                "guidance",
                policy_detail,
                f"{control_id}_policy_detail",
                "Policy Detail",
            )
        )
    if rationale:
        parts.append(
            make_part("guidance", rationale, f"{control_id}_rationale", "Rationale")
        )
    if instructions:
        parts.append(
            make_part(
                "guidance",
                instructions,
                f"{control_id}_implementation",
                "Implementation",
            )
        )
    if note:
        parts.append(make_part("guidance", note, f"{control_id}_note", "Note"))

    control = {
        "id": control_id,
        "class": "scuba-policy",
        "title": title_line,
        "props": props,
        "links": unique_links(threat_links(policy_block) + section_resource_links),
        "parts": parts,
    }
    return control, len(mappings)


def base_policy_props(
    policy_id: str,
    policy_block: str,
    title_line: str,
    section_title: str,
    section_id: str,
    last_modified: str,
    mappings: list[str],
    file_name: str,
) -> list[dict[str, str]]:
    """Return common properties used by every SCuBA catalog control."""

    props = [
        make_prop("source-policy-id", policy_id),
        make_prop("source-baseline", file_name),
        make_prop("source-policy-family", section_title),
        make_prop("source-policy-section", section_id),
        make_prop("recommendation-level", extract_recommendation(title_line)),
        make_prop("last-modified", last_modified or "not specified"),
        make_prop("automated-check", "true" if "Automated Check" in policy_block else "false"),
        make_prop("log-based-check", "true" if "Log-Based Check" in policy_block else "false"),
        make_prop("manual-check", "true" if "Manual" in policy_block else "false"),
        make_prop("configurable", "true" if "Configurable" in policy_block else "false"),
    ]
    if len(mappings) > 1:
        props.append(make_prop("source-control-mapping-count", len(mappings)))
    if "No TTP Mappings" in policy_block:
        props.append(make_prop("mitre-attck-mapping", "No TTP Mappings"))
    return props


def threat_links(policy_block: str) -> list[dict[str, str]]:
    """Return ATT&CK links from a policy block."""

    links = []
    for link_title, href in extract_links(policy_block):
        if "attack.mitre.org/techniques/" in href:
            links.append(
                {
                    "href": href,
                    "rel": "threat-mapping",
                    "text": "MITRE ATT&CK " + link_title,
                }
            )
    return links


def generate_baselines(
    input_dir: Path,
    output_dir: Path,
    release_version: str | None = None,
) -> JsonObject:
    """Generate the combined OSCAL catalog for all README-listed baselines."""

    output_dir.mkdir(parents=True, exist_ok=True)
    catalog, summary = build_catalog(input_dir, release_version)
    out_path = output_dir / str(summary["output"])
    out_path.write_text(json.dumps(catalog, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    summary_path = output_dir / "generation-summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description="Generate one OSCAL catalog JSON file for SCuBA baselines."
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=REPO_ROOT / "scubagoggles" / "baselines",
        help="Directory containing baseline Markdown files and README.md.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "dist" / "oscal-baseline-catalog",
        help="Directory for generated OSCAL catalog files.",
    )
    parser.add_argument(
        "--release-version",
        default=None,
        help="Optional release version to place in OSCAL metadata.version.",
    )
    return parser.parse_args()


def main() -> None:
    """Run the generator."""

    args = parse_args()
    summary = generate_baselines(args.input_dir, args.output_dir, args.release_version)
    print(
        f"{summary['output']}: baselines={summary['baselines']} "
        f"policies={summary['source_policies']} mappings={summary['source_mappings']} "
        f"resources={summary['resources']}"
    )
    print(f"Wrote OSCAL catalog files to {args.output_dir}.")


if __name__ == "__main__":
    main()
