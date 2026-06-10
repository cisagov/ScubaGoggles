"""Generate OSCAL component definitions from SCuBA baseline Markdown.

The Markdown files in ``scubagoggles/baselines`` remain the source of truth.
This utility creates machine-readable OSCAL ``component-definition`` JSON files
from those Markdown baselines for release artifacts and downstream automation.
"""

# pylint: disable=too-many-branches,too-many-lines

from __future__ import annotations

import argparse
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


GITHUB_BROWSER_BASE = (
    "https://github.com/cisagov/ScubaGoggles/blob/main/scubagoggles/baselines"
)
GITHUB_RAW_BASE = (
    "https://raw.githubusercontent.com/cisagov/ScubaGoggles/main/scubagoggles/baselines"
)
NIST_EXAMPLES = (
    "https://github.com/usnistgov/oscal-content/tree/main/examples/component-definition/json"
)
FEDRAMP_HIGH_PROFILE = (
    "https://raw.githubusercontent.com/GSA/fedramp-automation/master/"
    "dist/content/rev5/baselines/json/FedRAMP_rev5_HIGH-baseline_profile.json"
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


def normalize_control_id(mapping: str) -> str:
    """Normalize a source NIST mapping to an OSCAL catalog control ID.

    Examples:
    ``IA-2(1)`` becomes ``ia-2.1``.
    ``IA-5c`` becomes ``ia-5`` because ``c`` is a statement part.
    ``SC-7(10)(a)`` becomes ``sc-7.10`` because ``a`` is a statement part.
    """

    token = mapping.strip().replace(" ", "").replace(":", "")
    match = re.match(
        r"^([A-Z]{2})-(\d+)\((\d+)\)\(?([a-z])\)?$",
        token,
        re.IGNORECASE,
    )
    if match:
        return f"{match.group(1).lower()}-{match.group(2)}.{match.group(3)}"
    match = re.match(r"^([A-Z]{2})-(\d+)\((\d+)\)$", token)
    if match:
        return f"{match.group(1).lower()}-{match.group(2)}.{match.group(3)}"
    match = re.match(r"^([A-Z]{2})-(\d+)([a-z])$", token, re.IGNORECASE)
    if match:
        return f"{match.group(1).lower()}-{match.group(2)}"
    match = re.match(r"^([A-Z]{2})-(\d+)$", token)
    if match:
        return f"{match.group(1).lower()}-{match.group(2)}"
    return token.lower()


def statement_id(mapping: str, control_id: str) -> str:
    """Return the OSCAL statement ID for a source mapping."""

    token = mapping.strip().replace(" ", "").replace(":", "")
    match = re.match(r"^[A-Z]{2}-\d+\(\d+\)\(?([a-z])\)?$", token, re.IGNORECASE)
    if match:
        return f"{control_id}_smt.{match.group(1).lower()}"
    match = re.match(r"^[A-Z]{2}-\d+([a-z])$", token, re.IGNORECASE)
    if match:
        return f"{control_id}_smt.{match.group(1).lower()}"
    return f"{control_id}_smt"


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


def make_prop(name: str, value: Any, ns: str = SCUBA_NS) -> dict[str, str]:
    """Create an OSCAL property object."""

    return {"name": name, "ns": ns, "value": str(value)}


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
    resources: list[dict[str, Any]],
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


def latest_modified_value(implemented: list[dict[str, Any]]) -> str:
    """Return the final last-modified value found in generated requirements."""

    modified_values = []
    for item in implemented:
        for prop in item["props"]:
            if prop["name"] == "last-modified" and prop["value"] != "not specified":
                modified_values.append(prop["value"])
    return modified_values[-1] if modified_values else "not computed"


def oscal_timestamp() -> str:
    """Return an OSCAL-friendly UTC timestamp."""

    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def build_baseline(
    input_dir: Path,
    title: str,
    file_name: str,
    release_version: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build one OSCAL component definition from one baseline Markdown file."""

    source_path = input_dir / file_name
    text = source_path.read_text(encoding="utf-8")
    area, service = baseline_metadata(title, file_name)
    namespace = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"https://cisa.gov/scuba/google-workspace/{file_name}",
    )
    resources: list[dict[str, Any]] = []
    resource_map: dict[str, str] = {}

    fedramp_uuid = add_resource(
        resources,
        resource_map,
        namespace,
        "FedRAMP Rev. 5 High Baseline OSCAL Profile",
        FEDRAMP_HIGH_PROFILE,
        "FedRAMP Rev. 5 High baseline profile used as the OSCAL source for "
        "mapped NIST SP 800-53 Rev. 5 controls.",
        "application/oscal.profile+json",
    )
    add_resource(
        resources,
        resource_map,
        namespace,
        f"SCuBA Goggles {area} Baseline",
        f"{GITHUB_RAW_BASE}/{file_name}",
        "Source Markdown baseline transformed into this OSCAL component definition.",
        "text/markdown",
    )
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

    implemented: list[dict[str, Any]] = []
    covered_areas = []
    source_policy_count = 0
    section_matches = list(re.finditer(r"^## (\d+)\.\s+(.+?)\s*$", text, re.M))
    for section_idx, section_match in enumerate(section_matches):
        source_policy_count = parse_section(
            text,
            section_matches,
            section_idx,
            source_policy_count,
            covered_areas,
            implemented,
            resources,
            resource_map,
            namespace,
            area,
            file_name,
        )

    metadata_remarks = clean_text(text.split("# Baseline Policies", 1)[0])
    version = release_version if release_version else f"scuba-{source_path.stem}"
    generated_at = oscal_timestamp()
    doc = {
        "component-definition": {
            "uuid": stable_uuid(namespace, "component-definition"),
            "metadata": {
                "title": f"Google Workspace {area} SCuBA Baseline - OSCAL Component Definition",
                "published": generated_at,
                "last-modified": generated_at,
                "version": version,
                "oscal-version": "1.1.2",
                "props": [
                    make_prop("source-baseline", file_name),
                    make_prop("source-latest-policy-modified", latest_modified_value(implemented)),
                    make_prop("target-service", service),
                    make_prop("baseline-area", area),
                    make_prop("source-policy-count", source_policy_count),
                    make_prop("implemented-requirement-count", len(implemented)),
                ],
                "links": [
                    {
                        "href": f"{GITHUB_BROWSER_BASE}/{file_name}",
                        "rel": "source",
                        "text": f"SCuBA Goggles {area} baseline Markdown",
                    },
                    {
                        "href": NIST_EXAMPLES,
                        "rel": "derived-from",
                        "text": "NIST OSCAL component-definition JSON examples",
                    },
                ],
                "roles": [
                    {"id": "creator", "title": "Source Content Creator"},
                    {"id": "provider", "title": "Service Provider"},
                    {"id": "customer", "title": "Implementing Organization"},
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
                "remarks": metadata_remarks[:3000],
            },
            "components": [
                component(
                    namespace,
                    service,
                    area,
                    file_name,
                    covered_areas,
                    fedramp_uuid,
                    implemented,
                )
            ],
            "back-matter": {"resources": resources},
        }
    }
    summary = {
        "baseline": title,
        "source": file_name,
        "output": f"{source_path.stem}-oscal-component-definition.json",
        "source_policies": source_policy_count,
        "implemented_requirements": len(implemented),
        "resources": len(resources),
    }
    return doc, summary


def parse_section(
    text: str,
    section_matches: list[re.Match[str]],
    section_idx: int,
    source_policy_count: int,
    covered_areas: list[str],
    implemented: list[dict[str, Any]],
    resources: list[dict[str, Any]],
    resource_map: dict[str, str],
    namespace: uuid.UUID,
    area: str,
    file_name: str,
) -> int:
    """Parse one numbered baseline section into implemented requirements."""

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
    covered_areas.append(f"{section_id}. {section_title}")
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
    policies_text = blocks.get("policies", "")
    policy_matches = list(
        re.finditer(
            r"^#### (GWS\.[A-Z]+(?:CONTROLS)?\.\d+\.\d+v\d+)\s*$",
            policies_text,
            re.M,
        )
    )
    for policy_idx, policy_match in enumerate(policy_matches):
        source_policy_count += 1
        parse_policy(
            policies_text,
            policy_matches,
            policy_idx,
            section_title,
            section_id,
            overview,
            prerequisites,
            instructions_by_policy,
            common_instructions,
            section_resource_links,
            namespace,
            implemented,
        )
    return source_policy_count


def build_section_resource_links(
    blocks: dict[str, str],
    resources: list[dict[str, Any]],
    resource_map: dict[str, str],
    namespace: uuid.UUID,
    area: str,
    section_id: str,
    section_title: str,
    file_name: str,
) -> list[dict[str, str]]:
    """Build links from an implemented requirement to section resources."""

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


def parse_policy(
    policies_text: str,
    policy_matches: list[re.Match[str]],
    policy_idx: int,
    section_title: str,
    section_id: str,
    overview: str,
    prerequisites: str,
    instructions_by_policy: dict[str, str],
    common_instructions: str,
    section_resource_links: list[dict[str, str]],
    namespace: uuid.UUID,
    implemented: list[dict[str, Any]],
) -> None:
    """Parse one policy block and append OSCAL implemented requirements."""

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
    mappings = extract_mapping(policy_block) or ["unknown"]
    instructions = instructions_by_policy.get(policy_id, "")
    if common_instructions:
        instructions = (common_instructions + "\n\n" + instructions).strip()

    base_props = base_policy_props(
        policy_id,
        policy_block,
        title_line,
        section_title,
        section_id,
        last_modified,
        note,
        policy_detail,
        mappings,
        overview,
        prerequisites,
    )
    links = threat_links(policy_block) + section_resource_links
    statement_description = policy_statement_description(
        policy_detail,
        rationale,
        instructions,
        title_line,
    )
    remarks = policy_remarks(overview, prerequisites, note, policy_detail)
    for mapping_index, mapping in enumerate(mappings, start=1):
        control_id = normalize_control_id(mapping) if mapping != "unknown" else "unknown"
        props = list(base_props)
        props.append(make_prop("source-control-mapping", mapping))
        props.append(make_prop("source-control-mapping-index", mapping_index))
        item = {
            "uuid": stable_uuid(namespace, f"implemented:{policy_id}:{mapping}"),
            "control-id": control_id,
            "description": f"{policy_id}: {title_line}",
            "props": props,
            "links": links,
            "statements": [
                {
                    "uuid": stable_uuid(namespace, f"statement:{policy_id}:{mapping}"),
                    "statement-id": statement_id(mapping, control_id),
                    "description": statement_description,
                    "responsible-roles": [{"role-id": "customer"}],
                }
            ],
        }
        if remarks:
            item["remarks"] = remarks
        implemented.append(item)


def base_policy_props(
    policy_id: str,
    policy_block: str,
    title_line: str,
    section_title: str,
    section_id: str,
    last_modified: str,
    note: str,
    policy_detail: str,
    mappings: list[str],
    overview: str,
    prerequisites: str,
) -> list[dict[str, str]]:
    """Return common properties used by every mapping for a policy."""

    props = [
        make_prop("source-policy-id", policy_id),
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
        props.append(make_prop("source-control-mapping-set", ", ".join(mappings)))
    if note:
        props.append(make_prop("source-note", note))
    if policy_detail:
        props.append(make_prop("source-policy-detail", policy_detail[:2000]))
    if "No TTP Mappings" in policy_block:
        props.append(make_prop("mitre-attck-mapping", "No TTP Mappings"))
    if overview:
        props.append(make_prop("source-section-overview", overview[:1200]))
    if prerequisites:
        props.append(make_prop("section-prerequisites", prerequisites[:1200]))
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


def policy_statement_description(
    policy_detail: str,
    rationale: str,
    instructions: str,
    fallback: str,
) -> str:
    """Return the OSCAL statement description for a policy."""

    description_parts = []
    if policy_detail:
        description_parts.append("Policy detail: " + policy_detail)
    if rationale:
        description_parts.append("Rationale: " + rationale)
    if instructions:
        description_parts.append("Implementation: " + instructions)
    return " ".join(description_parts) if description_parts else fallback


def policy_remarks(
    overview: str,
    prerequisites: str,
    note: str,
    policy_detail: str,
) -> str:
    """Return additional source context as OSCAL remarks."""

    remarks_parts = []
    if overview:
        remarks_parts.append("Source section overview: " + overview)
    if prerequisites:
        remarks_parts.append("Prerequisites: " + prerequisites)
    if note:
        remarks_parts.append("Source note: " + note)
    if policy_detail:
        remarks_parts.append("Source policy detail: " + policy_detail)
    return "\n\n".join(remarks_parts)


def parties(namespace: uuid.UUID) -> list[dict[str, Any]]:
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


def component(
    namespace: uuid.UUID,
    service: str,
    area: str,
    file_name: str,
    covered_areas: list[str],
    fedramp_uuid: str,
    implemented: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return the OSCAL component for one baseline."""

    return {
        "uuid": stable_uuid(namespace, "component:google-workspace"),
        "type": "service",
        "title": service,
        "description": (
            "Google Workspace configuration guidance represented from the "
            f"CISA SCuBA Goggles {file_name} baseline."
        ),
        "purpose": (
            "Describe implementation responsibility and configuration evidence for "
            f"the Google Workspace {area} SCuBA baseline."
        ),
        "props": [
            make_prop(
                "assumption",
                "The organization uses the Google Workspace service or add-on "
                "addressed by this baseline.",
            ),
            make_prop("source-technology", "Google Admin Console"),
        ]
        + [make_prop("covered-area", covered_area) for covered_area in covered_areas],
        "responsible-roles": [
            {
                "role-id": "provider",
                "party-uuids": [stable_uuid(namespace, "party:google")],
            },
            {
                "role-id": "creator",
                "party-uuids": [stable_uuid(namespace, "party:cisa")],
            },
            {"role-id": "customer"},
        ],
        "control-implementations": [
            {
                "uuid": stable_uuid(namespace, "implementation"),
                "source": "#" + fedramp_uuid,
                "description": (
                    f"CISA SCuBA Google Workspace {area} policies mapped to "
                    "NIST SP 800-53 Rev. 5 FedRAMP High Baseline controls."
                ),
                "implemented-requirements": implemented,
            }
        ],
    }


def generate_baselines(
    input_dir: Path,
    output_dir: Path,
    release_version: str | None = None,
) -> list[dict[str, Any]]:
    """Generate all README-listed baseline OSCAL files."""

    output_dir.mkdir(parents=True, exist_ok=True)
    summary = []
    for title, file_name in parse_baselines_readme(input_dir):
        doc, item = build_baseline(input_dir, title, file_name, release_version)
        out_path = output_dir / item["output"]
        out_path.write_text(json.dumps(doc, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        summary.append(item)
    summary_path = output_dir / "generation-summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(
        description="Generate OSCAL component-definition JSON for SCuBA baselines."
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=repo_root / "scubagoggles" / "baselines",
        help="Directory containing baseline Markdown files and README.md.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=repo_root / "dist" / "oscal-baselines",
        help="Directory for generated OSCAL files.",
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
    for item in summary:
        print(
            f"{item['source']}: policies={item['source_policies']} "
            f"implemented={item['implemented_requirements']} resources={item['resources']}"
        )
    print(f"Wrote {len(summary)} baseline OSCAL files to {args.output_dir}.")


if __name__ == "__main__":
    main()
