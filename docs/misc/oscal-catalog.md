# OSCAL Catalog

ScubaGoggles can generate a single OSCAL catalog JSON release artifact from the
Google Workspace Secure Configuration Baseline Markdown files in
`scubagoggles/baselines`.

The Markdown baselines remain the source of truth. The generated catalog is a
machine-readable representation of the same baseline policy content, grouped by
baseline, section, and policy.

The catalog is intended to carry enough Markdown-derived content for downstream
systems to render a complete human-readable baseline view from OSCAL without
using the source Markdown document as the only copy of baseline prose.

The generated OSCAL keeps repeated prose at the highest applicable catalog
level. Baseline overview text remains on the baseline group, section overview,
prerequisites, and common implementation guidance remain on the section group,
and policy-specific statements, details, rationale, notes, and implementation
guidance remain on the policy control. This keeps the catalog readable while
preserving enough hierarchy for downstream tools to render a complete baseline.

OSCAL constrains `part.name` values in catalogs. The generator uses OSCAL
names such as `overview`, `instruction`, `guidance`, and `statement`, then
preserves the source Markdown heading in `part.title` and a stable source-based
identifier in `part.id`.

Generated OSCAL part objects are ordered for readability as `name`, optional
`title`, `id`, and then `prose`. JSON object order does not change the OSCAL
meaning, but this order helps reviewers scan the OSCAL bucket, source Markdown
label, stable identifier, and content in sequence.

Generated SCuBA property objects are ordered as `name`, `value`, and then
`ns`, so readers see the property label and value before the namespace that
defines that label.

## Part Name Mapping

The generator uses the following OSCAL part-name assumptions.

| Markdown content | OSCAL `part.name` | Preserved label |
| --- | --- | --- |
| Main SHALL/SHOULD policy sentence | `statement` | Not needed; also stored in `control.title` |
| Baseline introduction | `overview` | Not needed |
| Baseline assumptions | `overview` | `title: "Assumptions"` |
| Baseline key terminology | `overview` | `title: "Key Terminology"` |
| Section overview | `overview` | Not needed |
| Section prerequisites | `instruction` | `title: "Prerequisites"` |
| Common section implementation steps | `instruction` | `title: "Implementation"` |
| Policy detail | `guidance` | `title: "Policy Detail"` |
| Rationale | `guidance` | `title: "Rationale"` |
| Policy-specific implementation steps | `guidance` | `title: "Implementation"` |
| Note | `guidance` | `title: "Note"` |

## Markdown to OSCAL Cross-Walk

The tables below summarize how source Markdown content is represented in the
generated OSCAL catalog. They are split by catalog layer so the documentation
stays readable in GitHub's Markdown view.

### Catalog Inputs

| Markdown or input | OSCAL representation |
| --- | --- |
| Baseline README list | Creates ordered top-level `catalog.groups[]`. |
| Generated release version | Stored in `catalog.metadata.version` and the generated filename. |
| OSCAL version constant | Stored in `catalog.metadata.oscal-version` and the generated filename. |

The baseline list comes from `scubagoggles/baselines/README.md`.
The OSCAL version is defined by `DEFAULT_OSCAL_VERSION` in
`scubagoggles/scuba_constants.py`.

### Baseline Groups

| Markdown source | OSCAL representation |
| --- | --- |
| Baseline title and file name | Each README-listed baseline becomes one top-level group. |
| Baseline title | Stored in `catalog.groups[].title`. |
| Source Markdown filename | Stored in a `source-baseline` property. |
| Source Markdown file | Linked from the baseline group with `rel=source`. |
| Baseline introduction | Stored as an `overview` part on the baseline group. |
| Baseline preamble sections | Stored as titled `overview` parts on the baseline group. |

Examples of baseline preamble sections include `## Assumptions` and
`## Key Terminology`.

### Section Groups

| Markdown source | OSCAL representation |
| --- | --- |
| Numbered Markdown section | Becomes a nested group under the baseline group. |
| Section heading | Stored in the section group's `title`. |
| Section overview text | Stored once as an `overview` part on the section group. |
| `### Prerequisites` | Stored once as an `instruction` part titled `Prerequisites`. |
| Common implementation instructions | Stored once as an `Implementation` instruction. |

Section-level overview, prerequisites, and common implementation guidance are
not repeated on every child control. OSCAL consumers should read them from the
containing section group.

For example, `## 1. Phishing-Resistant Multifactor Authentication` becomes a
nested section group.

### Policy Controls

| Markdown source | OSCAL representation |
| --- | --- |
| `### Policies` block | Each SCuBA policy becomes one OSCAL control. |
| Policy heading | The normalized value becomes `control.id`. |
| Original SCuBA policy ID | Preserved in a `source-policy-id` property. |
| Main policy sentence | Stored in `control.title` and a `statement` part. |
| Additional policy detail | Stored as a `guidance` part titled `Policy Detail`. |
| `_Rationale:_` | Stored as a `guidance` part titled `Rationale`. |
| `_Note:_` | Stored as a `guidance` part titled `Note`. |
| Policy-specific implementation | Stored as a `guidance` part titled `Implementation`. |

The main policy statement is stored in both `control.title` and
`control.parts[name=statement]`. The statement part is the authoritative copy for
future OSCAL-to-Markdown conversion.

### Policy Properties and Links

| Markdown source | OSCAL representation |
| --- | --- |
| Policy badges | Converted to boolean-like string properties. |
| `_Last modified:_` | Stored in a `last-modified` property. |
| FedRAMP/NIST mapping line | Stored in a FedRAMP High mapping property. |
| Multiple NIST/FedRAMP mappings | Counted in a source mapping count property. |
| MITRE ATT&CK links | Stored as `threat-mapping` links on the control. |
| Resource links | Stored in back matter and linked as references. |
| Embedded baseline images | Preserved as back-matter resources and reference links. |

Shared references are de-duplicated in back matter and linked from applicable
controls.
This includes `### Resources` links, section overview links, and embedded
source images such as `<img src="images/MFA.PNG">`.

The FedRAMP High mapping property name is
`nist-sp800-53-rev5-fedramp-high-mapping`.

## Policy Example

The example below shows a concrete mapping for
`GWS.ASSUREDCONTROLS.1.1v1` from `assuredcontrols.md`.

### Example Identity

| Field | Example |
| --- | --- |
| Baseline Markdown | `assuredcontrols.md` |
| Baseline group title | `Google Workspace Assured Controls Baseline` |
| Section Markdown | `## 1. Google Support Staff Data Access` |
| Section group title | `1. Google Support Staff Data Access` |
| Policy Markdown | `#### GWS.ASSUREDCONTROLS.1.1v1` |
| OSCAL control ID | `gws.assuredcontrols.1.1v1` |

The original policy ID is also preserved in a `source-policy-id` property with
the value `GWS.ASSUREDCONTROLS.1.1v1`.

### Example Inherited Context

| Markdown content | OSCAL representation |
| --- | --- |
| Section overview text | Stored once in the section group's `overview` part. |
| `### Prerequisites` | Stored once in an `instruction` part titled `Prerequisites`. |

In this example, the section overview describes Google support staff data access
mechanisms, and the prerequisites describe licensing assumptions.

### Example Policy Content

| Markdown content | OSCAL representation |
| --- | --- |
| `Access Approvals SHOULD be enabled.` | Stored in `control.title` and the `statement` part. |
| `_Rationale:_ Unauthorized access to data increases...` | Stored in `guidance` titled `Rationale`. |
| Policy implementation instructions | Stored in `guidance` titled `Implementation`. |

### Example Policy Metadata

| Markdown content | OSCAL representation |
| --- | --- |
| `_Last modified:_ November 2025` | `last-modified = "November 2025"` |
| FedRAMP High mapping | `SC-7(10)(a)` |
| MITRE ATT&CK links | Stored as `threat-mapping` links on the control. |
| Automated Check badge | `automated-check = "true"` |
| Log-Based Check badge | `log-based-check = "true"` |

The example MITRE ATT&CK links are `T1530`, `T1537`, and `T1589`.

## Hierarchy and Flattening

OSCAL consumers should read inherited context from the containing catalog
groups. For example, a renderer for `gws.assuredcontrols.1.1v1` should combine
the control content with the overview, prerequisites, and common implementation
parts on its parent section group.

The catalog intentionally avoids repeating section-level prose on every child
control. If a later release adds a CSV or other row-oriented artifact, that
artifact can intentionally flatten inherited section context into each row
without making the canonical OSCAL catalog repetitive.

## Human-Readable Rendering

The generator keeps the main policy statement separate from supplemental policy
detail. For example, `control.parts[name=statement]` contains the SHALL/SHOULD
statement, while `control.parts[name=guidance,title=Policy Detail]` contains
extra explanatory content that appears before the rationale in Markdown.

This structure is intended to help any downstream OSCAL consumer render a full
human-readable baseline without losing baseline preamble text, policy
statements, supplemental policy detail, rationale, implementation guidance, or
other source content represented in the Markdown baselines.
