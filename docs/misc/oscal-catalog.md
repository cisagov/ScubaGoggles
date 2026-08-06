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

## Markdown to OSCAL Cross-Walk

The table below summarizes how source Markdown content is represented in the
generated OSCAL catalog.

| Markdown source | OSCAL object/path | Notes |
| --- | --- | --- |
| `scubagoggles/baselines/README.md` baseline list | `catalog.groups[]` | The README controls which baseline files are included and the order of the top-level catalog groups. |
| Generated release version | `catalog.metadata.version` and generated filename | Release workflows pass the ScubaGoggles version into the catalog metadata and filename. |
| OSCAL version constant | `catalog.metadata.oscal-version` and generated filename | The OSCAL version is defined by `DEFAULT_OSCAL_VERSION` in `scubagoggles/scuba_constants.py`. |
| Baseline title and file name | `catalog.groups[].title`, `catalog.groups[].props[name=source-baseline]`, `catalog.groups[].links[rel=source]` | Each README-listed baseline becomes one top-level catalog group. |
| Baseline introduction before `## Assumptions` | `catalog.groups[].parts[name=overview]` | Preserves introductory baseline context that is not part of a numbered policy section. |
| Baseline preamble sections, such as `## Assumptions` and `## Key Terminology` | `catalog.groups[].parts[name=assumptions]`, `catalog.groups[].parts[name=key-terminology]` | Preserves baseline-level sections as named OSCAL parts for downstream human-readable rendering. |
| Numbered Markdown section, such as `## 1. Phishing-Resistant Multifactor Authentication` | `catalog.groups[].groups[]` | Each numbered baseline section becomes a nested catalog group. |
| Section overview text before `### Policies` | `catalog.groups[].groups[].parts[name=overview]` | The section-level overview is stored once on the section group. Child controls inherit that context through the catalog hierarchy. |
| `### Policies` block | `catalog.groups[].groups[].controls[]` | Each SCuBA policy in the section becomes one OSCAL control. |
| Policy heading, such as `#### GWS.COMMONCONTROLS.1.1v1` | `control.props[name=source-policy-id]` and derived `control.id` | The original SCuBA policy ID is preserved as a property. The OSCAL control ID is a normalized form, such as `gws.commoncontrols.1.1v1`. |
| First non-badge line after the policy heading | `control.title` and `control.parts[name=statement]` | The main policy statement is stored as the authoritative statement part to support future OSCAL-to-Markdown conversion. |
| Additional policy detail before `_Rationale:_` | `control.parts[name=policy-detail]` | Extra explanatory policy content is kept separate from the main policy statement. |
| Automated, manual, log-based, or configurable badge | `control.props[name=automated-check]`, `control.props[name=manual-check]`, `control.props[name=log-based-check]`, `control.props[name=configurable]` | Badge state is converted to boolean-like string properties. |
| `_Rationale:_` | `control.parts[name=rationale]` | Preserves the rationale as human-readable OSCAL prose. |
| `_Last modified:_` | `control.props[name=last-modified]` | Preserves the Markdown policy modification date. |
| `_Note:_` | `control.parts[name=note]` | Notes are represented as readable prose on the policy control. |
| `_NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_` | `control.props[name=nist-sp800-53-rev5-fedramp-high-mapping]` | Multiple source mappings remain attached to the same SCuBA policy control. |
| Multiple NIST/FedRAMP mappings for one policy | `control.props[name=source-control-mapping-count]` | Records the number of mappings when the policy maps to more than one NIST SP 800-53 control or statement. |
| MITRE ATT&CK links | `control.links[rel=threat-mapping]` | ATT&CK technique links stay attached to the relevant policy control. |
| `### Resources` links and section overview links | `catalog.back-matter.resources[]` and `control.links[rel=reference]` | Shared references are de-duplicated in back matter and linked from applicable controls. |
| Embedded baseline images, such as `<img src="images/MFA.PNG">` | `catalog.back-matter.resources[]` and `control.links[rel=reference]` | Embedded source images are preserved as reference resources. |
| `### Prerequisites` | `catalog.groups[].groups[].parts[name=prerequisites]` | Section prerequisites are represented once on the section group. Child controls inherit that context through the catalog hierarchy. |
| Common implementation instructions | `catalog.groups[].groups[].parts[name=implementation]` | Common instructions are stored once at section level. Policy controls only store policy-specific implementation guidance. |
| Policy-specific implementation instructions | `control.parts[name=implementation]` | Policy implementation guidance is stored as readable OSCAL prose on the policy control. |

## Policy Example

The table below shows a concrete mapping for
`GWS.ASSUREDCONTROLS.1.1v1` from `assuredcontrols.md`.

| Field | Markdown | OSCAL example |
| --- | --- | --- |
| Baseline | `assuredcontrols.md` | `catalog.groups[id=gws-assuredcontrols].title = "Google Workspace Assured Controls Baseline"` |
| Section | `## 1. Google Support Staff Data Access` | `catalog.groups[].groups[id=gws-assuredcontrols-section-1].title = "1. Google Support Staff Data Access"` |
| Section overview | Text before `### Policies` describing Google support staff data access mechanisms | `catalog.groups[].groups[].parts[name=overview].prose` contains that section overview once on the section group |
| Section prerequisites | `### Prerequisites` lists the Assured Controls and Access Management licensing assumptions | `catalog.groups[].groups[].parts[name=prerequisites].prose` stores those prerequisites once on the section group |
| Policy ID | `#### GWS.ASSUREDCONTROLS.1.1v1` | `control.id = "gws.assuredcontrols.1.1v1"` and `control.props[name=source-policy-id].value = "GWS.ASSUREDCONTROLS.1.1v1"` |
| Statement | `Access Approvals SHOULD be enabled.` | `control.title = "Access Approvals SHOULD be enabled."` and `control.parts[name=statement].prose = "Access Approvals SHOULD be enabled."` |
| Rationale | `_Rationale:_ Unauthorized access to data increases the risk of exposing sensitive data to untrusted entities...` | `control.parts[name=rationale].prose` contains the full rationale |
| Last modified | `_Last modified:_ November 2025` | `control.props[name=last-modified].value = "November 2025"` |
| NIST mapping | `_NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ SC-7(10)(a)` | `control.props[name=nist-sp800-53-rev5-fedramp-high-mapping].value = "SC-7(10)(a)"` |
| MITRE ATT&CK mappings | `T1530`, `T1537`, and `T1589` links in the policy mapping list | `control.links[rel=threat-mapping]` contains links for `MITRE ATT&CK T1530`, `T1537`, and `T1589` |
| Check badges | Automated Check and Log-Based Check badges | `control.props[name=automated-check].value = "true"` and `control.props[name=log-based-check].value = "true"` |
| Implementation | `#### GWS.ASSUREDCONTROLS.1.1v1 Instructions` with the Access Approvals steps | `control.parts[name=implementation].prose` contains the policy-specific implementation steps |

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
statement, while `control.parts[name=policy-detail]` contains extra explanatory
content that appears before the rationale in Markdown.

This structure is intended to help any downstream OSCAL consumer render a full
human-readable baseline without losing baseline preamble text, policy
statements, supplemental policy detail, rationale, implementation guidance, or
other source content represented in the Markdown baselines.
