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

## Catalog Excerpt

The excerpt below shows the generated catalog structure from the top-level
`catalog` object down to the first policy in the first baseline group. It uses
the real first baseline, section, and policy identifiers from the generated
catalog. The shown prose fields are copied from the generated catalog as-is,
while sibling groups, controls, properties, links, and back-matter resources are
omitted for readability.

<details>
<summary>Show top-down OSCAL catalog excerpt</summary>

```json
{
  "catalog": {
    "uuid": "1a21eb2b-368d-5781-84c9-2ccadb555670",
    "metadata": {
      "title": "Google Workspace SCuBA Baselines - OSCAL Catalog",
      "last-modified": "2026-08-18T17:33:09Z",
      "version": "v1.0.0",
      "oscal-version": "1.2.2"
    },
    "groups": [
      {
        "id": "gws-assuredcontrols",
        "class": "scuba-baseline",
        "title": "Google Workspace Assured Controls Baseline",
        "props": [
          {
            "name": "source-baseline",
            "value": "assuredcontrols.md",
            "ns": "https://cisa.gov/scuba"
          }
        ],
        "links": [
          {
            "href": "#5774c748-0839-5ce7-bc40-cae2d2730853",
            "rel": "source",
            "text": "SCuBA Goggles Assured Controls baseline Markdown"
          }
        ],
        "parts": [
          {
            "name": "overview",
            "id": "gws-assuredcontrols_overview",
            "prose": "# CISA Google Workspace Secure Configuration Baseline for Assured Controls and Assured Controls Plus\n\nAssured Controls and Assured Controls Plus are paid add-ons within Google Workspace (GWS) relating to compliance and security.\nThis Secure Configuration Baseline (SCB) for Assured Controls provides specific policies to strengthen an organization's data security.\nThis baseline is intended as guidance for agencies that already have Assured Controls or Assured Controls Plus licenses.\nUsers who choose to implement this baseline should carefully consider the tradeoffs involved, including the potential security benefits, usability impacts, and possible increased fees for additional licenses.\n\nThe Cybersecurity and Infrastructure Security Agency's (CISA) Secure Cloud Business Applications (SCuBA) project, provides guidance and capabilities to secure federal civilian executive branch (FCEB) agencies' cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments.\n\nThe CISA SCuBA SCBs for GWS help secure federal information assets stored within GWS cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government's threats and risk tolerance. Organizations outside of the federal government may also find these baselines useful references to help reduce risks even if such organizations have different risk tolerances or face different threats.\n\nFor non-federal users, the information in this document is being provided \"as is\" for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or favoritism by CISA. Without limiting the generality of the foregoing, some controls and settings are not available in all products. CISA has no control over vendor changes to products offerings or features. Accordingly, these SCuBA SCBs for GWS may not be applicable to the products available to you. This document does not address, ensure compliance with, or supersede any law, regulation, or other authority. Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology. This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.\n\nThis baseline is based on Google documentation and addresses the following:\nGoogle Support Staff Data Access (https://github.com/cisagov/ScubaGoggles/blob/main/scubagoggles/baselines/assuredcontrols.md#1-google-support-staff-data-access)\nData Regions Advanced Settings (https://github.com/cisagov/ScubaGoggles/blob/main/scubagoggles/baselines/assuredcontrols.md#2-data-regions-advanced-settings)"
          }
        ],
        "groups": [
          {
            "id": "gws-assuredcontrols-section-1",
            "class": "scuba-baseline-section",
            "title": "1. Google Support Staff Data Access",
            "parts": [
              {
                "name": "overview",
                "id": "gws-assuredcontrols-section-1_overview",
                "prose": "Google Workspace (GWS) includes several mechanisms to control how Google support staff access an organization's data.\nAccess Approvals requires Google support staff to request approval before viewing an organization's data.\nAccess can also be restricted to specific demographics, such as access by U.S.-based Google staff only.\nHowever, these features require additional licensing and are not available by default with GWS Enterprise Plus."
              },
              {
                "name": "instruction",
                "title": "Prerequisites",
                "id": "gws-assuredcontrols-section-1_prerequisites",
                "prose": "Access Approvals requires either the Assured Controls or the Assured Controls Plus add-ons.\nAccess Management requires the Assured Controls Plus add-on. However, customers who purchased the Assured Controls and the Assured Support add-on prior to June 17, 2024, also have access to Access Management."
              }
            ],
            "controls": [
              {
                "id": "gws.assuredcontrols.1.1v1",
                "class": "scuba-policy",
                "title": "Access Approvals SHOULD be enabled.",
                "props": [
                  {
                    "name": "source-policy-id",
                    "value": "GWS.ASSUREDCONTROLS.1.1v1",
                    "ns": "https://cisa.gov/scuba"
                  },
                  {
                    "name": "last-modified",
                    "value": "November 2025",
                    "ns": "https://cisa.gov/scuba"
                  },
                  {
                    "name": "nist-sp800-53-rev5-fedramp-high-mapping",
                    "value": "SC-7(10)(a)",
                    "ns": "https://cisa.gov/scuba"
                  }
                ],
                "links": [
                  {
                    "href": "https://attack.mitre.org/techniques/T1530/",
                    "rel": "threat-mapping",
                    "text": "MITRE ATT&CK T1530: Data from Cloud Storage"
                  }
                ],
                "parts": [
                  {
                    "name": "statement",
                    "id": "gws.assuredcontrols.1.1v1_statement",
                    "prose": "Access Approvals SHOULD be enabled."
                  },
                  {
                    "name": "guidance",
                    "title": "Rationale",
                    "id": "gws.assuredcontrols.1.1v1_rationale",
                    "prose": "Unauthorized data access increases the risk of exposing sensitive data to untrusted entities. Unauthorized access and actions to an organization's data may be reduced by requiring approval of Google staff requests to access organizations' data."
                  },
                  {
                    "name": "guidance",
                    "title": "Implementation",
                    "id": "gws.assuredcontrols.1.1v1_implementation",
                    "prose": "1. Sign in to the Google Admin console (https://admin.google.com/) as a super admin.\n2. Select Data -\\> Compliance -\\> Access Approvals.\n3. Check the Require Google staff to request approval before viewing data necessary for support services box.\n4. Click SAVE."
                  }
                ]
              }
            ]
          }
        ]
      }
    ]
  }
}
```

</details>

## Viewing the Catalog

After downloading and extracting the generated OSCAL artifact, users can inspect
the catalog with an OSCAL-aware viewer such as <https://viewer.oscal.io/>.
This can help browse the catalog hierarchy and policy parts. Schema validation
is performed by the pinned OSCAL CLI in CI.

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
| Generated release version | Stored in `catalog.metadata.version` and the generated filename for release artifacts. |
| Ad hoc generator run | Uses the ScubaGoggles package version with a development build label in `catalog.metadata.version`. |
| OSCAL version constant | Stored in `catalog.metadata.oscal-version` and the generated filename. |

The baseline list comes from `scubagoggles/baselines/README.md`.
The OSCAL version is defined by `DEFAULT_OSCAL_VERSION` in
`scubagoggles/scuba_constants.py`.
Markdown links copied into OSCAL prose are resolved to absolute GitHub URLs so
the generated catalog remains portable outside the source repository checkout.

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
