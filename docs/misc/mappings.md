# Mappings
SCuBA controls have been mapped to both NIST SP 800-53 and the MITRE ATT&CK framework.

## NIST SP 800-53
- NIST SP 800-53 mappings were made using NIST SP 800-53 rev. 5.
- These mappings are limited to controls found within the FedRAMP High baseline.
- These mappings are displayed within the baseline documents, within the bulleted list following each policy statement.
- See [scuba-to-nist-sp-800-53-r5-fedramp-high.csv](/scubagoggles/mappings/scuba-to-nist-sp-800-53-r5-fedramp-high.csv) for a consolidated list of these mappings.

## MITRE ATT&CK
Mappings to the MITRE ATT&CK framework are displayed within the baseline documents themselves, within the bulleted list following each policy statement.

## OSCAL Catalog
The generated [OSCAL Catalog](oscal-catalog.md) release artifact preserves the
NIST SP 800-53 mappings as policy control properties and the MITRE ATT&CK
mappings as policy control links. The catalog keeps the source baseline
hierarchy so section-level context is represented once and inherited by the
policy controls in that section.
