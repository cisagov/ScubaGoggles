# Removed CISA Google Workspace Secure Configuration Baseline Policies

This document tracks policies that have been removed from the Secure Configuration Baselines. The removal of a policy from the baselines does not necessarily imply that whatever configuration recommended by the removed policy should not be used. In each case, review the "Removal rationale" section of the removed policy in this document for more details.

The Cybersecurity and Infrastructure Security Agency's (CISA) Secure Cloud Business Applications (SCuBA) project provides guidance and capabilities to secure federal civilian executive branch (FCEB) agencies' cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments.

The CISA SCuBA SCBs for GWS help secure federal information assets stored within GWS cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government's threats and risk tolerance. Organizations outside of the federal government may also find these baselines to be useful references to help reduce risks even if such organizations have different risk tolerances or face different threats.

For non-federal users, the information in this document is being provided "as is" for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or favoritism by CISA. Without limiting the generality of the foregoing, some controls and settings are not available in all products. CISA has no control over vendor changes to products offerings or features. Accordingly, these SCuBA SCBs for GWS may not be applicable to the products available to you. This document does not address, ensure compliance with, or supersede any law, regulation, or other authority. Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology. This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

## Key Terminology

The key words "MUST," "MUST NOT," "REQUIRED," "SHALL," "SHALL NOT," "SHOULD," "SHOULD NOT," "RECOMMENDED," "MAY," and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

Additional terminology in this document specific to their respective SCBs are to be interpreted as described in the following:

1. [Assured Controls](assuredcontrols.md#key-terminology)
2. [Common Controls](commoncontrols.md#key-terminology)
3. Gemini [Note: This baseline was renamed to the Super Intelligence (SI) baseline. Its key terminology can be found in the Super Intelligence (SI) baseline.]
4. [Gmail](gmail.md#key-terminology)
5. [Google Calendar](calendar.md#key-terminology)
6. [Google Chat](chat.md#key-terminology)
7. [Google Classroom](classroom.md#key-terminology)
8. [Google Drive and Docs](drive.md#key-terminology)
9. [Google Meet](meet.md#key-terminology)
10. [Google Sites](sites.md#key-terminology)
11. [Groups for Business](groups.md#key-terminology)
12. [Super Intelligence (SI)](si.md#key-terminology)

## Removed Policies
<details>
<summary> Gemini </summary>

#### GWS.GEMINI.1.1v1
Gemini app user access SHALL be set to OFF for everyone without a license.
- _Removal date:_ November 2026
- _Removal rationale:_ Reworked into the new Super Intelligence (SI) baseline policy GWS.SI.1.1v1.

#### GWS.GEMINI.2.1v1
Gemini Beta features SHALL be disabled.
- _Removal date:_ November 2026
- _Removal rationale:_ Reworked into the new Super Intelligence (SI) baseline policy GWS.SI.2.1v1.

#### GWS.GEMINI.3.1v1
Gemini conversation history SHALL be enabled.
- _Removal date:_ November 2026
- _Removal rationale:_ Reworked into the new Super Intelligence (SI) baseline policy GWS.SI.3.1v1.

#### GWS.GEMINI.3.2v1
Gemini conversation retention SHALL be set to minimum of 18 months.
- _Removal date:_ November 2026
- _Removal rationale:_ Reworked into the new Super Intelligence (SI) baseline policy GWS.SI.3.2v1.

#### GWS.GEMINI.4.1v1
Conversation sharing SHALL be set to OFF.
- _Removal date:_ November 2026
- _Removal rationale:_ Reworked into the new Super Intelligence (SI) baseline policy GWS.SI.4.1v1.
</details>
