# CISA Google Workspace Secure Configuration Baseline for Google Classroom

Google Classroom is a service in Google Workspace (GWS) to streamline assignments, boost collaboration, and foster communication. This service allows for the creation of classes, creating and grading assignments, student collaboration, communication with teachers and students, and integration with other Google products.

Google Classroom is designed and intended for implementation in educational institutions. Google Classroom is available with the Google Workspace (GWS) for Education Edition and is included with all tiers of GWS for Education including Fundamentals, Standard, and Plus. CISA's Secure Configuration Baseline (SCB) Google Classroom policies and guidance are written to correspond with the Plus edition.

The Cybersecurity and Infrastructure Security Agency's (CISA) Secure Cloud Business Applications (SCuBA) project provides guidance and capabilities to secure federal civilian executive branch (FCEB) agencies' cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments.

The CISA SCuBA SCBs for GWS help secure federal information assets stored within GWS cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government's threats and risk tolerance. Organizations outside of the federal government may also find these baselines to be useful references to help reduce risks even if such organizations have different risk tolerances or face different threats.

For non-federal users, the information in this document is being provided "as is" for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or favoritism by CISA. Without limiting the generality of the foregoing, some controls and settings are not available in all products. CISA has no control over vendor changes to products offerings or features. Accordingly, these SCuBA SCBs for GWS may not be applicable to the products available to you. This document does not address, ensure compliance with, or supersede any law, regulation, or other authority. Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology. This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

This baseline is based on Google documentation available at [Google Workspace Admin Help: Classroom](https://support.google.com/edu/classroom/?hl=en#topic=10298088) and addresses the following:

-   [Class Membership](#1-class-membership)
-   [Classroom API](#2-classroom-api)
-   [Roster Import](#3-roster-import)
-   [Student Unenrollment](#4-student-unenrollment)
-   [Class Creation](#5-class-creation)

Settings can be assigned to certain users within GWS through organizational units, configuration groups, or individually. Before changing a setting, the user can select the organizational unit, configuration group, or individual users to which they want to apply changes.

## Assumptions

This document assumes the organization is using GWS Education Plus.

This document does not address, ensure compliance with, or supersede any law, regulation, or other authority.  Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology.  This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

## Key Terminology

The key words "MUST," "MUST NOT," "REQUIRED," "SHOULD," "SHOULD NOT," "RECOMMENDED," "MAY," and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.
[![BOD 25-01 Requirement](https://img.shields.io/badge/BOD_25--01_Requirement-C41230)](https://www.cisa.gov/news-events/directives/bod-25-01-implementation-guidance-implementing-secure-practices-cloud-services) (**BOD 25-01 Requirement**): This indicator means that the policy is required under CISA BOD 25-01.

[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology) (**Automated Check**): This indicator means that the policy can be automatically checked via ScubaGoggles. See [our documentation](../../README.md) for help getting started.

[![Configurable](https://img.shields.io/badge/Configurable-005288)](../../docs/usage/Config.md#break-glass-accounts)(**Configurable**): This indicator means that the policy can be customized via config file.

[![Log-Based Check](https://img.shields.io/badge/Log--Based_Check-F6E8E5)](../../docs/usage/Limitations.md#log-based-policy-checks)(**Log-Based Check**): This indicator means that ScubaGoggles will check the policy by reviewing admin audit logs. See [Limitations](../../docs/usage/Limitations.md#log-based-policy-checks).

[![Manual](https://img.shields.io/badge/Manual-046B9A)](#gwscommoncontrols83v06-instructions)(**Manual**): This indicator means that the policy requires manual verification of configuration settings.

# Baseline Policies

## 1. Class Membership

This section covers who has the ability to join classes and what classes the users in your domain can join.

### Policies

#### GWS.CLASSROOM.1.1v1
"Who can join classes in your domain" SHOULD be set to "Users in your domain only."

[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)

- _Rationale:_ Classes can contain personally identifiable information (PII) or sensitive information. Restricting access to the organization's classes helps prevent data leakage resulting from unauthorized classroom access.
- _Last modified:_ October 2025
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ AC-3
- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)

#### GWS.CLASSROOM.1.2v1
"Which classes users in your domain can join" SHOULD be set to "Classes in your domain only."

[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)

- _Rationale:_ Allowing users to join classes from outside the organization's domains could allow data to be exfiltrated to entities outside the organization's control, potentially creating a significant security risk.
- _Last modified:_ October 2025
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ SC-7(10)
- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)

### Resources
-   [Google Workspace Admin Help: Control User Access to Classroom](https://support.google.com/edu/classroom/answer/6023715)

### Prerequisites

-   None

### Implementation
To configure the settings for Class Membership:

#### Policy Group 1 Common Implementation:
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Additional Google Service** -\> **Classroom**.
3.  Select **Class settings**.
4.  Select **About class membership**.

#### GWS.CLASSROOM.1.1v1 Instructions
1.  For **Who can join classes in your domain**, select **Users in your domain only**.
2.  Select **Save**.

#### GWS.CLASSROOM.1.2v1 Instructions
1.  For **Which classes can users in your domain join**, select **Classes in your domain only**.
2.  Select **Save**.

## 2. Classroom API

This section covers policies related to the Google Classroom application programming interface (API).

### Policies

#### GWS.CLASSROOM.2.1v1
Users SHOULD NOT be able to authorize apps to access their Google Classroom data.

[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)

- _Rationale:_ Allowing non-administrator users to authorize apps granting access to classroom data opens a possibility for data loss. Allowing only administrators to authorize application access reduces this risk.
- _Last modified:_ September 2023
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ AC-6(10)
- MITRE ATT&CK TTP Mapping
  - [T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
    - [T1059:009: Command and Scripting Interpreter: Cloud API](https://attack.mitre.org/techniques/T1059/009/)
  - [T1199: Trusted Relationship](https://attack.mitre.org/techniques/T1199/)

### Resources

-   [Google Workspace Admin Help: Set Classroom data access](https://support.google.com/edu/classroom/answer/6250906?hl=en)

### Prerequisites

-   None

### Implementation
To configure the settings for Classroom API:

#### GWS.CLASSROOM.2.1v1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Additional Google Service** -\> **Classroom**.
3.  Select **Data access**.
4.  Uncheck **Users can authorize apps to access their Google Classroom data**.
5.  Select **Save**.

## 3. Roster Import

This section covers policies related to importing rosters from Clever.

### Policies

#### GWS.CLASSROOM.3.1v1
"Roster Import" with Clever SHOULD be turned off.

[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)

- _Rationale:_ If an organization does not use Clever, allowing roster imports could create a way for unauthorized data to be incorporated into the organization's environment. If an organization does use Clever, then roster imports may be enabled.
- _Last modified:_ September 2023
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ CM-7
- MITRE ATT&CK TTP Mapping
  - [T1199: Trusted Relationship](https://attack.mitre.org/techniques/T1199/)

### Resources

-   [Google Workspace Admin Help: Get Started with SIS Roster Import](https://support.google.com/edu/classroom/answer/10495270?visit_id=638337540290677144-1371568967&p=sis_overview&rd=1)

### Prerequisites

-   None

### Implementation
To configure the settings for Roster Import:

#### GWS.CLASSROOM.3.1v1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Additional Google Service** -\> **Classroom**.
3.  Select **Roster import**.
4.  Select **off**.
5.  Select **Save**.

## 4. Student Unenrollment

This section covers policies related to unenrolling a student from a class.

### Policies

#### GWS.CLASSROOM.4.1v1
Only teachers SHOULD be allowed to unenroll students from classes.

[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)

- _Rationale:_ Allowing students to unenroll themselves from classes within Google Classroom creates the opportunity for data loss or other inconsistencies, especially for K-12 classrooms. Restricting this ability to teachers mitigates this risk.
- _Last modified:_ September 2023
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ AC-6(10)
- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

### Resources

-   [Google Workspace Admin Help: Control Student Unenrollment Settings](https://support.google.com/edu/classroom/answer/11189334?visit_id=638326465630147042-2696822563&p=student_unenrollment&rd=1)

### Prerequisites

-   None

### Implementation
To configure the settings for Student Unenrollment:

#### GWS.CLASSROOM.4.1v1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Additional Google Service** -\> **Classroom**.
3.  Select **Student unenrollment**.
4.  Select **Teachers only**.
5.  Select **Save**.

## 5. Class Creation

When first-time users sign in to Classroom, they self-identify as either a student or a teacher. Users who identify as teachers will be marked as a "pending teacher" until an administrator verifies their identity. Google Classroom allows administrators to restrict class creation to only verified teachers.

### Policies

#### GWS.CLASSROOM.5.1v1
Class creation SHOULD be restricted to verified teachers only.

[![Automated Check](https://img.shields.io/badge/Automated_Check-5E9732)](#key-terminology)

- _Rationale:_ Allowing "pending teachers" to create classes could potentially allow students to impersonate teachers. This could result in exploiting the trusted relationship between teacher and student, such as if the role was used to phish sensitive information from other students. Restricting class creation to verified teachers reduces this risk.
- _Last modified:_ June 2024
- _NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping:_ AC-6(5), AC-6(10)
- MITRE ATT&CK TTP Mapping
  - [T1656: Impersonation](https://attack.mitre.org/techniques/T1656/)
  - [T534: Internal Spearphishing](https://attack.mitre.org/techniques/T1534/)
  - [T1598: Phishing for Information](https://attack.mitre.org/techniques/T1598/)
    - [T1598:002: Phishing for Information: Spearphishing Attachment](https://attack.mitre.org/techniques/T1598/002/)
    - [T1598:003: Phishing for Information: Spearphishing Link](https://attack.mitre.org/techniques/T1598/003/)
    - [T1598:004: Phishing for Information: Spearphishing Voice](https://attack.mitre.org/techniques/T1598/004/)

### Resources

-   [Verify teachers and set permissions](https://support.google.com/edu/classroom/answer/6071551?hl=en)

### Prerequisites

-   None

### Implementation
To configure the settings for Class Creation:

#### GWS.CLASSROOM.5.1v1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Additional Google Service** -\> **Classroom**.
3.  Select **General settings**.
4.  Select **Teacher permissions**.
5.  Select **Verified teachers only** for **Who can create classes?**
6.  Select **Save**.
