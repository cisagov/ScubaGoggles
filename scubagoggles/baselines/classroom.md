# CISA Google Workspace Secure Configuration Baseline for Google Classroom

Google Classroom is a service to streamline assignments, boost collaboration, and foster communication. This service allows for the creation of classes, creating and grading assignments, student collaboration, communication with teachers and students, and integration with other Google products.

Google Classroom is designed and intended for implementation for Education Institutions. Google Classroom is available with the Google Workspace for Education Edition, and is included with all tiers of GWS for Education including Fundamentals, Standard, and Plus. CISA's Secure Configuration Baseline Classroom policies and guidance are written to the Plus edition.

The Secure Cloud Business Applications (SCuBA) project, run by the Cybersecurity and Infrastructure Security Agency (CISA), provides guidance and capabilities to secure federal civilian executive branch (FCEB) agencies' cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments.

The CISA SCuBA SCBs for GWS help secure federal information assets stored within GWS cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government's threats and risk tolerance. Organizations outside of the Federal Government may also find these baselines to be useful references to help reduce risks even if such organizations have different risk tolerances or face different threats.

For non-Federal users, the information in this document is being provided "as is" for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or favoritism by CISA. Without limiting the generality of the foregoing, some controls and settings are not available in all products; CISA has no control over vendor changes to products offerings or features. Accordingly, these SCuBA SCBs for GWS may not be applicable to the products available to you. This document does not address, ensure compliance with, or supersede any law, regulation, or other authority. Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology. This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

This baseline is based on Google documentation available at [Google Workspace Admin Help: Classroom](https://support.google.com/edu/classroom/?hl=en#topic=10298088) and addresses the following:

-   [Class Membership](#1-class-membership)
-   [Classroom API](#2-classroom-api)
-   [Roster Import](#3-roster-import)
-   [Student Unenrollment](#4-student-unenrollment)
-   [Class Creation](#5-class-creation)

Settings can be assigned to certain users within Google Workspace through organizational units, configuration groups, or individually. Before changing a setting, the user can select the organizational unit, configuration group, or individual users to which they want to apply changes.

## Assumptions

This document assumes the organization is using GWS Education Plus.

This document does not address, ensure compliance with, or supersede any law, regulation, or other authority.  Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology.  This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

## Key Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

# Baseline Policies

## 1. Class Membership

This section covers who has the ability to join classes and what classes the users in your domain can join.

### Policies

#### GWS.CLASSROOM.1.1v0.5
Who can join classes in your domain SHALL be set to Users in your domain only.

- _Rationale:_ Classes can contain private or otherwise sensitive information. Restricting classes to users in your domain helps prevent data leakage resulting from unauthorized classroom access.
- _Last modified:_ September 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)

#### GWS.CLASSROOM.1.2v0.5
Which classes users in your domain can join SHALL be set to Classes in your domain only.

- _Rationale:_ Allowing users to join a class from outside your domain could allow for data to be exfiltrated to entities outside the control of the organization creating a significant security risk.
- _Last modified:_ January 2025

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
3.  Select **Class Settings**.
4.  Select **About Class Membership**.

#### GWS.CLASSROOM.1.1v0.5 Instructions
1.  For **Who can join classes in your domain**, select **Users in your domain only**.
2.  Select **Save**.

#### GWS.CLASSROOM.1.2v0.5 Instructions
1.  For **Which classes can users in your domain join**, select **Classes in your domain only**.
2.  Select **Save**.

## 2. Classroom API

This section covers policies related to the Google Classroom API.

### Policies

#### GWS.CLASSROOM.2.1v0.5
Users SHALL NOT be able to authorize apps to access their Google Classroom data.

- _Rationale:_ Allowing ordinary users to authorize apps to have access to classroom data opens a possibility for data loss. Allowing only admins to authorize apps reduces this risk.
- _Last modified:_ September 2023

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

#### GWS.CLASSROOM.2.1v0.5 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Additional Google Service** -\> **Classroom**.
3.  Select **Data Access**.
4.  Uncheck **Users can authorize apps to access their Google Classroom data**.
5.  Select **Save**.

## 3. Roster Import

This section covers policies related to importing rosters from Clever.

### Policies

#### GWS.CLASSROOM.3.1v0.5
Roster import with Clever SHOULD be turned off.

- _Rationale:_ If your organization does not use Clever, allowing roster imports could create a way for unauthorized data to be inputted into your organization's environment. If your organization does use Clever, then roster imports may be enabled.
- _Last modified:_ September 2023

- MITRE ATT&CK TTP Mapping
  - [T1199: Trusted Relationship](https://attack.mitre.org/techniques/T1199/)

### Resources

-   [Google Workspace Admin Help: Get Started with SIS Roster Import](https://support.google.com/edu/classroom/answer/10495270?visit_id=638337540290677144-1371568967&p=sis_overview&rd=1)

### Prerequisites

-   None

### Implementation
To configure the settings for Roster Import:

#### GWS.CLASSROOM.3.1v0.5 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Additional Google Service** -\> **Classroom**.
3.  Select **Roster Import**.
4.  Select **OFF**.
5.  Select **Save**.

## 4. Student Unenrollment

This section covers policies related to unenrolling a student from a class.

### Policies

#### GWS.CLASSROOM.4.1v0.5
Only teachers SHALL be allowed to unenroll students from classes.

- _Rationale:_ Allowing students to unenroll themselves creates the opportunity for data loss or other inconsistencies, especially for K-12 classrooms. Restricting this ability to teachers mitigates this risk.
- _Last modified:_ September 2023

- MITRE ATT&CK TTP Mapping
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

### Resources

-   [Google Workspace Admin Help: Control Student Unenrollment Settings](https://support.google.com/edu/classroom/answer/11189334?visit_id=638326465630147042-2696822563&p=student_unenrollment&rd=1)

### Prerequisites

-   None

### Implementation
To configure the settings for Student Unenrollment:

#### GWS.CLASSROOM.4.1v0.5 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Additional Google Service** -\> **Classroom**.
3.  Select **Student unenrollment**.
4.  Select **Teachers Only**.
5.  Select **Save**.

## 5. Class Creation

The first time users sign in to Classroom, they self-identify as either a student or teacher. Users who identify as teachers will be marked as a pending teacher until an administrator verifies them. Google Classroom allows administrators to restrict class creation to only verified teachers.

### Policies

#### GWS.CLASSROOM.5.1v0.5
Class creation SHALL be restricted to verified teachers only.

- _Rationale:_ Allowing pending teachers to create classes potentially allows students to impersonate teachers and exploit the trusted relationship between teacher and student, e.g., to phish sensitive information from the students. Restricting class creation to verified teachers reduces this risk.
- _Last modified:_ June 2024

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

#### GWS.CLASSROOM.5.1v0.5 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps** -\> **Additional Google Service** -\> **Classroom**.
3.  Select **General Settings**.
4.  Select **Teacher permissions**.
5.  Select **Verified teachers only** for **Who can create classes?**
5.  Select **Save**.
