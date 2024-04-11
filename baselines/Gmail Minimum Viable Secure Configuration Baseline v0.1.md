# CISA Google Workspace Security Configuration Baseline for Gmail

Gmail is the Google Workspace offering for sending and receiving email. Users can upload attachments to emails and send them to a given email address. Additional Gmail features include integrating with other Google applications, such as Meet and Chat. This Secure Configuration Baseline (SCB) provides specific policies to strengthen Gmail security.

The Secure Cloud Business Applications (SCuBA) project provides guidance and capabilities to secure agencies' cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments. The SCuBA Secure Configuration Baselines (SCB) for Google Workspace (GWS) will help secure federal civilian executive branch (FCEB) information assets stored within GWS cloud environments through consistent, effective, modern, and manageable security configurations.

The CISA SCuBA SCBs for GWS help secure federal information assets stored within GWS cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government's threats and risk tolerance with the knowledge that every organization has different threat models and risk tolerance. Non-governmental organizations may also find value in applying these baselines to reduce risks.

The information in this document is being provided "as is" for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or favoritism by CISA.

This baseline is based on Google documentation available at the [Gmail Google Workspace Admin Help Center](https://support.google.com/a/topic/9202?hl=en&ref_topic=9197) and addresses the following:.

- [Mail Delegation](#1-mail-delegation)
- [Domain Keys Identified Mail](#2-domainkeys-identified-mail)
- [Sender Policy Framework](#3-sender-policy-framework)
- [Domain Based Message Authentication, Reporting, and Conformance](#4-domain-based-message-authentication-reporting-and-conformance)
- [Attachment Protections](#5-attachment-protections)
- [Links and External Images Protections](#6-links-and-external-images-protection)
- [Spoofing and Authentication Protection](#7-spoofing-and-authentication-protection)
- [User Email Uploads](#8-user-email-uploads)
- [POP and IMAP Access](#9-pop-and-imap-access-for-users)
- [Workspace Sync](#10-google-workspace-sync)
- [Automatic Forwarding](#11-automatic-forwarding)
- [Per User Outbound Gateways](#12-per-user-outbound-gateways)
- [Unintended External Reply Warning](#13-unintended-external-reply-warning)
- [Email Allowlist](#14-email-allowlist)
- [Enhanced Pre-Delivery Message Scanning](#15-enhanced-pre-delivery-message-scanning)
- [Security Sandbox](#16-security-sandbox)
- [Comprehensive Mail Storage](#17-comprehensive-mail-storage)
- [Content Compliance Filtering](#18-content-compliance-filtering)
- [Spam Filtering](#19-spam-filtering)


Within Google Workspace, settings can be assigned to users through organizational units, configuration groups, or individually. Before changing a setting, the user can select the organizational unit, configuration group, or individual users to which they want to apply changes.

## Assumptions

This document assumes the organization is using GWS Enterprise Plus.

This document does not address, ensure compliance with, or supersede any law, regulation, or other authority.  Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology.  This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

## Key Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

# Baseline Policies

## 1. Mail Delegation

This section determines whether users can delegate access to their mailbox to others within the same domain. This delegation includes access to read, send, and delete messages on the account owner's behalf. This delegation can be done via a command line tool (GAM) if enabled in the admin console.

### Policies

#### GWS.GMAIL.1.1v0.1
Mail Delegation SHOULD be disabled.

- _Rationale:_ Granting mail delegation can inadvertently lead to disclosure of sensitive information, impersonation of delegated accounts, or malicious alteration or deletion of emails. By controlling mail delegation, these risks can be significantly reduced, ensuring the security and integrity of email communications.
- _Last modified:_ October 4, 2023
- _Note:_ Exceptions should be limited to individuals authorized by existing Agency policy, such as SES or Politically Appointed staff. Other considerations include ensuring that delegated accounts require Phishing-Resistant Multi-Factor Authentication (MFA), limiting delegated account permissions (ex. allowing view/reply but not delete), monitoring delegated accounts regularly, and disabling them if no longer required.

- MITRE ATT&CK TTP Mapping
  - [T098: Account Manipulation](https://attack.mitre.org/techniques/T1098/)
    - [T098:002: Account Manipulation: Additional Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002/)

### Resources

-   [Google Workspace Admin Help: Turn Gmail delegation on or off](https://support.google.com/a/answer/7223765?hl=en)
-   [GAM: Example Email Settings - Creating a Gmail delegate](https://github.com/GAM-team/GAM/wiki/ExamplesEmailSettings#creating-a-gmail-delegate)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   None

### Implementation

#### GWS.GMAIL.1.1v0.1 Instructions
To configure the settings for Mail Delegation:
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Gmail**.
3.  Select **User Settings -\> Mail delegation**.
4.  Ensure that the **Let users delegate access to their mailbox to other users in the domain** checkbox is unchecked.
5.  Select **Save**.


## 2. DomainKeys Identified Mail

This section enables DomainKeys Identified Mail (DKIM) to help prevent spoofing on outgoing messages sent from a specific domain. DKIM allows digital signatures to be added to email messages in the message header, providing a layer of both authenticity and integrity to emails. Without DKIM, messages that are sent from a specific domain are more likely to be marked as spam by receiving mail servers. DKIM relies on Domain Name System (DNS) records, thus, its deployment depends on how an agency manages its DNS.

### Policies

#### GWS.GMAIL.2.1v0.1
DKIM SHOULD be enabled for all domains.

- _Rationale:_ Enabling DKIM for all domains can help prevent email spoofing and phishing attacks. Without DKIM, adversaries could manipulate email headers to appear as if they're from a legitimate source, potentially leading to the disclosure of sensitive information. By enabling DKIM, the authenticity of emails can be verified, reducing this risk.
- _Last modified:_ November 13, 2023

- MITRE ATT&CK TTP Mapping
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
  - [T1434: Internal Spear Phishing](https://attack.mitre.org/techniques/T1434/)

### Resources

-   [Binding Operational Directive 18-01 - Enhance Email and Web Security \| DHS](https://cyber.dhs.gov/bod/18-01/)
-   [Trustworthy Email \| NIST 800-177 Rev. 1](https://csrc.nist.gov/publications/detail/sp/800-177/rev-1/final)
-   [Google Workspace Admin Help: Help prevent spoofing and spam with DKIM](https://support.google.com/a/answer/174124)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   None

### Implementation

#### GWS.GMAIL.2.1v0.1 Instructions
To configure the settings for DKIM:
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Gmail**.
3.  Select **Authenticate email -\> DKIM authentication**.
4.  Select a domain listed in the **Selected** domain drop-down menu.
5.  Select **START AUTHENTICATION**.
6.  Select **Save**.
7.  Add the DNS TXT record listed in Admin Console to the domain, via the domain provider's DNS settings page. Note that it can take up to 48 hours for DNS changes to fully propagate.

Note that step 7 requires action taken outside of the Google Admin Console, dependent on the agency's domain provider. Thus, the exact final step needed to set up DKIM varies from agency to agency. See [Turn on DKIM for your domain](https://support.google.com/a/answer/180504) for more details.

To test your DKIM configuration, consider using a web-based tool, such as the [Google Admin Toolbox](https://toolbox.googleapps.com/apps/checkmx/).

## 3. Sender Policy Framework

The Sender Policy Framework (SPF) is a mechanism that allows administrators to specify which IP addresses are explicitly approved to send email on behalf of the domain, facilitating detection of spoofed emails. SPF isn't configured through the Google Admin Console, but rather via DNS records hosted by the agency's domain. Thus, the exact steps needed to set up SPF varies from agency to agency, but Google's documentation provides some helpful starting points.

### Policies

#### GWS.GMAIL.3.1v0.1
An SPF policy SHALL be published for each domain that fails all non-approved senders.

- _Rationale:_ Adversaries could potentially manipulate the 'FROM' field in an email to appear as a legitimate sender, increasing the risk of phishing attacks. By publishing an SPF policy for each domain that fails all non-approved senders, this risk can be reduced as it provides a means to detect and block such deceptive emails. Additionally, SPF is required for federal, executive branch, departments and agencies by Binding Operational Directive 18-01, "Enhance Email and Web Security."
- _Last modified:_ February 14, 2024
- _Note:_ SPF defines two different "fail" mechanisms: fail (indicated by `-`, sometimes referred to as hardfail) and softail (indicated by `~`). Fail, as used in this baseline policy, refers to hardfail (i.e., `-`). 

- MITRE ATT&CK TTP Mapping
  - [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)
    - [T1078:004: Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
    - [T1566:003: Phishing: Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/)

### Resources

-   [Binding Operational Directive 18-01 - Enhance Email and Web Security \| DHS](https://cyber.dhs.gov/bod/18-01/)
-   [Trustworthy Email \| NIST 800-177 Rev. 1](https://csrc.nist.gov/publications/detail/sp/800-177/rev-1/final)
-   [Google Workspace Admin Help: Help prevent spoofing and spam with SPF](https://support.google.com/a/answer/33786#to-do)

### Prerequisites
-   A list of approved IP addresses for sending mail must be maintained. Failing to maintain an accurate list of authorized IP addresses may result in spoofed email messages or failure to deliver legitimate messages when SPF is enabled. Maintaining such a list helps ensure that unauthorized servers sending spoofed messages can be detected, and permits message delivery from legitimate senders.

### Implementation

#### GWS.GMAIL.3.1v0.1 Instructions
First, identify any approved senders specific to your agency (see [Identify all email senders for your organization](https://support.google.com/a/answer/10686639#senders) for tips). SPF allows you to indicate approved senders by IP address or CIDR range. However, note that SPF allows you to [include](https://www.rfc-editor.org/rfc/rfc7208#section-5.2) the IP addresses indicated by a separate SPF policy, refered to by domain name. See [Define your SPF record—Basic setup](https://support.google.com/a/answer/10685031) for inclusions required for Google to send email on behalf of your domain.

SPF is not configured through the Google Workspace admin center, but rather via DNS records hosted by the agency's domain. Thus, the exact steps needed to set up SPF varies from agency to agency. See [Add your SPF record at your domain provider](https://support.google.com/a/answer/10684623) for more details.

To test your SPF configuration, consider using a web-based tool, such as the [Google Admin Toolbox](https://toolbox.googleapps.com/apps/checkmx/).  Additionally, SPF records can be requested using the command line tool `dig`. For example:
```
dig example.com txt
```
If SPF is configured, a response resembling `v=spf1 include:_spf.google.com -all` will be returned; though by necessity, the contents of the SPF policy may vary by agency. In this example, the SPF policy indicates the IP addresses listed by the policy for "_spf.google.com" are the only approved senders for "example.com." These IPs can be determined via additional SPF lookups, starting with "_spf.google.com."

Ensure the IP addresses listed as approved senders for your domains are correct. Additionally, ensure that each policy either ends in `-all` or [redirects](https://www.rfc-editor.org/rfc/rfc7208#section-6.1) to one that does; this directive indicates that all IPs that don't match the policy should fail. See [Define your SPF record—Advanced setup](https://support.google.com/a/answer/10683907) for a more in-depth discussion of SPF record syntax.

## 4. Domain-based Message Authentication, Reporting, and Conformance


Domain-based Message Authentication, Reporting, and Conformance (DMARC) works with SPF and DKIM to authenticate mail senders and ensure that destination email systems can validate messages sent from your domain. DMARC helps receiving mail systems determine what to do with messages sent from your domain that fail SPF or DKIM checks.

### Policies

#### GWS.GMAIL.4.1v0.1
A DMARC policy SHALL be published for every second-level domain.

- _Rationale:_ Without proper authentication and a DMARC policy available for each domain, recipients may improperly handle SPF and DKIM failures, possibly enabling adversaries to send deceptive emails that appear to be from your domain. By publishing a DMARC policy for every second-level domain, this risk can be reduced by publishing how authentication failures should be handled. 
- _Last modified:_ November 13, 2023

- MITRE ATT&CK TTP Mapping
  - None

#### GWS.GMAIL.4.2v0.1
The DMARC message rejection option SHALL be p=reject.

- _Rationale:_ Without stringent email authentication, adversaries could potentially send deceptive emails that appear to be from your domain, increasing the risk of phishing attacks. This policy reduces risk as it ensures that emails failing SPF or DKIM checks are automatically rejected, preventing potentially harmful emails from reaching recipients. Additionally, "reject" is the level of protection required by BOD 18-01, "Enhance Email and Web Security," for federal, executive branch, departments and agencies.
- _Last modified:_ November 13, 2023

- MITRE ATT&CK TTP Mapping
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
    - [T1566:003: Phishing: Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/)
  - [T1586:002: Compromise Accounts](https://attack.mitre.org/techniques/T1586/)
    - [T1586:002: Compromise Accounts: Email Accounts](https://attack.mitre.org/techniques/T1586/002/)

#### GWS.GMAIL.4.3v0.1
The DMARC point of contact for aggregate reports SHALL include `reports@dmarc.cyber.dhs.gov`.

- _Rationale:_ Without a centralized point of contact for DMARC aggregate reports, potential email security issues may go unnoticed, increasing the risk of phishing attacks. By including reports@dmarc.cyber.dhs.gov as the DMARC point of contact, this risk can be reduced by ensuring a streamlined process for CISA to monitor and address email authentication issues, enhancing overall email security as required by BOD 18-01 for federal, executive branch, departments and agencies.
- _Last modified:_ November 13, 2023
- _Note:_ Only federal, executive branch, departments and agencies should include this email address in their DMARC record.

- MITRE ATT&CK TTP Mapping
  - None

#### GWS.GMAIL.4.4v0.1
An agency point of contact SHOULD be included for aggregate and failure reports.

- _Rationale:_ Without a designated agency point of contact for DMARC aggregate and failure reports, potential email security issues may not be promptly addressed, increasing the risk of phishing attacks. By including an agency point of contact, this risk can be reduced as it facilitates a timely response to email authentication issues, enhancing overall email security.
- _Last modified:_ November 13, 2023

- MITRE ATT&CK TTP Mapping
  - None

### Resources

-   [Binding Operational Directive 18-01 - Enhance Email and Web Security \| DHS](https://cyber.dhs.gov/bod/18-01/)
-   [Trustworthy Email \| NIST 800-177 Rev. 1](https://csrc.nist.gov/publications/detail/sp/800-177/rev-1/final)
-   [Domain-based Message Authentication, Reporting, and Conformance (DMARC) \| RFC 7489](https://datatracker.ietf.org/doc/html/rfc7489)
-   [Google Workspace Admin Help: Help prevent spoofing and spam with DMARC](https://support.google.com/a/answer/2466580)

### Prerequisites

-   DKIM or SPF must be enabled

### Implementation

#### GWS.GMAIL.4.1v0.1 Instructions
DMARC is not configured through the Google Admin Console, but rather via DNS records hosted by the agency's domain(s). As such, implementation varies depending on how an agency manages its DNS records. See [Add your DMARC record](https://support.google.com/a/answer/2466563) for Google guidance.

Note, a DMARC record published at the second-level domain will protect all subdomains. In other words, a DMARC record published for `example.com` will protect both `a.example.com` and `b.example.com`, but a separate record would need to be published for `c.example.gov`.

To test your DMARC configuration, consider using one of many publicly available web-based tools, such as the [Google Admin Toolbox](https://toolbox.googleapps.com/apps/checkmx/). Additionally, DMARC records can be requested using the command line tool `dig`. For example:

```
dig _dmarc.example.com txt
```

If DMARC is configured, a response resembling `v=DMARC1; p=reject; pct=100; rua=mailto:reports@dmarc.cyber.dhs.gov, mailto:reports@example.com; ruf=mailto:reports@example.com` will be returned, though by necessity, the contents of the record will vary by agency. In this example, the policy indicates all emails failing the SPF/DKIM checks are to be rejected and aggregate reports sent to reports@dmarc.cyber.dhs.gov and reports@example.com. Failure reports will be sent to reports@example.com.

#### GWS.GMAIL.4.2v0.1 Instructions
See [GWS.GMAIL.4.1v1](#gwsgmail41v01-instructions) instructions for an overview of how to publish and check a DMARC record. Ensure the record published includes `p=reject`.

#### GWS.GMAIL.4.3v0.1 Instructions
See [GWS.GMAIL.4.1v1](#gwsgmail41v01-instructions) instructions for an overview of how to publish and check a DMARC record. Ensure the record published includes reports@dmarc.cyber.dhs.gov as one of the emails for the `rua` field.

#### GWS.GMAIL.4.4v0.1 Instructions
See [GWS.GMAIL.4.1v1](#gwsgmail41v01-instructions) instructions for an overview of how to publish and check a DMARC record. Ensure the record published includes a point of contact specific to your agency, in addition to reports@dmarc.cyber.dhs.gov, as one of the emails for the `rua` field and one or more agency-defined points of contact for the `ruf` field.

## 5. Attachment Protections

This section enables protections against suspicious attachments and scripts from untrusted senders, to include encrypted attachments, documents with malicious scripts, and attachment file types that are uncommon and/or archaic. Through these attachments malware can be spread. These messages can be kept in the inbox with a warning label (default), moved to spam, or quarantined.

A Google Workspace solution is not strictly required to satisfy this baseline control, but the solution selected by an agency should offer services comparable to those offered by Google.

### Policies

#### GWS.GMAIL.5.1v0.1
Protect against encrypted attachments from untrusted senders SHALL be enabled.

- _Rationale:_ Attachments from untrusted senders, especially encrypted ones, may contain malicious content that poses a security risk. By enabling protection against encrypted attachments from untrusted senders, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
    - [T1566:003: Phishing: Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/)
  - [T1204: User Execution](https://attack.mitre.org/techniques/T1204/)
    - [T1204:001: User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)
    - [T1204:002: User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
    - [T1204:003: User Execution: Malicious Image](https://attack.mitre.org/techniques/T1204/003/)

#### GWS.GMAIL.5.2v0.1
Protect against attachments with scripts from untrusted senders SHALL be enabled.

- _Rationale:_ Attachments with scripts from untrusted senders may contain malicious content that poses a security risk. By enabling protection against such attachments, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
    - [T1566:003: Phishing: Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/)
  - [T1204: User Execution](https://attack.mitre.org/techniques/T1204/)
    - [T1204:001: User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)
    - [T1204:002: User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
    - [T1204:003: User Execution: Malicious Image](https://attack.mitre.org/techniques/T1204/003/)

#### GWS.GMAIL.5.3v0.1
Protect against anomalous attachment types in emails SHALL be enabled.

- _Rationale:_ Anomalous attachment types in emails may contain malicious content that poses a security risk. By enabling protection against such attachments, this risk can be reduced, enhancing the safety and integrity of the user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
    - [T1566:003: Phishing: Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/)
  - [T1204: User Execution](https://attack.mitre.org/techniques/T1204/)
    - [T1204:001: User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)
    - [T1204:002: User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
    - [T1204:003: User Execution: Malicious Image](https://attack.mitre.org/techniques/T1204/003/)

#### GWS.GMAIL.5.4v0.1
Google SHOULD be allowed to automatically apply future recommended settings for attachments.

- _Rationale:_ By enabling this feature, the system can automatically stay updated with the latest security measures recommended by Google, reducing the risk of security breaches.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - None

#### GWS.GMAIL.5.5v0.1
Emails flagged by the above attachment protection controls SHALL NOT be kept in inbox.

- _Rationale:_ Keeping emails flagged by attachment protection controls in the inbox could potentially expose users to malicious content. By ensuring such emails are not kept in the inbox, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ September 8, 2023
- _Note:_ Agencies and Organizations can choose whether to send email to spam or quarantine. Applies to Policies 5.1 - 5.3.

- MITRE ATT&CK TTP Mapping
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
    - [T1566:003: Phishing: Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/)
  - [T1204: User Execution](https://attack.mitre.org/techniques/T1204/)
    - [T1204:001: User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)
    - [T1204:002: User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
    - [T1204:003: User Execution: Malicious Image](https://attack.mitre.org/techniques/T1204/003/)


#### GWS.GMAIL.5.6v0.1
Any third-party or outside application selected for attachment protection SHOULD offer services comparable to those offered by Google Workspace.

- _Rationale:_ Using third-party or outside applications for attachment protection that do not offer services comparable to those offered by Google Workspace could potentially expose users to security risks. By ensuring that selected applications offer comparable services, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - None


### Resources

-   [Google Workspace Admin Help: Advanced phishing and malware protection](https://support.google.com/a/answer/9157861?product_name=UnuFlow&hl=en&visit_id=637831282628458101-2078141803&rd=1&src=supportwidget0&hl=en#zippy=%2Cturn-on-attachment-protection)

### Prerequisites

-   N/A

### Implementation

To configure the settings for Attachment Protections:

#### Policies Group 5 common Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Gmail**.
3.  Select **Safety -\> Attachments**.
4.  Follow implementation for each individual policy
5.  Select **Save**.

#### GWS.GMAIL.5.1v0.1 Instructions
1.  Check the **Protect against encrypted attachments from untrusted senders** checkbox.

#### GWS.GMAIL.5.2v0.1 Instructions
1.  Check the **Protect against attachments with scripts from untrusted senders** checkbox.

#### GWS.GMAIL.5.3v0.1 Instructions
1Ok.  Check the **Protect against anomalous attachment types in emails** checkbox

#### GWS.GMAIL.5.4v0.1 Instructions
1.  Check the **Apply future recommended settings automatically** checkbox.

#### GWS.GMAIL.5.5v0.1 Instructions
1.  Under the setting for Policy 5.1 through Policy 5.3, ensure either "Move email to spam" or "Quarantine" is selected.



#### GWS.GMAIL.5.6v0.1 Instructions
1.  No implementation steps for this policy


## 6. Links and External Images Protection

This section enables extra protections to prevent email phishing due to links and external images. Specific settings for this control include identifying hidden malicious links behind shortened URLs, scanning linked images to find hidden malicious content, showing a warning prompt when clicking links to untrusted domains, and applying future recommended settings automatically.

A Google Workspace solution is not strictly required to satisfy this baseline control, but the solution selected by an agency should offer services comparable to those offered by Google.

### Policies

#### GWS.GMAIL.6.1v0.1
Identify links behind shortened URLs SHALL be enabled.

- _Rationale:_ Shortened URLs can potentially hide malicious links, posing a security risk. By enabling the identification of links behind shortened URLs, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1434: Internal Spearphishing](https://attack.mitre.org/techniques/T1434/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
  - [T1204: User Execution](https://attack.mitre.org/techniques/T1204/)
    - [T1204:001: User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)

#### GWS.GMAIL.6.2v0.1
Scan linked images SHALL be enabled.

- _Rationale:_ Linked images in emails can potentially contain malicious content, posing a security risk. By enabling the scanning of linked images, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1434: Internal Spearphishing](https://attack.mitre.org/techniques/T1434/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
  - [T1204: User Execution](https://attack.mitre.org/techniques/T1204/)
    - [T1204:002: User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)

#### GWS.GMAIL.6.3v0.1
Show warning prompt for any click on links to untrusted domains SHALL be enabled.

- _Rationale:_ Clicking on links to unfamiliar domains can potentially expose users to malicious content, posing a security risk. By enabling a warning prompt for any click on such links, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1434: Internal Spearphishing](https://attack.mitre.org/techniques/T1434/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
  - [T1204: User Execution](https://attack.mitre.org/techniques/T1204/)
    - [T1204:001: User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)

#### GWS.GMAIL.6.4v0.1
Google SHALL be allowed to automatically apply future recommended settings for links and external images.

- _Rationale:_ By enabling this feature, the system can automatically stay updated with the latest recommended security measures from Google, reducing the risk of security breaches and enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - None

#### GWS.GMAIL.6.5v0.1
Any third-party or outside application selected for links and external images protection SHOULD offer services comparable to those offered by Google Workspace.

- _Rationale:_ Using third-party or outside applications for links and external images protection that do not offer services comparable to those offered by Google Workspace could potentially expose users to security risks. By ensuring that selected applications offer comparable services, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - None


### Resources

-   [Google Workspace Admin Help: Advanced phishing and malware protection](https://support.google.com/a/answer/9157861?product_name=UnuFlow&hl=en&visit_id=637831282628458101-2078141803&rd=1&src=supportwidget0&hl=en#zippy=%2Cturn-on-attachment-protection)
-   [Google Workspace Admin Help: Set up rules to detect harmful attachments](https://support.google.com/a/answer/7676854?product_name=UnuFlow&hl=en&visit_id=637831464632988595-2408633144&rd=1&src=supportwidget0&hl=en)
-   [Google Workspace Admin Help: Monitor the health of your Gmail settings](https://support.google.com/a/answer/7490901?product_name=UnuFlow&hl=en&visit_id=637831464698491311-452219641&rd=1&src=supportwidget0&hl=en)
-   [CIS Google Workspace Foundations Benchmark](https://www.cisecurity.org/benchmark/google_workspace)

### Prerequisites

-   N/A

### Implementation

To configure the settings for Links and External Images Protection:

#### Policies Group 6 common Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Gmail**.
3.  Select **Safety -\> Links and external images**.
4.  Follow implementation for each individual policy.
5.  Select **Save**

#### GWS.GMAIL.6.1v0.1 Instructions
1.  Check the **Identify links behind shortened URLs** checkbox.

#### GWS.GMAIL.6.2v0.1 Instructions
1.  Check the **Scan linked images** checkbox.

#### GWS.GMAIL.6.3v0.1 Instructions
1.  Check the **Show warning prompt for any click on links to untrusted domains** checkbox.

#### GWS.GMAIL.6.4v0.1 Instructions
1.  Check the **Apply future recommended settings automatically** checkbox.

#### GWS.GMAIL.6.5v0.1 Instructions
1.  No implementation steps for this policy


## 7. Spoofing and Authentication Protection

This control enables extra protections to prevent spoofing of a domain name, employee names, email pretending to be from a specific domain, and unauthenticated email from any domain. These messages can be kept in the inbox with a warning label (default), moved to spam, or quarantined.

A Google Workspace solution is not strictly required to satisfy this baseline control, but the solution selected by an agency should offer services comparable to those offered by Google.

### Policies

#### GWS.GMAIL.7.1v0.1
Protect against domain spoofing based on similar domain names SHALL be enabled.

- _Rationale:_ Emails sent from domains that look similar to your domain can potentially deceive users into interacting with malicious content, posing a security risk. By enabling protection against such spoofing, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1434: Internal Spearphishing](https://attack.mitre.org/techniques/T1434/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)

#### GWS.GMAIL.7.2v0.1
Protect against spoofing of employee names SHALL be enabled.

- _Rationale:_ Spoofing of employee identities (e.g., CEO and IT staff) can potentially deceive users into interacting with malicious content, posing a security risk. By enabling protection against such spoofing, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1434: Internal Spearphishing](https://attack.mitre.org/techniques/T1434/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)

#### GWS.GMAIL.7.3v0.1
Protect against inbound emails spoofing your domain SHALL be enabled.

- _Rationale:_ Inbound emails appearing to come from your domain can potentially deceive users into interacting with malicious content, posing a security risk. By enabling protection against such spoofing, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1434: Internal Spearphishing](https://attack.mitre.org/techniques/T1434/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)

#### GWS.GMAIL.7.4v0.1
Protect against any unauthenticated emails SHALL be enabled.

- _Rationale:_ Unauthenticated emails can potentially contain malicious content, posing a security risk. By enabling protection against such emails, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1434: Internal Spearphishing](https://attack.mitre.org/techniques/T1434/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)

#### GWS.GMAIL.7.5v0.1
Protect your Groups from inbound emails spoofing your domain SHALL be enabled.

- _Rationale:_ Inbound emails spoofing your domain can potentially deceive users into interacting with malicious content, posing a security risk. By enabling protection against such spoofing, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1434: Internal Spearphishing](https://attack.mitre.org/techniques/T1434/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)

#### GWS.GMAIL.7.6v0.1
Emails flagged by the above spoofing and authentication controls SHALL NOT be kept in inbox.

- _Rationale:_ Keeping emails flagged by spoofing and authentication controls in the inbox could potentially expose users to malicious content. By ensuring such emails are not kept in the inbox, this risk can be reduced, enhancing the safety and integrity of the user's data and systems.
- _Last modified:_ September 8, 2023
- _Note:_ Agencies and organizations can choose whether to send to spam or quarantine. This policy applies to Policy 7.1 - Policy 7.5

- MITRE ATT&CK TTP Mapping
  - [T1434: Internal Spearphishing](https://attack.mitre.org/techniques/T1434/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)


#### GWS.GMAIL.7.7v0.1
Google SHALL be allowed to automatically apply future recommended settings for spoofing and authentication.

- _Rationale:_ By enabling this feature, the system can automatically stay updated with the latest recommended security measures from Google, reducing the risk of security breaches and enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1434: Internal Spearphishing](https://attack.mitre.org/techniques/T1434/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)

#### GWS.GMAIL.7.8v0.1
Any third-party or outside application selected for spoofing and authentication protection SHOULD offer services comparable to those offered by Google Workspace.

- _Rationale:_ Using third-party or outside applications for spoofing and authentication protection that do not offer services comparable to those offered by Google Workspace could potentially expose users to security risks. By ensuring that selected applications offer comparable services, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1434: Internal Spearphishing](https://attack.mitre.org/techniques/T1434/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)

### Resources

-   [Google Workspace Admin Help: Advanced phishing and malware protection](https://support.google.com/a/answer/9157861?product_name=UnuFlow&hl=en&visit_id=637831282628458101-2078141803&rd=1&src=supportwidget0&hl=en#zippy=%2Cturn-on-attachment-protection)

### Prerequisites

-   N/A

### Implementation

To configure the settings for Spoofing and Authentication Protection:

#### Policies Group 7 common Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Gmail**.
3.  Select **Safety -\> Spoofing and authentication**.
4.  Follow steps for individual policies below.
5.  Select **Save**

#### GWS.GMAIL.7.1v0.1 Instructions
1.  Check the **Protect against domain spoofing based on similar domain names** checkbox.

#### GWS.GMAIL.7.2v0.1 Instructions
1.  Check the **Protect against spoofing of employee names** checkbox.

#### GWS.GMAIL.7.3v0.1 Instructions
1.  Check the **Protect against inbound emails spoofing your domain** checkbox.

#### GWS.GMAIL.7.4v0.1 Instructions
1.  Check the **Protect against any unauthenticated emails** checkbox.

#### GWS.GMAIL.7.5v0.1 Instructions
1.  Check the **Protect your groups from inbound emails spoofing your domain** checkbox.

#### GWS.GMAIL.7.6v0.1 Instructions
1.  Under each setting from Policy 7.1 through Policy 7.5, make sure either "Move email to spam" or "Quarantine" is selected.


#### GWS.GMAIL.7.7v0.1 Instructions
1.  Check the **Apply future recommended settings automatically** checkbox.

#### GWS.GMAIL.7.8v0.1 Instructions
1.  There is no implementation for this policy.


## 8. User Email Uploads

This section addresses a feature that enables users to import their email and contacts from non-Google webmail accounts such as Yahoo!, Hotmail, or AOL.

### Policies

#### GWS.GMAIL.8.1v0.1
User email uploads SHALL be disabled to protect against unauthorized files being introduced into the secured environment.

- _Rationale:_ Allowing user email uploads could potentially introduce unauthorized or malicious files into the secured environment, posing a security risk. By disabling user email uploads, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1199: Trusted Relationship](https://attack.mitre.org/techniques/T1199/)
  - [T1204: User Execution](https://attack.mitre.org/techniques/T1204/)
    - [T1204:001: User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)
    - [T1204:002: User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
    - [T1204:003: User Execution: Malicious Image](https://attack.mitre.org/techniques/T1204/003/)

### Resources

-   [Google Workspace Admin Help: Advanced Gmail settings reference for admins](https://support.google.com/a/answer/2786758#zippy=%2Csetup-settings)
-   [Google Workspace Admin Help: Turn imports from webmail hosts on or off](https://support.google.com/a/answer/2525613?product_name=UnuFlow&hl=en&visit_id=637832286168108072-385761693&rd=1&src=supportwidget0&hl=en)

### Prerequisites

-   N/A

### Implementation

To configure the settings for User Email Uploads:

#### GWS.GMAIL.8.1v0.1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Gmail**.
3.  Select **Setup -\> User email uploads**.
4.  Uncheck the **Show users the option to import mail and contacts from Yahoo!, Hotmail, AOL, or other webmail or POP3 accounts from the Gmail settings page** checkbox.
5.  Select **Save**.


## 9. POP and IMAP Access for Users

This section determines whether users have POP3 and IMAP access. Doing so allows the user to access Gmail emails from outside the context of protected/hardened environments and from older versions of Gmail applications or other third-party mail applications.

### Policies

#### GWS.GMAIL.9.1v0.1
POP and IMAP access SHALL be disabled to protect sensitive agency or organization emails from being accessed through legacy applications or other third-party mail clients.

- _Rationale:_ Enabling POP and IMAP access could potentially expose sensitive agency or organization emails to unauthorized access through legacy applications or third-party mail clients, posing a security risk. By disabling POP and IMAP access, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
    - [T1048:002: Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002/)

#### GWS.GMAIL.9.2v0.1
POP and IMAP access MAY be enabled on a per-user and per-application basis as needed.

- _Rationale:_ Enabling POP and IMAP access indiscriminately could potentially expose sensitive agency or organization emails to unauthorized access through legacy applications or third-party mail clients, posing a security risk. By only allowing POP and IMAP access on a per-user and per-application basis as needed, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
    - [T1048:001: Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/001/)
    - [T1048:002: Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002/)

### Resources

-   [Google Workspace Admin Help: Turn POP and IMAP on and off for users](https://support.google.com/a/answer/105694?hl=en)

### Prerequisites

-   N/A

### Implementation

To configure the settings for POP and IMAP access:

#### Policies Group 9 common Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Gmail**.
3.  Select **End User Access -\> POP and IMAP access**.
4.  Follow the implementation for each policy.
5.  Select **Save**.

#### GWS.GMAIL.9.1v0.1 Instructions
1.  Uncheck the **Enable IMAP access for all users** checkbox.

#### GWS.GMAIL.9.2v0.1 Instructions
1.  Uncheck the **Enable POP access for all users** checkbox.


## 10. Google Workspace Sync

This section determines whether Google Workspace Sync allows data synchronization between Google Workspace and Microsoft Outlook. The data includes email, calendar, and contacts. Data synchronizes each time users start Outlook. This is an additional plugin that must be downloaded.

### Policies

#### GWS.GMAIL.10.1v0.1
Google Workspace Sync SHOULD be disabled.

- _Rationale:_ Enabling Google Workspace Sync could potentially expose sensitive agency or organization data to unauthorized access or loss, posing a security risk. By disabling Google Workspace Sync, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
    - [T1048:001: Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/001/)
    - [T1048:002: Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002/)
    - [T1048:003: Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003/)
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1199: Trusted Relationship](https://attack.mitre.org/techniques/T1199/)

#### GWS.GMAIL.10.2v0.1
Google Workspace Sync MAY be enabled on a per-user basis as needed.

- _Rationale:_ Enabling Google Workspace Sync indiscriminately could potentially expose sensitive agency or organization data to unauthorized access or loss, posing a security risk. By only allowing Google Workspace Sync on a per-user basis as needed, this risk can be reduced, ensuring the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
    - [T1048:001: Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/001/)
    - [T1048:002: Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002/)
    - [T1048:003: Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003/)
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
  - [T1199: Trusted Relationship](https://attack.mitre.org/techniques/T1199/)

### Resources

-   [Google Workspace Sync for Microsoft Outlook](https://tools.google.com/dlpage/gssmo)

### Prerequisites

-   N/A

### Implementation

To configure the settings for Google Workspace Sync:

#### Policy Group 10 Common Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Gmail**.
3.  Select **End User Access -\> Google Workspace Sync**.

#### GWS.GMAIL.10.1v0.1 Instructions
1.  Uncheck the **Enable Google Workspace Sync for Microsoft Outlook for my users** checkbox.
2.  Select **Save**.

#### GWS.GMAIL.10.2v0.1 Instructions
1.  There is no implementation steps for this policy.
2.  Select **Save**.


## 11. Automatic Forwarding

This section determines whether emails can be automatically forwarded from a user's inbox to another of their choosing, possibly to external domains.

### Policies

#### GWS.GMAIL.11.1v0.1
Automatic forwarding SHOULD be disabled, especially to external domains.

- _Rationale:_ By enabling automatic forwarding, especially to external domains, adversaries could gain persistent access to a victim's email, potentially exposing sensitive agency or organization emails to unauthorized access or loss. By disabling automatic forwarding, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1114: Email Collection](https://attack.mitre.org/techniques/T1114/)
    - [T1114:003: Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/)

### Resources
-   [Google Workspace Admin Help: Disable automatic forwarding](https://support.google.com/a/answer/2491924?hl=en)

### Prerequisites

-   N/A

### Implementation

To configure the settings for Automatic Forwarding:

#### GWS.GMAIL.11.1v0.1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Gmail**.
3.  Select **End User Access -\> Automatic forwarding**.
4.  Uncheck the **Allow users to automatically forward incoming email to another address** checkbox.
5.  Select **Save**.

## 12. Per-user Outbound Gateways

This section determines whether outgoing mail is delivered only through the Google Workspace mail servers or another specified external SMTP server. With this setting, a user can choose which email address displays in the "From" field.

### Policies

#### GWS.GMAIL.12.1v0.1
Using a per-user outbound gateway that is a mail server other than the Google Workspace mail servers SHALL be disabled.

- _Rationale:_ Using a per-user outbound gateway that is a mail server other than the Google Workspace mail servers could potentially expose sensitive agency or organization emails to unauthorized access or loss, posing a security risk. By disabling this feature, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1114: Email Collection](https://attack.mitre.org/techniques/T1114/)
    - [T1114:002: Email Collection: Remote Email Collection](https://attack.mitre.org/techniques/T1114/002/)
  - [T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
    - [T1204:001: User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)
    - [T1204:002: User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002)

### Resources

-   [Google Workspace Admin Help: Allow per-user outbound gateways](https://support.google.com/a/answer/176054?hl=en#zippy=%2Cwhy-youd-disallow-use-of-an-outbound-gateway%2Cwhy-youd-allow-use-of-an-outbound-gateway)

### Prerequisites

-   N/A

### Implementation

To configure the settings for Per-user Outbound Gateways:

#### GWS.GMAIL.12.1v0.1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Gmail**.
3.  Select **End User Access -\> Allow per-user outbound gateways**.
4.  Uncheck the **Allow users to send mail through an external SMTP server when configuring a "from" address hosted outside your email domain** checkbox.
5.  Select **Save**.


## 13. Unintended External Reply Warning

This section determines whether users are prompted with a warning for messages that include external recipients (users with emails addresses that are outside of your organization). However, the warning is not shown if the external recipient is in the organization's Directory, personal Contacts, or other Contacts; or if a secondary domain or domain alias address is used.

### Policies

#### GWS.GMAIL.13.1v0.1
Unintended external reply warnings SHALL be enabled to avoid unintentional replies and remind users to treat external messages with caution.

- _Rationale:_ Without unintended external reply warnings, users may inadvertently reply to external messages, potentially exposing sensitive information. By enabling these warnings, users are reminded to treat external messages with caution, reducing this risk and enhancing the safety and integrity of user data and systems.
- _Last modified:_ July, 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
    - [T1566:003: Phishing: Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/)

### Resources

-   [Google Workspace Admin Help: Control Gmail external recipient warnings](https://support.google.com/a/answer/7380041?amp;ref_topic=9974443&product_name=UnuFlow&hl=en&ref_topic=9974443&visit_id=637832389706060412-548862041&rd=1&src=supportwidget0&hl=en)
-   [Capacity Enhancement Guide Counter-Phishing Recommendations for Federal Agencies \| CISA](https://www.cisa.gov/sites/default/files/publications/Capacity_Enhancement_Guide-Counter-Phishing_Recommendations_for_Federal_Agencies.pdf)
-   [Actions to Counter Email-Based Attacks on Election-Related Entities \| CISA](https://www.cisa.gov/sites/default/files/publications/CISA_Insights_Actions_to_Counter_Email-Based_Attacks_on_Election-Related_S508C.pdf)

### Prerequisites

-   N/A

### Implementation

To configure the settings to warn users of external recipients:

#### GWS.GMAIL.13.1v0.1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Gmail**.
3.  Select **End User Access -\> Warn for external recipients**.
4.  Check the **Highlight any external recipients in a conversation. Warn users before they reply to email with external recipients who aren't in their contacts** checkbox.
5.  Select **Save**.


## 14. Email Allowlist

This section determines whether an email allowlist allows for messages from certain IP addresses to not be marked as spam by Gmail. However, if implemented, emails from these senders will bypass important security mechanisms, such as SPF, DKIM, and DMARC.

### Policies

#### GWS.GMAIL.14.1v0.1
An email allowlist SHOULD not be implemented.

- _Rationale:_ Implementing an email allowlist could potentially expose users to security risks as allowlisted senders bypass important security mechanisms, including spam filtering and sender authentication checks. By not implementing an allowlist, this risk can be reduced, enhancing the safety and integrity of the user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1562: Impair Defenses](https://attack.mitre.org/techniques/T1562/)
    - [T1562:001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
    - [T1566:003: Phishing: Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/)

### Resources

-   [Google Workspace Admin Help: Add IP addresses to allowlists in Gmail](https://support.google.com/a/answer/60751?product_name=UnuFlow&hl=en&visit_id=637832433423162856-2822445044&rd=1&src=supportwidget0&hl=en)

### Prerequisites

-   N/A

### Implementation

To configure the settings for Email Allowlists:

#### GWS.GMAIL.14.1v0.1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Gmail**.
3.  Select **Spam, phishing, and malware -\> Email allowlist**.
4.  Under the **Enter the IP addresses for your email allowlist** field, ensure **no IP addresses** are listed.
5.  Select **Save**.

#### GWS.GMAIL.14.2v0.1 Instructions
1.  There is no implementation steps for this policy


## 15. Enhanced Pre-Delivery Message Scanning

This section determines whether Gmail can screen and identify suspicious content that may be phishing attempts. In doing so, Google can either show a warning or move the email to Spam, but email delivery will experience a short delay due to the additional checks.

A Google Workspace solution is not strictly required to satisfy this baseline control, but the solution selected by an agency should offer services comparable to those offered by Google.

### Policies

#### GWS.GMAIL.15.1v0.1
Enhanced pre-delivery message scanning SHALL be enabled to prevent phishing.

- _Rationale:_ Without enhanced pre-delivery message scanning, users may be exposed to phishing attempts, posing a security risk. By enabling this feature, potential phishing emails can be identified and blocked before reaching the user, reducing this risk and enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
    - [T1566:002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
    - [T1566:003: Phishing: Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/)

#### GWS.GMAIL.15.2v0.1
Any third-party or outside application selected for enhanced pre-delivery message scanning SHOULD offer services comparable to those offered by Google Workspace.

- _Rationale:_ Using third-party or outside applications for enhanced pre-delivery message scanning that do not offer services comparable to those offered by Google Workspace could potentially expose users to security risks. By ensuring that selected applications offer comparable services, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - None

### Resources

-   [Google Workspace Admin Help: Help prevent phishing with pre-delivery message scanning](https://support.google.com/a/answer/7380368?product_name=UnuFlow&hl=en&visit_id=637835839970922069-4253681586&rd=1&src=supportwidget0&hl=en)

### Prerequisites

-   N/A

### Implementation

To configure the settings for Enhanced Pre-Delivery Message Scanning:

#### GWS.GMAIL.15.1v0.1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Gmail**.
3.  Select **Spam, phishing, and malware -\> Enhanced pre-delivery message scanning**.
4.  Check the **Enables improved detection of suspicious content prior to delivery** checkbox.
5.  Select **Save**.

#### GWS.GMAIL.15.2v0.1 Instructions
1.  There is no implementation steps for this policy


## 16. Security Sandbox

This section determines whether certain messages and their associated attachments are executed in a sandbox environment for protection against malware, ransomware, and zero-day threats. Malicious software may be missed by traditional antivirus programs. However, this may cause some messages to get delayed before final delivery. Some of the file types scanned include Microsoft executables, Microsoft Office, PDF, and archives (zip, rar).

A Google Workspace solution is not strictly required to satisfy this baseline control, but the solution selected by an agency should offer services comparable to those offered by Google.

### Policies

#### GWS.GMAIL.16.1v0.1
Security sandbox SHOULD be enabled to provide additional protections for their email messages.

- _Rationale:_ Without a security sandbox, any emails with malicious content could potentially interact directly with the users' systems, posing a risk. By enabling the security sandbox, additional protections are provided for email messages, reducing this risk and enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)
    - [T1566:001: Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)

#### GWS.GMAIL.16.2v0.1
Any third-party or outside application selected for security sandbox SHOULD offer services comparable to those offered by Google Workspace.

- _Rationale:_ Using third-party or outside applications for security sandbox that do not offer services comparable to those offered by Google Workspace could potentially expose users to security risks. By ensuring that selected applications offer comparable services, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - None

### Resources

-   [Google Workspace Admin Help: Set up rules to detect harmful attachments](https://support.google.com/a/answer/7676854?amp;visit_id=637866938191629894-2885947509&amp;rd=1&product_name=UnuFlow&hl=en&visit_id=637866938191629894-2885947509&rd=2&src=supportwidget0&hl=en)

### Prerequisites

-   N/A

### Implementation

To configure the settings for Security sandbox or Security sandbox rules:

#### GWS.GMAIL.16.1v0.1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Gmail**.
3.  Select **Spam, phishing, and malware -\> Security sandbox**.
4.  Check the **Enable virtual execution of attachments in a sandbox environment for all the users of the Organizational Unit for protection against malware, ransomware, and zero-day threats** checkbox.
5.  Either **Security sandbox** or **Security sandbox rules** may be enabled but enabling **Security sandbox** takes precedence.
6.  If **Security sandbox** rules are enabled, then the configuration needs to be completed and consists of the following fields **:**
    1. A short description.
    2. Email messages to affect.
    3. Expressions to describe the content to search for in each message.
    4. Action to take if expressions match.
7. Select **Save**.

#### GWS.GMAIL.16.2v0.1 Instructions
1.  There is no implementation steps for this policy.

## 17. Comprehensive Mail Storage

This section allows for email messages sent through other Google Workspace applications, (i.e., Calendar, Drive, Docs, Sheets, Slides, Drawings, Forms, and Keep) to be stored in the associated users' Gmail mailboxes. This includes a copy of all sent or received messages within a specified domain (including messages sent or received by non-Gmail mailboxes).

### Policies

#### GWS.GMAIL.17.1v0.1
Comprehensive mail storage SHOULD be enabled to allow tracking of information across applications.

- _Rationale:_ Without comprehensive mail storage, tracking of information across applications could be compromised, posing a potential security risk. By enabling comprehensive mail storage, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ November 14, 2023

- MITRE ATT&CK TTP Mapping
  - None

### Resources

-   [Google Workspace Admin Help: Set up comprehensive mail storage](https://support.google.com/a/answer/3547347?product_name=UnuFlow&hl=en&visit_id=637835896823763789-338955802&rd=1&src=supportwidget0&hl=en)

### Prerequisites

-   N/A

### Implementation

To configure the settings for Comprehensive Mail Storage:

#### GWS.GMAIL.17.1v0.1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Gmail**.
3.  Select **Compliance -\> Comprehensive mail storage**.
4.  Check the **Ensure that a copy of all sent and received mail is stored in associated users' mailboxes** checkbox.
5.  Select **Save**.


## 18. Content Compliance Filtering

This section determines whether Gmail content is filtered based upon specified expressions, such as keyword, strings or patterns, and metadata. The compliance actions based upon the word lists are reject, quarantine, or deliver with modifications.

A Google Workspace solution is not strictly required to satisfy this baseline control, but the solution selected by an agency should offer services comparable to those offered by Google.

### Policies

#### GWS.GMAIL.18.1v0.1
Content filtering SHOULD be enabled within Gmail messages.

- _Rationale:_ Without content filtering, Gmail messages could potentially contain sensitive or private content, posing a security risk. By enabling content filtering, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1114: Email Collection](https://attack.mitre.org/techniques/T1114/)
    - [T1114:002: Email Collection: Remote Email Collection](https://attack.mitre.org/techniques/T1114/002/)

#### GWS.GMAIL.18.2v0.1
Any third-party or outside application selected for advanced email content filtering SHOULD offer services comparable to those offered by Google Workspace.

- _Rationale:_ Using third-party or outside applications for advanced email content filtering that do not offer services comparable to those offered by Google Workspace could potentially expose users to security risks. By ensuring that selected applications offer comparable services, this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - None

#### GWS.GMAIL.18.3v0.1
Gmail or third-party applications SHALL be configured to protect PII and sensitive information as defined by the agency. At a minimum, credit card numbers, taxpayer Identification Numbers (TIN), and Social Security Numbers (SSN) SHALL be blocked.

- _Rationale:_ Without proper configuration, Gmail or third-party applications could potentially expose PII and sensitive information, posing a security risk. By configuring these applications to block at least credit card numbers, Taxpayer Identification Numbers (TIN), and Social Security Numbers (SSN), this risk can be reduced, enhancing the safety and integrity of user data and systems.
- _Last modified:_ July 10, 2023

- MITRE ATT&CK TTP Mapping
  - [T1114: Email Collection](https://attack.mitre.org/techniques/T1114/)
    - [T1114:002: Email Collection: Remote Email Collection](https://attack.mitre.org/techniques/T1114/002/)
  - [T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
    - [T1048:001: Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/001/)
    - [T1048:002: Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002/)
  - [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

### Resources

-   [Google Workspace Admin Help: Set up rules for advanced email content filtering](https://support.google.com/a/answer/1346934?hl=en&ref_topic=9974692)
-   [Personally identifiable information (PII) \| NIST](https://csrc.nist.gov/glossary/term/personally_identifiable_information#:~:text=NISTIR%208259,2%20under%20PII%20from%20EGovAct)
-   [Sensitive information \| NIST](https://csrc.nist.gov/glossary/term/sensitive_information)

### Prerequisites

-   N/A

### Implementation

To configure the settings for Objectionable content:

#### GWS.GMAIL.18.1v0.1 Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Gmail**.
3.  Select **Compliance -\> Content Compliance**.
4.  If **Content compliance** filtering is enabled, then the configuration needs to be completed and consists of the following fields:
    1.  A short description.
    2.  Email messages to affect.
    3.  Expressions for content to search for in messages.
    4.  Compliance action options.
5.  Select **Save**.

#### GWS.GMAIL.18.2v0.1 Instructions
1.  There is no implementation steps for this policy.

#### GWS.GMAIL.18.3v0.1 Instructions
1.  There is no implementation steps for this policy.

## 19. Spam Filtering

This section covers the settings relating to bypassing spam filters.

### Policies

#### GWS.GMAIL.19.1v0.1
Domains SHALL NOT be added to lists that bypass spam filters.

- _Rationale:_ Allowing an entire domain to bypass the spam filters allows for the potential for a spoofed email within the domain to bypass the filter. Only allowing specific users to bypass helps mitigate the risk.
- _Last modified:_ April 10, 2024
- _Note:_ Allowed senders MAY be added.

- MITRE ATT&CK TTP Mapping
  - { Needs TTP Mappings }

#### GWS.GMAIL.19.2v0.1
Domains SHALL NOT be added to lists that bypass spam filters and hide warnings.

- _Rationale:_ Allowing an entire domain to bypass the spam filters and hide warnings allows for the potential for a spoofed email within the domain to bypass the filter and prevents the user from knowing. Not adding domains and users helps mitigate the risk.
- _Last modified:_ April 10, 2024

- MITRE ATT&CK TTP Mapping
  - { Needs TTP Mappings }

#### GWS.GMAIL.19.3v0.1
Bypass spam filters and hide warnings for all messages from internal and external senders SHALL NOT be enabled.

- _Rationale:_ Bypassing spam filters and hiding warning for all messages from internal and external senders creates a security risk because of the potential for a malicious message being able to bypass filters. Disabling this feature mitigates the risk.
- _Last modified:_ April 10, 2024

- MITRE ATT&CK TTP Mapping
  - { Needs TTP Mappings }

### Resources

-   [How to bypass the spam filter for incoming emails using the spam settings ](https://knowledge.workspace.google.com/kb/how-to-bypass-the-spam-filter-for-incoming-emails-using-the-spam-settings-000006661)

### Prerequisites

-   N/A

### Implementation

To configure the settings for spam filtering:

#### Policy Group 19 Common Instructions
1.  Sign in to the [Google Admin Console](https://admin.google.com).
2.  Select **Apps -\> Google Workspace -\> Gmail**.
3.  Select **Spam, Phishing, and Malware**.

#### GWS.GMAIL.19.1v0.1 Instructions
1.  Un-select **Bypass spam filters for messages from senders or domains in selected lists.**
2.  Select **Save**.

#### GWS.GMAIL.19.2v0.1 Instructions
1.  Un-select **Bypass spam filters and hide warnings for messages from senders or domains in selected lists.**
2.  Select **Save**.

#### GWS.GMAIL.19.3v0.1 Instructions
1.  Un-select **Bypass spam filters and hide warnings for all messages from internal and external senders**
2.  Select **Save**.
