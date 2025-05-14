package gmail

import future.keywords
import data.utils
import data.utils.GetFriendlyEnabledValue

GmailEnabled(orgunit) := utils.AppEnabled(input.policies, "gmail", orgunit)

Format(Array) := format_int(count(Array), 10)

Description(String1, String2, String3) := trim(concat("", [String1, concat("", [String2, String3]), "."]), " ")

ReportDetailsArray(Status, _, _) :=  Detail if {
    Status == true
    Detail := "Requirement met."
}

ReportDetailsArray(Status, Array1, Array2) := Detail if {
	Status == false
    Fraction := concat(" of ", [Format(Array1), Format(Array2)])
	String := concat(", ", Array1)
    Detail := Description(Fraction, " agency domain(s) found in violation: ", String)
}

AllDomains := {Domain | some Domain in input.domains}

LogEvents := utils.GetEvents("gmail_logs")

###############
# GWS.GMAIL.1 #
###############

#
# Baseline GWS.GMAIL.1.1
#--

GmailId1_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.1.1")

NonComplianceMessage1_1(value) := sprintf("Mail delegation is %s", [value])

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1(GetFriendlyEnabledValue(mailDelegation))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    mailDelegation := settings.gmail_mail_delegation.enableMailDelegation
    mailDelegation
}

tests contains {
    "PolicyId": GmailId1_1,
    "Prerequisites": [
        "policy/gmail_mail_delegation.enableMailDelegation",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs1_1) == 0
}
#--

###############
# GWS.GMAIL.2 #
###############

#
# Baseline GWS.GMAIL.2.1
#--

GmailId2_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.2.1")

# Not applicable at OU or Group level
DomainsWithDkim contains DkimRecord.domain if {
    some DkimRecord in input.dkim_records
    some Rdata in DkimRecord.rdata
    startswith(Rdata, "v=DKIM1;")
}

tests contains {
    "PolicyId": GmailId2_1,
    "Prerequisites": ["directory/v1/domains/list", "get_dkim_records"],
    "Criticality": "Should",
    "ReportDetails": ReportDetailsArray(Status, DomainsWithoutDkim, AllDomains),
    "ActualValue": input.dkim_records,
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    DomainsWithoutDkim := AllDomains - DomainsWithDkim
    Status := count(DomainsWithoutDkim) == 0
}
#--

###############
# GWS.GMAIL.3 #
###############

#
# Baseline GWS.GMAIL.3.1
#--

GmailId3_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.3.1")

# Not applicable at OU or Group level
DomainsWithSpf contains SpfRecord.domain if {
    some SpfRecord in input.spf_records
    some Rdata in SpfRecord.rdata
    startswith(Rdata, "v=spf1 ")
    # Ensure that the policy either ends with "-all" or directs to a different SPF policy
    true in [
        endswith(Rdata, "-all"),
        contains(Rdata, "redirect")
    ]
}

tests contains {
    "PolicyId": GmailId3_1,
    "Prerequisites": ["directory/v1/domains/list", "get_spf_records"],
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsArray(Status, DomainsWithoutSpf, AllDomains),
    "ActualValue": DomainsWithoutSpf,
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    DomainsWithoutSpf := AllDomains - DomainsWithSpf
    Status := count(DomainsWithoutSpf) == 0
}
#--


###############
# GWS.GMAIL.4 #
###############

#
# Baseline GWS.GMAIL.4.1
#--

GmailId4_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.4.1")

# Not applicable at OU or Group level
DomainsWithDmarc contains DmarcRecord.domain if {
    some DmarcRecord in input.dmarc_records
    some Rdata in DmarcRecord.rdata
    startswith(Rdata, "v=DMARC1;")
}

tests contains {
    "PolicyId": GmailId4_1,
    "Prerequisites": ["directory/v1/domains/list", "get_dmarc_records"],
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsArray(Status, DomainsWithoutDmarc, AllDomains),
    "ActualValue": input.dmarc_records,
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    DomainsWithoutDmarc := AllDomains - DomainsWithDmarc
    Status := count(DomainsWithoutDmarc) == 0
}
#--

#
# Baseline GWS.GMAIL.4.2
#--

GmailId4_2 := utils.PolicyIdWithSuffix("GWS.GMAIL.4.2")

# Not applicable at OU or Group level
DomainsWithPreject contains DmarcRecord.domain if {
    some DmarcRecord in input.dmarc_records
    some Rdata in DmarcRecord.rdata
    contains(Rdata, "p=reject;")
}

tests contains {
    "PolicyId": GmailId4_2,
    "Prerequisites": ["directory/v1/domains/list", "get_dmarc_records"],
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsArray(Status, DomainsWithoutPreject, AllDomains),
    "ActualValue": input.dmarc_records,
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    DomainsWithoutPreject := AllDomains - DomainsWithPreject
    Status := count(DomainsWithoutPreject) == 0
}
#--

#
# Baseline GWS.GMAIL.4.3
#--

GmailId4_3 := utils.PolicyIdWithSuffix("GWS.GMAIL.4.3")

# Not applicable at OU or Group level
DomainsWithDHSContact contains DmarcRecord.domain if {
    some DmarcRecord in input.dmarc_records
    some Rdata in DmarcRecord.rdata
    contains(Rdata, "mailto:reports@dmarc.cyber.dhs.gov")
}

tests contains {
    "PolicyId": GmailId4_3,
    "Prerequisites": ["directory/v1/domains/list", "get_dmarc_records"],
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsArray(Status, DomainsWithoutDHSContact, AllDomains),
    "ActualValue": input.dmarc_records,
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    DomainsWithoutDHSContact := AllDomains - DomainsWithDHSContact
    Status := count(DomainsWithoutDHSContact) == 0
}
#--

#
# Baseline GWS.GMAIL.4.4
#--

GmailId4_4 := utils.PolicyIdWithSuffix("GWS.GMAIL.4.4")

# Not applicable at OU or Group level
DomainsWithAgencyContact contains DmarcRecord.domain if {
    some DmarcRecord in input.dmarc_records
    some Rdata in DmarcRecord.rdata
    count(split(Rdata, "@")) >= 3
}

tests contains {
    "PolicyId": GmailId4_4,
    "Prerequisites": ["directory/v1/domains/list", "get_dmarc_records"],
    "Criticality": "Should",
    "ReportDetails": ReportDetailsArray(Status, DomainsWithoutAgencyContact, AllDomains),
    "ActualValue": input.dmarc_records,
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    DomainsWithoutAgencyContact := AllDomains - DomainsWithAgencyContact
    Status := count(DomainsWithoutAgencyContact) == 0
}
#--

###############
# GWS.GMAIL.5 #
###############

#
# Baseline GWS.GMAIL.5.1
#--

GmailId5_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.5.1")

# The following prefix applies to the next 2 baselines and is used to keep
# string length from getting too long.
ProtectionEncryptAttPrefix := "Protection against encrypted attachments"
NonComplianceMessage5_1(value) := sprintf("%s from untrusted senders is set to: %s",
                                          [ProtectionEncryptAttPrefix, value])

NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_1(GetFriendlyEnabledValue(noEncrypt))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    noEncrypt := settings.gmail_email_attachment_safety.enableEncryptedAttachmentProtection
    noEncrypt != true
}

tests contains {
    "PolicyId": GmailId5_1,
    "Prerequisites": [
        "policy/gmail_email_attachment_safety.enableEncryptedAttachmentProtection",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs5_1) == 0
}
#--

#
# Baseline GWS.GMAIL.5.2
#--

GmailId5_2 := utils.PolicyIdWithSuffix("GWS.GMAIL.5.2")

NonComplianceMessage5_2(value) := sprintf("%s with scripts from untrusted senders is set to: %s",
                                          [ProtectionEncryptAttPrefix, value])

NonCompliantOUs5_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_2(GetFriendlyEnabledValue(noEncrypt))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    noEncrypt := settings.gmail_email_attachment_safety.enableAttachmentWithScriptsProtection
    noEncrypt != true
}

tests contains {
    "PolicyId": GmailId5_2,
    "Prerequisites": [
        "policy/gmail_email_attachment_safety.enableAttachmentWithScriptsProtection",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs5_2) == 0
}
#--

#
# Baseline GWS.GMAIL.5.3
#--

GmailId5_3 := utils.PolicyIdWithSuffix("GWS.GMAIL.5.3")

NonComplianceMessage5_3(value) := sprintf("Protection against anomalous attachment types in emails is set to: %s",
                                          [value])

NonCompliantOUs5_3 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_3(GetFriendlyEnabledValue(protectAtt))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    protectAtt := settings.gmail_email_attachment_safety.enableAnomalousAttachmentProtection
    protectAtt != true
}

tests contains {
    "PolicyId": GmailId5_3,
    "Prerequisites": [
        "policy/gmail_email_attachment_safety.enableAnomalousAttachmentProtection",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_3, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs5_3) == 0
}
#--

#
# Baseline GWS.GMAIL.5.4
#--

GmailId5_4 := utils.PolicyIdWithSuffix("GWS.GMAIL.5.4")

NonComplianceMessage5_4(value) := sprintf("Automatically enables all future added settings is set to: %s",
                                          [value])

NonCompliantOUs5_4 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_4(GetFriendlyEnabledValue(futureAtt))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    futureAtt := settings.gmail_email_attachment_safety.applyFutureRecommendedSettingsAutomatically
    futureAtt != true
}

tests contains {
    "PolicyId": GmailId5_4,
    "Prerequisites": [
        "policy/gmail_email_attachment_safety.applyFutureRecommendedSettingsAutomatically",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_4, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs5_4) == 0
}
#--

#
# Baseline GWS.GMAIL.5.5
#--

GmailId5_5 := utils.PolicyIdWithSuffix("GWS.GMAIL.5.5")

NonComplianceMessage5_5(types) := sprintf("%s attachment emails not removed from inbox",
                                          [concat(", ", sort(types))])

AttachConfigs := [
	{"type": "anomalous type",
	 "setting": "anomalousAttachmentProtectionConsequence"},
	{"type": "encrypted",
	 "setting": "encryptedAttachmentProtectionConsequence"},
	{"type": "scripts",
	 "setting": "attachmentWithScriptsProtectionConsequence"}
]

NonCompliantOUs5_5 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_5(types)
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    types := [config.type |
        some config in AttachConfigs
        consequence = settings.gmail_email_attachment_safety[config.setting]
        not consequence in ["SPAM_FOLDER", "QUARANTINE"]
    ]
    count(types) > 0
}

tests contains {
    "PolicyId": GmailId5_5,
     "Prerequisites": [
        "policy/gmail_email_attachment_safety.anomalousAttachmentProtectionConsequence",
		"policy/gmail_email_attachment_safety.encryptedAttachmentProtectionConsequence",
		"policy/gmail_email_attachment_safety.attachmentWithScriptsProtectionConsequence",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_5, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_5},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs5_5) == 0
}
#--

#
# Baseline GWS.GMAIL.5.6
#--
# No implementation steps provided for this policy

GmailId5_6 := utils.PolicyIdWithSuffix("GWS.GMAIL.5.6")

tests contains {
    "PolicyId": GmailId5_6,
    "Prerequisites": [],
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please check manually.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--

###############
# GWS.GMAIL.6 #
###############

#
# Baseline GWS.GMAIL.6.1
#--

GmailId6_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.6.1")

NonComplianceMessage6_1(value) := sprintf("Identify links behind shortened URLs is: %s",
                                          [value])

NonCompliantOUs6_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_1(GetFriendlyEnabledValue(shortLinks))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    shortLinks := settings.gmail_links_and_external_images.enableShortenerScanning
    shortLinks != true
}

tests contains {
    "PolicyId": GmailId6_1,
    "Prerequisites": [
        "policy/gmail_links_and_external_images.enableShortenerScanning",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs6_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs6_1) == 0
}
#--

#
# Baseline GWS.GMAIL.6.2
#--

GmailId6_2 := utils.PolicyIdWithSuffix("GWS.GMAIL.6.2")

NonComplianceMessage6_2(value) := sprintf("Scan linked images is: %s",
                                          [value])

NonCompliantOUs6_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_2(GetFriendlyEnabledValue(scanImages))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    scanImages := settings.gmail_links_and_external_images.enableExternalImageScanning
    scanImages != true
}

tests contains {
    "PolicyId": GmailId6_2,
    "Prerequisites": [
        "policy/gmail_links_and_external_images.enableExternalImageScanning",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs6_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs6_2) == 0
}
#--

#
# Baseline GWS.GMAIL.6.3
#--

GmailId6_3 := utils.PolicyIdWithSuffix("GWS.GMAIL.6.3")

NonComplianceMessage6_3(value) := sprintf("Show warning prompt for click on links to untrusted domains is: %s",
                                          [value])

NonCompliantOUs6_3 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_3(GetFriendlyEnabledValue(warnEnabled))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    warnEnabled := settings.gmail_links_and_external_images.enableAggressiveWarningsOnUntrustedLinks
    warnEnabled != true
}

tests contains {
    "PolicyId": GmailId6_3,
    "Prerequisites": [
        "policy/gmail_links_and_external_images.enableAggressiveWarningsOnUntrustedLinks",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs6_3, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs6_3) == 0
}
#--

#
# Baseline GWS.GMAIL.6.4
#--

GmailId6_4 := utils.PolicyIdWithSuffix("GWS.GMAIL.6.4")

NonComplianceMessage6_4(value) := sprintf("Apply future recommended settings automatically is: %s",
                                          [value])

NonCompliantOUs6_4 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_4(GetFriendlyEnabledValue(applyFuture))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    applyFuture := settings.gmail_links_and_external_images.applyFutureSettingsAutomatically
    applyFuture != true
}

tests contains {
    "PolicyId": GmailId6_4,
    "Prerequisites": [
        "policy/gmail_links_and_external_images.applyFutureSettingsAutomatically",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs6_4, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs6_4) == 0
}
#--

#
# Baseline GWS.GMAIL.6.5
#--

GmailId6_5 := utils.PolicyIdWithSuffix("GWS.GMAIL.6.5")

# No implementation steps provided for this policy
tests contains {
    "PolicyId": GmailId6_5,
    "Prerequisites": [],
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}

###############
# GWS.GMAIL.7 #
###############

#
# Baseline GWS.GMAIL.7.1
#--

GmailId7_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.7.1")

NonComplianceMessage7_1(value) := sprintf("Protect against domain spoofing using similar domain names is set to: %s",
                                          [value])

NonCompliantOUs7_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_1(GetFriendlyEnabledValue(spoofProtect))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    spoofProtect := settings.gmail_spoofing_and_authentication.detectDomainNameSpoofing
    spoofProtect != true
}

tests contains {
    "PolicyId": GmailId7_1,
    "Prerequisites": [
        "policy/gmail_spoofing_and_authentication.detectDomainNameSpoofing",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs7_1) == 0
}
#--

#
# Baseline GWS.GMAIL.7.2
#--

GmailId7_2 := utils.PolicyIdWithSuffix("GWS.GMAIL.7.2")

NonComplianceMessage7_2(value) := sprintf("Protect against spoofing of employee names is set to: %s",
                                          [value])

NonCompliantOUs7_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_2(GetFriendlyEnabledValue(spoofProtect))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    spoofProtect := settings.gmail_spoofing_and_authentication.detectEmployeeNameSpoofing
    spoofProtect != true
}

tests contains {
    "PolicyId": GmailId7_2,
    "Prerequisites": [
        "policy/gmail_spoofing_and_authentication.detectEmployeeNameSpoofing",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs7_2) == 0
}
#--

#
# Baseline GWS.GMAIL.7.3
#--

GmailId7_3 := utils.PolicyIdWithSuffix("GWS.GMAIL.7.3")

NonComplianceMessage7_3(value) := sprintf("Protect against inbound emails spoofing your domain is set to: %s",
                                          [value])

NonCompliantOUs7_3 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_3(GetFriendlyEnabledValue(spoofProtect))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    spoofProtect := settings.gmail_spoofing_and_authentication.detectDomainSpoofingFromUnauthenticatedSenders
    spoofProtect != true
}

tests contains {
    "PolicyId": GmailId7_3,
    "Prerequisites": [
        "policy/gmail_spoofing_and_authentication.detectDomainSpoofingFromUnauthenticatedSenders",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_3, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs7_3) == 0
}
#--

#
# Baseline GWS.GMAIL.7.4
#--

GmailId7_4 := utils.PolicyIdWithSuffix("GWS.GMAIL.7.4")

NonComplianceMessage7_4(value) := sprintf("Protect against any unauthenticated emails is set to: %s",
                                          [value])

NonCompliantOUs7_4 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_4(GetFriendlyEnabledValue(unauthEmail))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    unauthEmail := settings.gmail_spoofing_and_authentication.detectUnauthenticatedEmails
    unauthEmail != true
}

tests contains {
    "PolicyId": GmailId7_4,
    "Prerequisites": [
        "policy/gmail_spoofing_and_authentication.detectUnauthenticatedEmails",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_4, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs7_4) == 0
}
#--

#
# Baseline GWS.GMAIL.7.5
#--

GmailId7_5 := utils.PolicyIdWithSuffix("GWS.GMAIL.7.5")

NonComplianceMessage7_5(value) := sprintf("Protect your Groups from inbound emails spoofing your domain is set to: %s",
                                          [value])

NonCompliantOUs7_5 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_5(GetFriendlyEnabledValue(detectSpoof))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    detectSpoof := settings.gmail_spoofing_and_authentication.detectDomainSpoofingFromUnauthenticatedSenders
    detectSpoof != true
}

tests contains {
    "PolicyId": GmailId7_5,
    "Prerequisites": [
        "policy/gmail_spoofing_and_authentication.detectDomainSpoofingFromUnauthenticatedSenders",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_5, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_5},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs7_5) == 0
}
#--

#
# Baseline GWS.GMAIL.7.6
#--

GmailId7_6 := utils.PolicyIdWithSuffix("GWS.GMAIL.7.6")

NonComplianceMessage7_6(types) := sprintf("%s spoof emails not removed from inbox",
                                          [concat(", ", sort(types))])

SpoofConfigs := [
	{"type": "domain", "setting": "domainSpoofingConsequence"},
	{"type": "domain name", "setting": "domainNameSpoofingConsequence"},
	{"type": "employee name", "setting": "employeeNameSpoofingConsequence"},
	{"type": "groups", "setting": "groupsSpoofingConsequence"},
	{"type": "unauthenticated", "setting": "unauthenticatedEmailConsequence"}
]

NonCompliantOUs7_6 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_6(types)
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    types := [config.type |
        some config in SpoofConfigs
        consequence = settings.gmail_spoofing_and_authentication[config.setting]
        not consequence in ["SPAM_FOLDER", "QUARANTINE"]
    ]
    count(types) > 0
}

tests contains {
    "PolicyId": GmailId7_6,
    "Prerequisites": [
        "policy/gmail_spoofing_and_authentication.domainSpoofingConsequence",
		"policy/gmail_spoofing_and_authentication.domainNameSpoofingConsequence",
		"policy/gmail_spoofing_and_authentication.employeeNameSpoofingConsequence",
		"policy/gmail_spoofing_and_authentication.groupsSpoofingConsequence",
		"policy/gmail_spoofing_and_authentication.unauthenticatedEmailConsequence",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_6, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_6},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs7_6) == 0
}
#--

#
# Baseline GWS.GMAIL.7.7
#--

GmailId7_7 := utils.PolicyIdWithSuffix("GWS.GMAIL.7.7")

NonComplianceMessage7_7(value) := sprintf("Automatically enable all future added settings is set to: %s",
                                          [value])

NonCompliantOUs7_7 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_7(GetFriendlyEnabledValue(applyFuture))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    applyFuture := settings.gmail_spoofing_and_authentication.applyFutureSettingsAutomatically
    applyFuture != true
}

tests contains {
    "PolicyId": GmailId7_7,
    "Prerequisites": [
        "policy/gmail_spoofing_and_authentication.applyFutureSettingsAutomatically",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_7, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_7},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs7_7) == 0
}
#--

#
# Baseline GWS.GMAIL.7.8
#--

GmailId7_8 := utils.PolicyIdWithSuffix("GWS.GMAIL.7.8")

# No implementation steps provided for this policy
tests contains {
    "PolicyId": GmailId7_8,
    "Prerequisites": [],
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--

###############
# GWS.GMAIL.8 #
###############

#
# Baseline GWS.GMAIL.8.1
#--

GmailId8_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.8.1")

NonComplianceMessage8_1(value) := sprintf("User email uploads is %s", [value])

NonCompliantOUs8_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage8_1(GetFriendlyEnabledValue(emailUploads))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    emailUploads := settings.gmail_user_email_uploads.enableMailAndContactsImport
    emailUploads
}

tests contains {
    "PolicyId": GmailId8_1,
    "Prerequisites": [
        "policy/gmail_user_email_uploads.enableMailAndContactsImport",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs8_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs8_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs8_1) == 0
}
#--

###############
# GWS.GMAIL.9 #
###############

#
# Baseline GWS.GMAIL.9.1
#--

GmailId9_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.9.1")

GetFriendlyValue9_1(ImapEnabled, PopEnabled) := Description if {
    ImapEnabled == true
    PopEnabled == true
    Description := "IMAP and POP access are enabled"
} else := Description if {
    ImapEnabled == true
    PopEnabled == false
    Description := "IMAP access is enabled"
} else := Description if {
    ImapEnabled == false
    PopEnabled == true
    Description := "POP access is enabled"
} else := "Both IMAP and POP access are disabled"

NonCompliantOUs9_1 contains {
    "Name": OU,
    "Value": GetFriendlyValue9_1(imapEnable, popEnable)
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    imapSection := "gmail_imap_access"
    imapSetting := "enableImapAccess"
    popSection := "gmail_pop_access"
    popSetting := "enablePopAccess"
    imapSet := utils.ApiSettingExists(imapSection, imapSetting, OU)
    popSet := utils.ApiSettingExists(popSection, popSetting, OU)
    true in {imapSet, popSet}
    imapEnable := utils.GetApiSettingValue(imapSection, imapSetting, OU)
    popEnable := utils.GetApiSettingValue(popSection, popSetting, OU)
    true in {imapEnable, popEnable}
}

tests contains {
    "PolicyId": GmailId9_1,
    "Prerequisites": [
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs9_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs9_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs9_1) == 0
}
#--

################
# GWS.GMAIL.10 #
################

#
# Baseline GWS.GMAIL.10.1
#--

GmailId10_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.10.1")

NonComplianceMessage10_1(value) := sprintf("Google Workspace Sync is %s",
                                          [value])

NonCompliantOUs10_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage10_1(GetFriendlyEnabledValue(syncEnable))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    syncEnable := settings.gmail_workspace_sync_for_outlook.enableGoogleWorkspaceSyncForMicrosoftOutlook
    syncEnable
}

tests contains {
    "PolicyId": GmailId10_1,
    "Prerequisites": [
        "policy/gmail_workspace_sync_for_outlook.enableGoogleWorkspaceSyncForMicrosoftOutlook",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs10_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs10_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs10_1) == 0
}
#--

################
# GWS.GMAIL.11 #
################

#
# Baseline GWS.GMAIL.11.1
#--

GmailId11_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.11.1")

NonComplianceMessage11_1(value) := sprintf("Automatic email forwarding is set to: %s",
                                           [value])

NonCompliantOUs11_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage11_1(GetFriendlyEnabledValue(autoforward))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    autoforward := settings.gmail_auto_forwarding.enableAutoForwarding
    autoforward != false
}

tests contains {
    "PolicyId": GmailId11_1,
    "Prerequisites": [
        "policy/gmail_auto_forwarding.enableAutoForwarding",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs11_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs11_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs11_1) == 0
}
#--

################
# GWS.GMAIL.12 #
################

#
# Baseline GWS.GMAIL.12.1
#--

GmailId12_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.12.1")

NonComplianceMessage12_1(value) := sprintf("Per-user Outbound Gateways are %s",
                                           [value])

NonCompliantOUs12_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage12_1(GetFriendlyEnabledValue(outGatewayEnable))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    outGatewayEnable := settings.gmail_per_user_outbound_gateway.allowUsersToUseExternalSmtpServers
    outGatewayEnable
}

tests contains {
    "PolicyId": GmailId12_1,
    "Prerequisites": [
        "policy/gmail_per_user_outbound_gateway.allowUsersToUseExternalSmtpServers",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs12_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs12_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs12_1) == 0
}
#--

################
# GWS.GMAIL.13 #
################

#
# Baseline GWS.GMAIL.13.1
#--

GmailId13_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.13.1")

GetFriendlyValue13_1(Value) := "enabled" if {
    Value == "false"
} else := "disabled" if {
    Value == "true"
} else := Value

NonCompliantOUs13_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Warn for external participants is set to",
        GetFriendlyValue13_1(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "OutOfDomainWarningProto disable_untrusted_recipient_warning", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": GmailId13_1,
    "Prerequisites": ["reports/v1/activities/list"],
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    SettingName := "OutOfDomainWarningProto disable_untrusted_recipient_warning"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": GmailId13_1,
    "Prerequisites": ["reports/v1/activities/list"],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs13_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs13_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "OutOfDomainWarningProto disable_untrusted_recipient_warning"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs13_1) == 0
}
#--

################
# GWS.GMAIL.14 #
################

#
# Baseline GWS.GMAIL.14.1
#--

GmailId14_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.14.1")

NonComplianceMessage14_1(Value, OU) := sprintf("Email allowlists are %s in %s.",
                                               [Value, OU])

# As with the other tests, this always returns a result, even if gmail is
# disabled - see how this is implemented by converting the enable status to 1/0
# (whereas a false value would fail the tests conditional).

tests contains {
    "PolicyId": GmailId14_1,
    "Prerequisites": [
        "policy/gmail_email_spam_filter_ip_allowlist.allowedIpAddresses",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Should",
    "ReportDetails": NonComplianceMessage14_1(GetFriendlyEnabledValue(allowListCount > 0),
                                              utils.TopLevelOU),
    "ActualValue": {utils.TopLevelOU: allowList},
    "RequirementMet": allowListCount == 0,
    "NoSuchEvent": false
}
if {
    enabled := to_number(GmailEnabled(utils.TopLevelOU))
    settings := input.policies[utils.TopLevelOU]
    allowList := settings.gmail_email_spam_filter_ip_allowlist.allowedIpAddresses
    allowListCount := enabled * count(allowList)
}
#--

################
# GWS.GMAIL.15 #
################

#
# Baseline GWS.GMAIL.15.1
#--

GmailId15_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.15.1")

NonComplianceMessage15_1(value) := sprintf("Enhanced pre-delivery message scanning is %s",
                                           [value])

NonCompliantOUs15_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage15_1(GetFriendlyEnabledValue(preScanning))
}
if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    preDelivery := settings.gmail_enhanced_pre_delivery_message_scanning
    preScanning := preDelivery.enableImprovedSuspiciousContentDetection
    preScanning != true
}

tests contains {
    "PolicyId": GmailId15_1,
    "Prerequisites": [
        "policy/gmail_enhanced_pre_delivery_message_scanning.enableImprovedSuspiciousContentDetection",
        "policy/gmail_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs15_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs15_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs15_1) == 0
}
#--

#
# Baseline GWS.GMAIL.15.2
#--

GmailId15_2 := utils.PolicyIdWithSuffix("GWS.GMAIL.15.2")

# No implementation steps provided for this policy
tests contains {
    "PolicyId": GmailId15_2,
    "Prerequisites": [],
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--

################
# GWS.GMAIL.16 #
################

#
# Baseline GWS.GMAIL.16.1
#--

GmailId16_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.16.1")

NonCompliantOUs16_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Security sandbox is",
        GetFriendlyEnabledValue(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "AttachmentDeepScanningSettingsProto deep_scanning_enabled", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": GmailId16_1,
    "Prerequisites": ["reports/v1/activities/list"],
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "AttachmentDeepScanningSettingsProto deep_scanning_enabled"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": GmailId16_1,
    "Prerequisites": ["reports/v1/activities/list"],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs16_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs16_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "AttachmentDeepScanningSettingsProto deep_scanning_enabled"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs16_1) == 0
}
#--

#
# Baseline GWS.GMAIL.16.2
#--

GmailId16_2 := utils.PolicyIdWithSuffix("GWS.GMAIL.16.2")

# No implementation steps provided for this policy
tests contains {
    "PolicyId": GmailId16_2,
    "Prerequisites": [],
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--

################
# GWS.GMAIL.17 #
################

#
# Baseline GWS.GMAIL.17.1
#--

GmailId17_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.17.1")

# At this time we are unable to test because settings are configured in the GWS Admin Console
# and not available within the generated logs
tests contains {
    "PolicyId": GmailId17_1,
    "Prerequisites": [],
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--

################
# GWS.GMAIL.18 #
################

#
# Baseline GWS.GMAIL.18.1
#--

GmailId18_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.18.1")

# At this time we are unable to test because settings are configured in the GWS Admin Console
# and not available within the generated logs
tests contains {
    "PolicyId": GmailId18_1,
    "Prerequisites": [],
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--

#
# Baseline GWS.GMAIL.18.2
#--

GmailId18_2 := utils.PolicyIdWithSuffix("GWS.GMAIL.18.2")

tests contains {
    "PolicyId": GmailId18_2,
    "Prerequisites": [],
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--

#
# Baseline GWS.GMAIL.18.3
#--

GmailId18_3 := utils.PolicyIdWithSuffix("GWS.GMAIL.18.3")

tests contains {
    "PolicyId": GmailId18_3,
    "Prerequisites": [],
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--
