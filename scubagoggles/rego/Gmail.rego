package gmail

import future.keywords
import data.utils
import data.utils.GetFriendlyEnabledValue
import data.utils.PolicyApiInUse

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

# Cannot be controlled at group level

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Mail delegation is set to",
        GetFriendlyEnabledValue(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_MAIL_DELEGATION_WITHIN_DOMAIN", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests contains {
    "PolicyId": GmailId1_1,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_MAIL_DELEGATION_WITHIN_DOMAIN", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": GmailId1_1,
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_MAIL_DELEGATION_WITHIN_DOMAIN", utils.TopLevelOU)
    count(Events) > 0
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

# Cannot be controlled at group level

GmailId5_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.5.1")

LogMessage5_1 := "Attachment safety Enable: protect against encrypted attachments from untrusted senders"

Check5_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage5_1, utils.TopLevelOU)
    count(events) > 0
}

Check5_1_OK if {PolicyApiInUse}

# The following prefix applies to the next 2 baselines and is used to keep
# string length from getting too long.
ProtectionEncryptAttPrefix := "Protection against encrypted attachments"
NonComplianceMessage5_1(value) := sprintf("%s from untrusted senders is set to: %s",
                                          [ProtectionEncryptAttPrefix, value])

NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_1(GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents,
                concat("", ["Attachment safety Enable: ",
                    "protect against encrypted attachments from untrusted senders"]), OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_1(GetFriendlyEnabledValue(noEncrypt))
} if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    noEncrypt := settings.gmail_email_attachment_safety.enableEncryptedAttachmentProtection
    noEncrypt != true
}

tests contains {
    "PolicyId": GmailId5_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
} if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check5_1_OK
}

tests contains {
    "PolicyId": GmailId5_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check5_1_OK
    Status := count(NonCompliantOUs5_1) == 0
}

#
# Baseline GWS.GMAIL.5.2
#--

GmailId5_2 := utils.PolicyIdWithSuffix("GWS.GMAIL.5.2")

LogMessage5_2 := "Attachment safety Enable: protect against attachments with scripts from untrusted senders"

Check5_2_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage5_2, utils.TopLevelOU)
    count(events) > 0
}

Check5_2_OK if {PolicyApiInUse}

NonComplianceMessage5_2(value) := sprintf("%s with scripts from untrusted senders is set to: %s",
                                          [ProtectionEncryptAttPrefix, value])

NonCompliantOUs5_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_2(GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents,
                concat("", ["Attachment safety Enable: ",
                    "protect against attachments with scripts from untrusted senders"]), OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs5_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_2(GetFriendlyEnabledValue(noEncrypt))
} if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    noEncrypt := settings.gmail_email_attachment_safety.enableAttachmentWithScriptsProtection
    noEncrypt != true
}

tests contains {
    "PolicyId": GmailId5_2,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check5_2_OK
}

tests contains {
    "PolicyId": GmailId5_2,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check5_2_OK
    Status := count(NonCompliantOUs5_2) == 0
}

#--

#
# Baseline GWS.GMAIL.5.3
#--

GmailId5_3 := utils.PolicyIdWithSuffix("GWS.GMAIL.5.3")

LogMessage5_3 := "Attachment safety Enable: Protect against anomalous attachment types in emails"

Check5_3_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage5_3, utils.TopLevelOU)
    count(events) > 0
}

Check5_3_OK if {PolicyApiInUse}

NonComplianceMessage5_3(value) := sprintf("Protection against anomalous attachment types in emails is set to: %s",
                                          [value])

NonCompliantOUs5_3 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_3(GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents,
                concat("", ["Attachment safety Enable: Protect against anomalous attachment types in emails"]), OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs5_3 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_3(GetFriendlyEnabledValue(protectAtt))
} if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    protectAtt := settings.gmail_email_attachment_safety.enableAnomalousAttachmentProtection
    protectAtt != true
}

tests contains {
    "PolicyId": GmailId5_3,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check5_3_OK
}

tests contains {
    "PolicyId": GmailId5_3,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_3, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check5_3_OK
    Status := count(NonCompliantOUs5_3) == 0
}
#--

#
# Baseline GWS.GMAIL.5.4
#--

GmailId5_4 := utils.PolicyIdWithSuffix("GWS.GMAIL.5.4")

LogMessage5_4 := "Attachment safety Enable: automatically enables all future added settings"

Check5_4_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage5_4, utils.TopLevelOU)
    count(events) > 0
}

Check5_4_OK if {PolicyApiInUse}

NonComplianceMessage5_4(value) := sprintf("Automatically enables all future added settings is set to: %s",
                                          [value])

NonCompliantOUs5_4 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_4(GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, concat("", ["Attachment safety Enable: ",
                                                "automatically enables all future added settings"]), OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs5_4 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_4(GetFriendlyEnabledValue(futureAtt))
} if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    futureAtt := settings.gmail_email_attachment_safety.applyFutureRecommendedSettingsAutomatically
    futureAtt != true
}

tests contains {
    "PolicyId": GmailId5_4,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check5_4_OK
}

tests contains {
    "PolicyId": GmailId5_4,
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_4, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check5_4_OK
    Status := count(NonCompliantOUs5_4) == 0
}
#--

#
# Baseline GWS.GMAIL.5.5
#--

GmailId5_5 := utils.PolicyIdWithSuffix("GWS.GMAIL.5.5")

NonComplianceMessage5_5(types) := sprintf("%s attachment emails not removed from inbox",
                                          [concat(", ", sort(types))])

default NoSuchEvent5_5 := false

NoSuchEvent5_5 := false if {
    PolicyApiInUse
} else := true if {
    SettingName := "Attachment safety Encrypted attachment protection setting action"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
} else := true if {
    SettingName := "Attachment safety Attachment with scripts protection action"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
} else := true if {
    SettingName := "Attachment safety Anomalous attachment protection setting action"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

EncryptedAttachmentMessage(NewValueEncryptedAttachment)
    := "Encrypted attachments from untrusted senders"
    if { NewValueEncryptedAttachment == "Show warning" }
    else := ""

AttachmentWithScriptsMessage(NewValueAttachmentWithScripts)
    := "Emails with attachments, with scripts from untrusted senders"
    if { NewValueAttachmentWithScripts == "Show warning" }
    else := ""

AnomalousAttachmentMessage(NewValueAnomalousAttachment)
    := "Emails with anomalous attachments"
    if { NewValueAnomalousAttachment == "Show warning" }
    else := ""

AllDetailedMessageListEmailAttachments(
    NewValueEncryptedAttachment,
    NewValueAttachmentWithScripts, NewValueAnomalousAttachment
) := [
    EncryptedAttachmentMessage(NewValueEncryptedAttachment),
    AttachmentWithScriptsMessage(NewValueAttachmentWithScripts),
    AnomalousAttachmentMessage(NewValueAnomalousAttachment)
]

DetailedMessageListEmailAttachments(NewValueEncryptedAttachment,
    NewValueAttachmentWithScripts, NewValueAnomalousAttachment) := [
        s | some s in AllDetailedMessageListEmailAttachments(
            NewValueEncryptedAttachment, NewValueAttachmentWithScripts,
            NewValueAnomalousAttachment
        ); s != ""
    ]

GetFriendlyValue5_5(NewValueEventEncryptedAttachment, NewValueAttachmentWithScripts,
    NewValueAnomalousAttachment) := concat("", [
    "The following email types are kept in the inbox:",
    "<ul>",
    concat("", [concat("", [
        "<li>",
        Value,
        "</li>"
    ]) | some Value in DetailedMessageListEmailAttachments(NewValueEventEncryptedAttachment,
        NewValueAttachmentWithScripts,
        NewValueAnomalousAttachment)]),
    "</ul>"
])

NonCompliantOUs5_5 contains {
    "Name": OU,
    "Value": GetFriendlyValue5_5(LastEventEncryptedAttachment.NewValue,
        LastEventAttachmentWithScripts.NewValue,
        LastEventAnomalousAttachment.NewValue)
} if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    EncryptedAttachmentEvents := utils.FilterEventsOU(LogEvents,
        "Attachment safety Encrypted attachment protection setting action", OU)
    count(EncryptedAttachmentEvents) > 0
    LastEventEncryptedAttachment := utils.GetLastEvent(EncryptedAttachmentEvents)

    AttachmentWithScriptsEvents := utils.FilterEventsOU(LogEvents,
        "Attachment safety Attachment with scripts protection action", OU)
    count(AttachmentWithScriptsEvents) > 0
    LastEventAttachmentWithScripts := utils.GetLastEvent(AttachmentWithScriptsEvents)

    AnomalousAttachmentEvents := utils.FilterEventsOU(LogEvents,
        "Attachment safety Anomalous attachment protection setting action", OU)
    count(AnomalousAttachmentEvents) > 0
    LastEventAnomalousAttachment := utils.GetLastEvent(AnomalousAttachmentEvents)

    # OU is non-compliant if any of the following are true
    true in [
        LastEventEncryptedAttachment.NewValue == "Show warning",
        LastEventAttachmentWithScripts.NewValue == "Show warning",
        LastEventAnomalousAttachment.NewValue == "Show warning"
    ]
}

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
} if {
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
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    NoSuchEvent5_5
}

tests contains {
    "PolicyId": GmailId5_5,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_5, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_5},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    not NoSuchEvent5_5
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

# Cannot be controlled at Group level

#
# Baseline GWS.GMAIL.6.1
#--

GmailId6_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.6.1")

LogMessage6_1 := "Links and external images safety Enable: identify links behind shortened URLs"

Check6_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage6_1, utils.TopLevelOU)
    count(events) > 0
}

Check6_1_OK if {PolicyApiInUse}

NonComplianceMessage6_1(value) := sprintf("Identify links behind shortened URLs is: %s",
                                          [value])

NonCompliantOUs6_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_1(GetFriendlyEnabledValue(LastEvent.NewValue))
} if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage6_1, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs6_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_1(GetFriendlyEnabledValue(shortLinks))
} if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    shortLinks := settings.gmail_links_and_external_images.enableShortenerScanning
    shortLinks != true
}

tests contains {
    "PolicyId": GmailId6_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check6_1_OK
}

tests contains {
    "PolicyId": GmailId6_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs6_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check6_1_OK
    Status := count(NonCompliantOUs6_1) == 0
}
#--

#
# Baseline GWS.GMAIL.6.2
#--

GmailId6_2 := utils.PolicyIdWithSuffix("GWS.GMAIL.6.2")

LogMessage6_2 := "Links and external images safety Enable: scan linked images"

Check6_2_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage6_2, utils.TopLevelOU)
    count(events) > 0
}

Check6_2_OK if {PolicyApiInUse}

NonComplianceMessage6_2(value) := sprintf("Scan linked images is: %s",
                                          [value])

NonCompliantOUs6_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_2(GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage6_2, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs6_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_2(GetFriendlyEnabledValue(scanImages))
} if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    scanImages := settings.gmail_links_and_external_images.enableExternalImageScanning
    scanImages != true
}

tests contains {
    "PolicyId": GmailId6_2,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check6_2_OK
}

tests contains {
    "PolicyId": GmailId6_2,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs6_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check6_2_OK
    Status := count(NonCompliantOUs6_2) == 0
}
#--

#
# Baseline GWS.GMAIL.6.3
#--

GmailId6_3 := utils.PolicyIdWithSuffix("GWS.GMAIL.6.3")

# NOTE: "unstrusted" really is the spelling the API uses:
LogMessage6_3 := sprintf("%s %s %s", ["Links and external images safety Enable:",
                                      "show warning prompt for click on links",
                                      "to unstrusted domains"])

Check6_3_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage6_3, utils.TopLevelOU)
    count(events) > 0
}

Check6_3_OK if {PolicyApiInUse}

NonComplianceMessage6_3(value) := sprintf("Show warning prompt for click on links to untrusted domains is: %s",
                                          [value])

NonCompliantOUs6_3 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_3(GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage6_3, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs6_3 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_3(GetFriendlyEnabledValue(warnEnabled))
} if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    warnEnabled := settings.gmail_links_and_external_images.enableAggressiveWarningsOnUntrustedLinks
    warnEnabled != true
}

tests contains {
    "PolicyId": GmailId6_3,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check6_3_OK
}

tests contains {
    "PolicyId": GmailId6_3,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs6_3, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check6_3_OK
    Status := count(NonCompliantOUs6_3) == 0
}
#--

#
# Baseline GWS.GMAIL.6.4
#--

GmailId6_4 := utils.PolicyIdWithSuffix("GWS.GMAIL.6.4")

LogMessage6_4 := sprintf("%s %s %s", ["Links and external images safety Enable:",
                                      "automatically enables all future",
                                      "added settings"])

Check6_4_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage6_4, utils.TopLevelOU)
    count(events) > 0
}

Check6_4_OK if {PolicyApiInUse}

NonComplianceMessage6_4(value) := sprintf("Apply future recommended settings automatically is: %s",
                                          [value])

NonCompliantOUs6_4 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_4(GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage6_4, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs6_4 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_4(GetFriendlyEnabledValue(applyFuture))
} if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    applyFuture := settings.gmail_links_and_external_images.applyFutureSettingsAutomatically
    applyFuture != true
}

tests contains {
    "PolicyId": GmailId6_4,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check6_4_OK
}

tests contains {
    "PolicyId": GmailId6_4,
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs6_4, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check6_4_OK
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

# No group level control

GmailId7_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.7.1")

LogMessage7_1 := sprintf("%s %s %s", ["Spoofing and authentication safety",
                                      "Enable: protect against domain spoofing",
                                      "using similar domain names"])

Check7_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage7_1, utils.TopLevelOU)
    count(events) > 0
}

Check7_1_OK if {PolicyApiInUse}

NonComplianceMessage7_1(value) := sprintf("Protect against domain spoofing using similar domain names is set to: %s",
                                          [value])

NonCompliantOUs7_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_1(GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage7_1, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs7_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_1(GetFriendlyEnabledValue(spoofProtect))
} if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    spoofProtect := settings.gmail_spoofing_and_authentication.detectDomainNameSpoofing
    spoofProtect != true
}

tests contains {
    "PolicyId": GmailId7_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check7_1_OK
}

tests contains {
    "PolicyId": GmailId7_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check7_1_OK
    Status := count(NonCompliantOUs7_1) == 0
}
#--

#
# Baseline GWS.GMAIL.7.2
#--

GmailId7_2 := utils.PolicyIdWithSuffix("GWS.GMAIL.7.2")

LogMessage7_2 := sprintf("%s %s %s", ["Spoofing and authentication safety",
                                      "Enable: protect against spoofing of",
                                      "employee names"])

Check7_2_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage7_2, utils.TopLevelOU)
    count(events) > 0
}

Check7_2_OK if {PolicyApiInUse}

NonComplianceMessage7_2(value) := sprintf("Protect against spoofing of employee names is set to: %s",
                                          [value])

NonCompliantOUs7_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_2(GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage7_2, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs7_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_2(GetFriendlyEnabledValue(spoofProtect))
} if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    spoofProtect := settings.gmail_spoofing_and_authentication.detectEmployeeNameSpoofing
    spoofProtect != true
}

tests contains {
    "PolicyId": GmailId7_2,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check7_2_OK
}

tests contains {
    "PolicyId": GmailId7_2,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check7_2_OK
    Status := count(NonCompliantOUs7_2) == 0
}
#--

#
# Baseline GWS.GMAIL.7.3
#--

GmailId7_3 := utils.PolicyIdWithSuffix("GWS.GMAIL.7.3")

LogMessage7_3 := sprintf("%s %s %s", ["Spoofing and authentication safety",
                                      "Enable: protect against inbound emails",
                                      "spoofing your domain"])

Check7_3_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage7_3, utils.TopLevelOU)
    count(events) > 0
}

Check7_3_OK if {PolicyApiInUse}

NonComplianceMessage7_3(value) := sprintf("Protect against inbound emails spoofing your domain is set to: %s",
                                          [value])

NonCompliantOUs7_3 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_3(GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage7_3, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs7_3 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_3(GetFriendlyEnabledValue(spoofProtect))
} if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    spoofProtect := settings.gmail_spoofing_and_authentication.detectDomainSpoofingFromUnauthenticatedSenders
    spoofProtect != true
}

tests contains {
    "PolicyId": GmailId7_3,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check7_3_OK
}

tests contains {
    "PolicyId": GmailId7_3,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_3, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check7_3_OK
    Status := count(NonCompliantOUs7_3) == 0
}
#--

#
# Baseline GWS.GMAIL.7.4
#--

GmailId7_4 := utils.PolicyIdWithSuffix("GWS.GMAIL.7.4")

LogMessage7_4 := sprintf("%s %s %s", ["Spoofing and authentication safety",
                                      "Enable: protect against any",
                                      "unauthenticated emails"])

Check7_4_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage7_4, utils.TopLevelOU)
    count(events) > 0
}

Check7_4_OK if {PolicyApiInUse}

NonComplianceMessage7_4(value) := sprintf("Protect against any unauthenticated emails is set to: %s",
                                          [value])

NonCompliantOUs7_4 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_4(GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage7_4, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs7_4 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_4(GetFriendlyEnabledValue(unauthEmail))
} if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    unauthEmail := settings.gmail_spoofing_and_authentication.detectUnauthenticatedEmails
    unauthEmail != true
}

tests contains {
    "PolicyId": GmailId7_4,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check7_4_OK
}

tests contains {
    "PolicyId": GmailId7_4,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_4, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check7_4_OK
    Status := count(NonCompliantOUs7_4) == 0
}
#--

#
# Baseline GWS.GMAIL.7.5
#--

GmailId7_5 := utils.PolicyIdWithSuffix("GWS.GMAIL.7.5")

LogMessage7_5 := sprintf("%s %s %s", ["Spoofing and authentication safety",
                                      "Enable: protect your Groups from",
                                      "inbound emails spoofing your domain"])

Check7_5_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage7_5, utils.TopLevelOU)
    count(events) > 0
}

Check7_5_OK if {PolicyApiInUse}

NonComplianceMessage7_5(value) := sprintf("Protect your Groups from inbound emails spoofing your domain is set to: %s",
                                          [value])

NonCompliantOUs7_5 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_5(GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage7_5, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs7_5 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_5(GetFriendlyEnabledValue(detectSpoof))
} if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    detectSpoof := settings.gmail_spoofing_and_authentication.detectDomainSpoofingFromUnauthenticatedSenders
    detectSpoof != true
}

tests contains {
    "PolicyId": GmailId7_5,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check7_5_OK
}

tests contains {
    "PolicyId": GmailId7_5,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_5, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_5},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check7_5_OK
    Status := count(NonCompliantOUs7_5) == 0
}
#--

#
# Baseline GWS.GMAIL.7.6
#--

GmailId7_6 := utils.PolicyIdWithSuffix("GWS.GMAIL.7.6")

NonComplianceMessage7_6(types) := sprintf("%s spoof emails not removed from inbox",
                                          [concat(", ", sort(types))])

# No such event is true if any of the relevant settings doesn't having any events
default NoSuchEvent7_6 := false

NoSuchEvent7_6 := false if {
    PolicyApiInUse
} else := true if {
    SettingName :=
        "Spoofing and authentication safety Protect against domain spoofing based on similar domain names action"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
} else := true if {
    SettingName :=
        "Spoofing and authentication safety Protect against spoofing of employee names action"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
} else := true if {
    SettingName :=
        "Spoofing and authentication safety Protect against inbound emails spoofing your domain action"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
} else := true if {
    SettingName :=
        "Spoofing and authentication safety Protect against any unauthenticated emails action"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
} else := true if {
    SettingName :=
        "Spoofing and authentication safety Protect your Groups from inbound emails spoofing your domain action"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

DomainNamesMessage(NewValueDomainNames) := "Inbound emails spoofing similar domain names"
    if { NewValueDomainNames == "Show warning" }
    else := ""

EmployeeNamesMessage(NewValueEmployeeNames) := "Inbound emails spoofing employee names"
    if { NewValueEmployeeNames == "Show warning" }
    else := ""

InboundEmailsMessage(NewValueInboundEmail) := "Inbound emails spoofing your domain name"
    if { NewValueInboundEmail == "Show warning" }
    else := ""

UnauthenticatedEmailsMessage(NewValueUnauthenticatedEmails) := "Unauthenticated emails"
    if { NewValueUnauthenticatedEmails in ["Show warning", "No action"] }
    else := ""

GroupEmailsMessage(NewValueGroupEmails) := "Inbound spoofing emails addressed to groups"
    if { NewValueGroupEmails == "Show warning" }
    else := ""

AllDetailedMessages(NewValueDomainNames, NewValueEmployeeNames, NewValueInboundEmails,
    NewValueUnauthenticatedEmails, NewValueGroupEmails) := [
        DomainNamesMessage(NewValueDomainNames), EmployeeNamesMessage(NewValueEmployeeNames),
        InboundEmailsMessage(NewValueInboundEmails), UnauthenticatedEmailsMessage(NewValueUnauthenticatedEmails),
        GroupEmailsMessage(NewValueGroupEmails)
    ]

DetailedMessageList(NewValueDomainNames, NewValueEmployeeNames, NewValueInboundEmails,
    NewValueUnauthenticatedEmails, NewValueGroupEmails) := [s | some s in
        AllDetailedMessages(
            NewValueDomainNames, NewValueEmployeeNames, NewValueInboundEmails,
    NewValueUnauthenticatedEmails, NewValueGroupEmails
        ); s != ""]

GetFriendlyValue7_6(NewValueDomainNames, NewValueEmployeeNames, NewValueInboundEmails,
    NewValueUnauthenticatedEmails, NewValueGroupEmails) := concat("", [
    "The following email types are kept in the inbox:",
    "<ul>",
    concat("", [concat("", [
        "<li>",
        Value,
        "</li>"
    ]) | some Value in DetailedMessageList(NewValueDomainNames, NewValueEmployeeNames,
        NewValueInboundEmails, NewValueUnauthenticatedEmails, NewValueGroupEmails)]),
    "</ul>"
])

NonCompliantOUs7_6 contains {
    "Name": OU,
    "Value": GetFriendlyValue7_6(LastEventDomainNames.NewValue, LastEventEmployeeNames.NewValue,
        LastEventInboundEmails.NewValue, LastEventUnauthenticatedEmails.NewValue,
        LastEventGroupEmails.NewValue)
} if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents

      DomainNamesSetting := concat("", [
        "Spoofing and authentication safety Protect against domain spoofing based on ",
        "similar domain names action"
    ])
    DomainNamesEvents := utils.FilterEventsOU(LogEvents, DomainNamesSetting, OU)
    LastEventDomainNames := utils.GetLastEvent(DomainNamesEvents)

    EmployeeNamesSetting :=
        "Spoofing and authentication safety Protect against spoofing of employee names action"
    EmployeeNamesEvents := utils.FilterEventsOU(LogEvents, EmployeeNamesSetting, OU)
    LastEventEmployeeNames := utils.GetLastEvent(EmployeeNamesEvents)

    InboundEmailsSetting :=
        "Spoofing and authentication safety Protect against inbound emails spoofing your domain action"
    InboundEmailsEvents := utils.FilterEventsOU(LogEvents, InboundEmailsSetting, OU)
    LastEventInboundEmails := utils.GetLastEvent(InboundEmailsEvents)

    UnauthenticatedEmailsSetting :=
        "Spoofing and authentication safety Protect against any unauthenticated emails action"
    UnauthenticatedEmailsEvents := utils.FilterEventsOU(LogEvents, UnauthenticatedEmailsSetting, OU)
    LastEventUnauthenticatedEmails := utils.GetLastEvent(UnauthenticatedEmailsEvents)

    GroupEmailsSetting := concat("", [
        "Spoofing and authentication safety Protect your Groups from inbound emails spoofing ",
        "your domain action"
    ])
    GroupEmailsEvents := utils.FilterEventsOU(LogEvents, GroupEmailsSetting, OU)
    LastEventGroupEmails := utils.GetLastEvent(GroupEmailsEvents)

    # OU is non-compliant if any of the following are true
    true in [
        LastEventDomainNames.NewValue == "Show warning",
        LastEventEmployeeNames.NewValue == "Show warning",
        LastEventInboundEmails.NewValue == "Show warning",
        LastEventUnauthenticatedEmails.NewValue == "Show warning",
        LastEventUnauthenticatedEmails.NewValue == "No action",
        LastEventGroupEmails.NewValue == "Show warning"
    ]
}

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
} if {
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
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    NoSuchEvent7_6
}

tests contains {
    "PolicyId": GmailId7_6,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_6, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_6},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    not NoSuchEvent7_6
    Status := count(NonCompliantOUs7_6) == 0
}
#--

#
# Baseline GWS.GMAIL.7.7
#--

GmailId7_7 := utils.PolicyIdWithSuffix("GWS.GMAIL.7.7")

LogMessage7_7 := sprintf("%s %s %s", ["Spoofing and authentication safety",
                                      "Enable: automatically enables all",
                                      "future added settings"])

Check7_7_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsNoOU(LogEvents, LogMessage7_7)
    count(events) > 0
}

Check7_7_OK if {PolicyApiInUse}

NonComplianceMessage7_7(value) := sprintf("Automatically enable all future added settings is set to: %s",
                                          [value])

NonCompliantOUs7_7 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_7(GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage7_7, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs7_7 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_7(GetFriendlyEnabledValue(applyFuture))
} if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    applyFuture := settings.gmail_spoofing_and_authentication.applyFutureSettingsAutomatically
    applyFuture != true
}

tests contains {
    "PolicyId": GmailId7_7,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": false,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check7_7_OK
}

tests contains {
    "PolicyId": GmailId7_7,
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_7, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_7},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check7_7_OK
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

NonCompliantOUs8_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "User email uploads is set to",
        GetFriendlyEnabledValue(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_EMAIL_USER_IMPORT", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests contains {
    "PolicyId": GmailId8_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_EMAIL_USER_IMPORT", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": GmailId8_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs8_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs8_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_EMAIL_USER_IMPORT", utils.TopLevelOU)
    count(Events) > 0
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

default NoSuchEvent9_1(_) := false

NoSuchEvent9_1(TopLevelOU) := true if {
    SettingName := "IMAP_ACCESS"
    EventsIMAPAccess := utils.FilterEventsOU(LogEvents, SettingName, TopLevelOU)
    count(EventsIMAPAccess) == 0
} else := true if {
    SettingName := "ENABLE_POP_ACCESS"
    EventsPOPAccess := utils.FilterEventsOU(LogEvents, SettingName, TopLevelOU)
    count(EventsPOPAccess) == 0
}

GetFriendlyValue9_1(ImapEnabled, PopEnabled) := Description if {
    ImapEnabled == true
    PopEnabled == true
    Description := "POP and IMAP access are enabled"
} else := Description if {
    ImapEnabled == true
    PopEnabled == false
    Description := "IMAP access is enabled"
} else := Description if {
    ImapEnabled == false
    PopEnabled == true
    Description := "POP access is enabled"
} else := "Both POP and IMAP access are disabled"


NonCompliantOUs9_1 contains {
    "Name": OU,
    "Value": GetFriendlyValue9_1(ImapEnabled, PopEnabled)
}
if {
    some OU in utils.OUsWithEvents

    ImapEvents := utils.FilterEventsOU(LogEvents, "IMAP_ACCESS", OU)
    count(ImapEvents) > 0
    LastImapEvent := utils.GetLastEvent(ImapEvents)

    PopEvents := utils.FilterEventsOU(LogEvents, "ENABLE_POP_ACCESS", OU)
    count(PopEvents) > 0
    LastPopEvent := utils.GetLastEvent(PopEvents)

    ImapEnabled := (LastImapEvent.NewValue in {"DISABLED", "INHERIT_FROM_PARENT"}) == false
    PopEnabled := (LastPopEvent.NewValue in {"false", "INHERIT_FROM_PARENT"}) == false
    true in {
        ImapEnabled,
        PopEnabled
    }
}

NonCompliantGroups9_1 contains {
    "Name": Group,
    "Value": GetFriendlyValue9_1(ImapEnabled, PopEnabled)
}
if {
    some Group in utils.GroupsWithEvents

    ImapEvents := utils.FilterEventsGroup(LogEvents, "IMAP_ACCESS", Group)
    count(ImapEvents) > 0
    LastImapEvent := utils.GetLastEvent(ImapEvents)

    PopEvents := utils.FilterEventsGroup(LogEvents, "ENABLE_POP_ACCESS", Group)
    count(PopEvents) > 0
    LastPopEvent := utils.GetLastEvent(PopEvents)

    ImapEnabled := (LastImapEvent.NewValue in {"DISABLED", "INHERIT_FROM_PARENT"}) == false
    PopEnabled := (LastPopEvent.NewValue in {"false", "INHERIT_FROM_PARENT"}) == false
    true in {
        ImapEnabled,
        PopEnabled
    }
}

tests contains {
    "PolicyId": GmailId9_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    NoSuchEvent9_1(utils.TopLevelOU)
}

tests contains {
    "PolicyId": GmailId9_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs9_1, NonCompliantGroups9_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs9_1, "NonCompliantGroups": NonCompliantGroups9_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    not NoSuchEvent9_1(utils.TopLevelOU)

    Conditions := {count(NonCompliantOUs9_1) == 0, count(NonCompliantGroups9_1) == 0}
    Status := (false in Conditions) == false
}
#--

################
# GWS.GMAIL.10 #
################

#
# Baseline GWS.GMAIL.10.1
#--

GmailId10_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.10.1")

NonCompliantOUs10_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Automatically enable outlook sync is set to",
        GetFriendlyEnabledValue(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_OUTLOOK_SYNC", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests contains {
    "PolicyId": GmailId10_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_OUTLOOK_SYNC", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": GmailId10_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs10_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs10_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_OUTLOOK_SYNC", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs10_1) == 0
}
#--

#
# Baseline GWS.GMAIL.10.2
#--

GmailId10_2 := utils.PolicyIdWithSuffix("GWS.GMAIL.10.2")

# No implementation steps provided for this policy
tests contains {
    "PolicyId": GmailId10_2,
    "Criticality": "May/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--

################
# GWS.GMAIL.11 #
################

#
# Baseline GWS.GMAIL.11.1
#--

GmailId11_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.11.1")

LogMessage11_1 := "ENABLE_EMAIL_AUTOFORWARDING"

Check11_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage11_1, utils.TopLevelOU)
    count(events) > 0
}

Check11_1_OK if {PolicyApiInUse}

NonComplianceMessage11_1(value) := sprintf("Automatic email forwarding is set to: %s",
                                           [value])

NonCompliantOUs11_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage11_1(GetFriendlyEnabledValue(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage11_1, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

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
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check11_1_OK
}

tests contains {
    "PolicyId": GmailId11_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs11_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs11_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check11_1_OK
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

NonCompliantOUs12_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Allow per-user outbound gateways is set to",
        GetFriendlyEnabledValue(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "OUTBOUND_RELAY_ENABLED", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests contains {
    "PolicyId": GmailId12_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    Events := utils.FilterEventsOU(LogEvents, "OUTBOUND_RELAY_ENABLED", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": GmailId12_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs12_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs12_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "OUTBOUND_RELAY_ENABLED", utils.TopLevelOU)
    count(Events) > 0
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

LogMessage14_1 := "GmailIpWhitelistSpamFilteringProto is_empty"

Check14_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage14_1, utils.TopLevelOU)
    count(events) > 0
}

Check14_1_OK if {PolicyApiInUse}

NonComplianceMessage14_1(Value, OU) := sprintf("Email allowlists are %s in %s.",
                                               [Value, OU])

# Note that in the event logs, a STRING value of "false" means allowlists are
# enabled, but policy API checks for a boolean true value.

GetFriendlyValue14_1(Value) := "enabled" if {
    Value in {true, "false"}
} else := "disabled" if {
    Value in {false, "true"}
} else := Value

tests contains {
    "PolicyId": GmailId14_1,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": {LogMessage14_1: "No relevant event in the current logs"},
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check14_1_OK
}

tests contains {
    "PolicyId": GmailId14_1,
    "Criticality": "Should",
    "ReportDetails": NonComplianceMessage14_1(GetFriendlyValue14_1(LastEvent.NewValue),
                                              utils.TopLevelOU),
    "ActualValue": {LastEvent.Setting: LastEvent.NewValue},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage14_1, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    Status := LastEvent.NewValue == "true"
}

# This test applies only to the policy API - it is NOT shared with the events
# implementation.  Similar to the above events implementation test, this test
# always returns a result, even if gmail is disabled - see how this is
# implemented by converting the enable status to 1/0 (whereas a false value
# would fail the tests conditional).

tests contains {
    "PolicyId": GmailId14_1,
    "Criticality": "Should",
    "ReportDetails": NonComplianceMessage14_1(GetFriendlyValue14_1(allowListCount > 0),
                                              utils.TopLevelOU),
    "ActualValue": {utils.TopLevelOU: allowList},
    "RequirementMet": allowListCount == 0,
    "NoSuchEvent": false
}
if {
    PolicyApiInUse
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

LogMessage15_1 := "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"

Check15_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage15_1, utils.TopLevelOU)
    count(events) > 0
}

Check15_1_OK if {PolicyApiInUse}

NonComplianceMessage15_1(value) := sprintf("Enhanced pre-delivery message scanning is %s",
                                           [value])

GetFriendlyValue15_1(Value) := "enabled" if {
    Value in {true, "false"}
} else := "disabled" if {
    Value in {false, "true"}
} else := Value

NonCompliantOUs15_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage15_1(GetFriendlyValue15_1(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage15_1, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs15_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage15_1(GetFriendlyValue15_1(preScanning))
} if {
    some OU, settings in input.policies
    GmailEnabled(OU)
    preDelivery := settings.gmail_enhanced_pre_delivery_message_scanning
    preScanning := preDelivery.enableImprovedSuspiciousContentDetection
    preScanning != true
}

tests contains {
    "PolicyId": GmailId15_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check15_1_OK
}

tests contains {
    "PolicyId": GmailId15_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs15_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs15_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check15_1_OK
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
    "Criticality": "Should/Not-Implemented",
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

# At this time we are unable to test because settings are configured in the GWS Admin Console
# and not available within the generated logs
tests contains {
    "PolicyId": GmailId18_2,
    "Criticality": "Should/Not-Implemented",
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

# At this time we are unable to test because settings are configured in the GWS Admin Console
# and not available within the generated logs
tests contains {
    "PolicyId": GmailId18_3,
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--

################
# GWS.GMAIL.19 #
################

#
# Baseline GWS.GMAIL.19.1
#--

GmailId19_1 := utils.PolicyIdWithSuffix("GWS.GMAIL.19.1")

# At this time we are unable to test because settings are configured in the GWS Admin Console
# and not available within the generated logs
tests contains {
    "PolicyId": GmailId19_1,
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--

#
# Baseline GWS.GMAIL.19.2
#--

GmailId19_2 := utils.PolicyIdWithSuffix("GWS.GMAIL.19.2")

tests contains {
    "PolicyId": GmailId19_2,
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--

#
# Baseline GWS.GMAIL.19.3
#--

GmailId19_3 := utils.PolicyIdWithSuffix("GWS.GMAIL.19.3")

tests contains {
    "PolicyId": GmailId19_3,
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--
