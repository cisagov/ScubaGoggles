package gmail

import data.utils
import future.keywords

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

AllDomains contains Domain.domain if {
    some Domain in input.dkim_records
}

LogEvents := utils.GetEvents("gmail_logs")

###############
# GWS.GMAIL.1 #
###############

#
# Baseline GWS.GMAIL.1.1v0.1
#--
NonCompliantOUs1_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "ENABLE_MAIL_DELEGATION_WITHIN_DOMAIN", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests contains {
    "PolicyId": "GWS.GMAIL.1.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    Events := utils.FilterEvents(LogEvents, "ENABLE_MAIL_DELEGATION_WITHIN_DOMAIN", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.1.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents(LogEvents, "ENABLE_MAIL_DELEGATION_WITHIN_DOMAIN", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_1) == 0
}
#--

###############
# GWS.GMAIL.2 #
###############

#
# Baseline GWS.GMAIL.2.1v0.1
#--
DomainsWithDkim contains DkimRecord.domain if {
    some DkimRecord in input.dkim_records
    some Rdata in DkimRecord.rdata
    startswith(Rdata, "v=DKIM1;")
}

tests contains {
    "PolicyId": "GWS.GMAIL.2.1v0.1",
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
# Baseline GWS.GMAIL.3.1v0.1
#--
DomainsWithSpf contains SpfRecord.domain if {
    some SpfRecord in input.spf_records
    some Rdata in SpfRecord.rdata
    startswith(Rdata, "v=spf1 ")
}

tests contains {
    "PolicyId": "GWS.GMAIL.3.1v0.1",
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
# Baseline GWS.GMAIL.4.1v0.1
#--
DomainsWithDmarc contains DmarcRecord.domain if {
    some DmarcRecord in input.dmarc_records
    some Rdata in DmarcRecord.rdata
    startswith(Rdata, "v=DMARC1;")
}

tests contains {
    "PolicyId": "GWS.GMAIL.4.1v0.1",
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
# Baseline GWS.GMAIL.4.2v0.1
#--
DomainsWithPreject contains DmarcRecord.domain if {
    some DmarcRecord in input.dmarc_records
    some Rdata in DmarcRecord.rdata
    contains(Rdata, "p=reject;")
}

tests contains {
    "PolicyId": "GWS.GMAIL.4.2v0.1",
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
# Baseline GWS.GMAIL.4.3v0.1
#--
DomainsWithDHSContact contains DmarcRecord.domain if {
    some DmarcRecord in input.dmarc_records
    some Rdata in DmarcRecord.rdata
    contains(Rdata, "mailto:reports@dmarc.cyber.dhs.gov")
}

tests contains {
    "PolicyId": "GWS.GMAIL.4.3v0.1",
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
# Baseline GWS.GMAIL.4.4v0.1
#--
DomainsWithAgencyContact contains DmarcRecord.domain if {
    some DmarcRecord in input.dmarc_records
    some Rdata in DmarcRecord.rdata
    count(split(Rdata, "@")) >= 3
}

tests contains {
    "PolicyId": "GWS.GMAIL.4.4v0.1",
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
# Baseline GWS.GMAIL.5.1v0.1
#--
NonCompliantOUs5_1 contains OU if {
    some OU in utils.OUsWithEvents
    SettingName := "Attachment safety Enable: protect against encrypted attachments from untrusted senders"
    Events := utils.FilterEvents(LogEvents, SettingName, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
} if {
    DefaultSafe := false
    SettingName := "Attachment safety Enable: protect against encrypted attachments from untrusted senders"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs5_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Attachment safety Enable: protect against encrypted attachments from untrusted senders"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_1) == 0
}

#
# Baseline GWS.GMAIL.5.2v0.1
#--
NonCompliantOUs5_2 contains OU if {
    some OU in utils.OUsWithEvents
    SettingName := "Attachment safety Enable: protect against attachments with scripts from untrusted senders"
    Events := utils.FilterEvents(LogEvents, SettingName, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Attachment safety Enable: protect against attachments with scripts from untrusted senders"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs5_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Attachment safety Enable: protect against attachments with scripts from untrusted senders"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_2) == 0
}

EncryptedAttachmentSettingDetailsStr(LastEvent) := Description if {
    LastEvent.NewValue == "true"
    Description := concat("", [
        "<span class=setting>Attachment protection for encrypted attachments from untrusted senders is ",
        "enabled</span> in ",
        LastEvent.OrgUnit
    ])
}

EncryptedAttachmentSettingDetailsStr(LastEvent) := Description if {
    LastEvent.NewValue == "false"
    Description := concat("", [
        "<span class=setting>Attachment protection for encrypted attachments from untrusted senders is ",
        "not enabled</span> in ",
        LastEvent.OrgUnit
    ])
}
#--

#
# Baseline GWS.GMAIL.5.3v0.1
#--
NonCompliantOUs5_3 contains OU if {
    some OU in utils.OUsWithEvents
    SettingName := "Attachment safety Enable: Protect against anomalous attachment types in emails"
    Events := utils.FilterEvents(LogEvents, SettingName, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.3v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Attachment safety Enable: Protect against anomalous attachment types in emails"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.3v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs5_3),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Attachment safety Enable: Protect against anomalous attachment types in emails"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_3) == 0
}
#--

#
# Baseline GWS.GMAIL.5.4v0.1
#--
NonCompliantOUs5_4 contains OU if {
    some OU in utils.OUsWithEvents
    SettingName := "Attachment safety Enable: automatically enables all future added settings"
    Events := utils.FilterEvents(LogEvents, SettingName, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.4v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Attachment safety Enable: automatically enables all future added settings"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.4v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs5_4),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Attachment safety Enable: automatically enables all future added settings"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_4) == 0
}
#--

#
# Baseline GWS.GMAIL.5.5v0.1
#--
default NoSuchEvent5_5(_) := true

NoSuchEvent5_5(TopLevelOU) := false if {
    # No such event...
    SettingName := "Attachment safety Encrypted attachment protection setting action"
    Events := utils.FilterEvents(LogEvents, SettingName, TopLevelOU)
    count(Events) != 0
}

NoSuchEvent5_5(TopLevelOU) := false if {
    # No such event...
    SettingName := "Attachment safety Attachment with scripts protection action"
    Events := utils.FilterEvents(LogEvents, SettingName, TopLevelOU)
    count(Events) != 0
}

NoSuchEvent5_5(TopLevelOU) := false if {
    # No such event...
    SettingName := "Attachment safety Anomalous attachment protection setting action"
    Events := utils.FilterEvents(LogEvents, SettingName, TopLevelOU)
    count(Events) != 0
}

NonCompliantOUs5_5 contains OU if {
    some OU in utils.OUsWithEvents
    Events_A := utils.FilterEvents(LogEvents, "Attachment safety Encrypted attachment protection setting action", OU)
    count(Events_A) > 0
    LastEvent_A := utils.GetLastEvent(Events_A)

    Events_B := utils.FilterEvents(LogEvents, "Attachment safety Attachment with scripts protection action", OU)
    count(Events_B) > 0
    LastEvent_B := utils.GetLastEvent(Events_B)

    Events_C := utils.FilterEvents(LogEvents, "Attachment safety Anomalous attachment protection setting action", OU)
    count(Events_C) > 0
    LastEvent_C := utils.GetLastEvent(Events_C)

    true in [
        LastEvent_A.NewValue == "Show warning",
        LastEvent_B.NewValue == "Show warning",
        LastEvent_C.NewValue == "Show warning"
    ]
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.5v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    NoSuchEvent5_5(utils.TopLevelOU)
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.5v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs5_5),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_5},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    not NoSuchEvent5_5(utils.TopLevelOU)
    Status := count(NonCompliantOUs5_5) == 0
}
#--

#
# Baseline GWS.GMAIL.5.6v0.1
#--
# No implementation steps provided for this policy
tests contains {
    "PolicyId": "GWS.GMAIL.5.6v0.1",
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false}
#--

###############
# GWS.GMAIL.6 #
###############

#
# Baseline GWS.GMAIL.6.1v0.1
#--
NonCompliantOUs6_1 contains OU if {
    some OU in utils.OUsWithEvents
    SettingName := "Links and external images safety Enable: identify links behind shortened URLs"
    Events := utils.FilterEvents(LogEvents, SettingName, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.6.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Links and external images safety Enable: identify links behind shortened URLs"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.6.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs6_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Links and external images safety Enable: identify links behind shortened URLs"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs6_1) == 0
}
#--

#
# Baseline GWS.GMAIL.6.2v0.1
#--
NonCompliantOUs6_2 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "Links and external images safety Enable: scan linked images", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.6.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Links and external images safety Enable: scan linked images"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.6.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs6_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Links and external images safety Enable: scan linked images"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs6_2) == 0
}
#--

#
# Baseline GWS.GMAIL.6.3v0.1
#--
NonCompliantOUs6_3 contains OU if {
    some OU in utils.OUsWithEvents
    SettingName := concat("", [
        "Links and external images safety Enable: show warning prompt for click on links to ",
        "unstrusted domains" # NOTE: "unstrusted" really is the spelling the API uses
    ])
    Events := utils.FilterEvents(LogEvents, SettingName, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.6.3v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := concat("", [
        "Links and external images safety Enable: show warning prompt for click on links to ",
        "unstrusted domains" # NOTE: "unstrusted" really is the spelling the API uses
    ])
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.6.3v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs6_3),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := concat("", [
        "Links and external images safety Enable: show warning prompt for click on links to ",
        "unstrusted domains" # NOTE: "unstrusted" really is the spelling the API uses
    ])
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs6_3) == 0
}
#--

#
# Baseline GWS.GMAIL.6.4v0.1
#--
NonCompliantOUs6_4 contains OU if {
    some OU in utils.OUsWithEvents
    SettingName := "Links and external images safety Enable: automatically enables all future added settings"
    Events := utils.FilterEvents(LogEvents, SettingName, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.6.4v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Links and external images safety Enable: automatically enables all future added settings"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.6.4v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs6_4),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Links and external images safety Enable: automatically enables all future added settings"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs6_4) == 0
}
#--

#
# Baseline GWS.GMAIL.6.5v0.1
#--
# No implementation steps provided for this policy
tests contains {
    "PolicyId": "GWS.GMAIL.6.5v0.1",
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
# Baseline GWS.GMAIL.7.1v0.1
#--
NonCompliantOUs7_1 contains OU if {
    some OU in utils.OUsWithEvents
    SettingName := concat("", [
        "Spoofing and authentication safety Enable: protect against domain spoofing using ",
        "similar domain names"
    ])
    Events := utils.FilterEvents(LogEvents, SettingName, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := concat("", [
        "Spoofing and authentication safety Enable: protect against domain spoofing using ",
        "similar domain names"
    ])
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs7_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := concat("", [
        "Spoofing and authentication safety Enable: protect against domain spoofing using ",
        "similar domain names"
    ])
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs7_1) == 0
}
#--

#
# Baseline GWS.GMAIL.7.2v0.1
#--
NonCompliantOUs7_2 contains OU if {
    some OU in utils.OUsWithEvents
    SettingName := "Spoofing and authentication safety Enable: protect against spoofing of employee names"
    Events := utils.FilterEvents(LogEvents, SettingName, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Spoofing and authentication safety Enable: protect against spoofing of employee names"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs7_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Spoofing and authentication safety Enable: protect against spoofing of employee names"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs7_2) == 0
}
#--

#
# Baseline GWS.GMAIL.7.3v0.1
#--
NonCompliantOUs7_3 contains OU if {
    some OU in utils.OUsWithEvents
    SettingName := "Spoofing and authentication safety Enable: protect against inbound emails spoofing your domain"
    Events := utils.FilterEvents(LogEvents, SettingName, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.3v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Spoofing and authentication safety Enable: protect against inbound emails spoofing your domain"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.3v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs7_3),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Spoofing and authentication safety Enable: protect against inbound emails spoofing your domain"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs7_3) == 0
}
#--

#
# Baseline GWS.GMAIL.7.4v0.1
#--
NonCompliantOUs7_4 contains OU if {
    some OU in utils.OUsWithEvents
    SettingName := "Spoofing and authentication safety Enable: protect against any unauthenticated emails"
    Events := utils.FilterEvents(LogEvents, SettingName, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.4v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Spoofing and authentication safety Enable: protect against any unauthenticated emails"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.4v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs7_4),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Spoofing and authentication safety Enable: protect against any unauthenticated emails"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs7_4) == 0
}
#--

#
# Baseline GWS.GMAIL.7.5v0.1
#--

NonCompliantOUs7_5 contains OU if {
    some OU in utils.OUsWithEvents
    SettingName := concat("", [
        "Spoofing and authentication safety Enable: protect your Groups from inbound emails ",
        "spoofing your domain"
    ])
    Events := utils.FilterEvents(LogEvents, SettingName, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.5v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := concat("", [
        "Spoofing and authentication safety Enable: protect your Groups from inbound emails ",
        "spoofing your domain"
    ])
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.5v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs7_5),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_5},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := concat("", [
        "Spoofing and authentication safety Enable: protect your Groups from inbound emails ",
        "spoofing your domain"
    ])
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs7_5) == 0
}
#--

#
# Baseline GWS.GMAIL.7.6v0.1
#--

default NoSuchEvent7_6(_) := true

NoSuchEvent7_6(TopLevelOU) := false if {
    # No such event...
    SettingName := concat("", [
        "Spoofing and authentication safety Protect against domain spoofing based on similar ",
        "domain names action"
    ])
    Events := utils.FilterEvents(LogEvents, SettingName, TopLevelOU)
    count(Events) != 0
}

NoSuchEvent7_6(TopLevelOU) := false if {
    # No such event...
    SettingName := "Spoofing and authentication safety Protect against spoofing of employee names action"
    Events := utils.FilterEvents(LogEvents, SettingName, TopLevelOU)
    count(Events) != 0
}

NoSuchEvent7_6(TopLevelOU) := false if {
    # No such event...
    SettingName := concat("", [
        "Spoofing and authentication safety Protect against domain spoofing based on similar ",
        "domain names action"
    ])
    Events := utils.FilterEvents(LogEvents, SettingName, TopLevelOU)
    count(Events) != 0
}

NoSuchEvent7_6(TopLevelOU) := false if {
    # No such event...
    SettingName := "Spoofing and authentication safety Protect against any unauthenticated emails action"
    Events := utils.FilterEvents(LogEvents, SettingName, TopLevelOU)
    count(Events) != 0
}

NoSuchEvent7_6(TopLevelOU) := false if {
    # No such event...
    SettingName := concat("", [
        "Spoofing and authentication safety Protect your Groups from inbound emails spoofing ",
        "your domain action"
    ])
    Events := utils.FilterEvents(LogEvents, SettingName, TopLevelOU)
    count(Events) != 0
}

NonCompliantOUs7_6 contains OU if {
    some OU in utils.OUsWithEvents

    SettingA := concat("", [
        "Spoofing and authentication safety Protect against domain spoofing based on ",
        "similar domain names action"
    ])
    EventsA := utils.FilterEvents(LogEvents, SettingA, OU)
    count(EventsA) > 0
    LastEventA := utils.GetLastEvent(EventsA)

    SettingB := "Spoofing and authentication safety Protect against spoofing of employee names action"
    EventsB := utils.FilterEvents(LogEvents, SettingB, OU)
    count(EventsB) > 0
    LastEventB := utils.GetLastEvent(EventsB)

    SettingC := "Spoofing and authentication safety Protect against inbound emails spoofing your domain action"
    EventsC := utils.FilterEvents(LogEvents, SettingC, OU)
    count(EventsC) > 0
    LastEventC := utils.GetLastEvent(EventsC)

    SettingD := "Spoofing and authentication safety Protect against any unauthenticated emails action"
    EventsD := utils.FilterEvents(LogEvents, SettingD, OU)
    count(EventsD) > 0
    LastEventD := utils.GetLastEvent(EventsD)

    SettingE := concat("", [
        "Spoofing and authentication safety Protect your Groups from inbound emails spoofing ",
        "your domain action"
    ])
    EventsE := utils.FilterEvents(LogEvents, SettingE, OU)
    count(EventsE) > 0
    LastEventE := utils.GetLastEvent(EventsE)

    # OU is non-compliant if any of the following are true
    true in [
        LastEventA.NewValue == "Show warning",
        LastEventB.NewValue == "Show warning",
        LastEventC.NewValue == "Show warning",
        LastEventD.NewValue == "Show warning",
        LastEventD.NewValue == "No action",
        LastEventE.NewValue == "Show warning"
    ]
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.6v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    NoSuchEvent7_6(utils.TopLevelOU)
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.6v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs7_6),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_6},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    not NoSuchEvent7_6(utils.TopLevelOU)
    Status := count(NonCompliantOUs7_6) == 0
}
#--

#
# Baseline GWS.GMAIL.7.7v0.1
#--

NonCompliantOUs7_7 contains OU if {
    some OU in utils.OUsWithEvents
    SettingName := "Spoofing and authentication safety Enable: automatically enables all future added settings"
    Events := utils.FilterEvents(LogEvents, SettingName, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.7v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": false,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Spoofing and authentication safety Enable: automatically enables all future added settings"
    Events := utils.FilterEventsNoOU(LogEvents, SettingName)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.7v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs7_7),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_7},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Spoofing and authentication safety Enable: automatically enables all future added settings"
    Events := utils.FilterEventsNoOU(LogEvents, SettingName)
    count(Events) > 0
    Status := count(NonCompliantOUs7_7) == 0
}
#--

#
# Baseline GWS.GMAIL.7.8v0.1
#--
# No implementation steps provided for this policy
tests contains {
    "PolicyId": "GWS.GMAIL.7.8v0.1",
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
# Baseline GWS.GMAIL.8.1v0.1
#--
NonCompliantOUs8_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "ENABLE_EMAIL_USER_IMPORT", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests contains {
    "PolicyId": "GWS.GMAIL.8.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents(LogEvents, "ENABLE_EMAIL_USER_IMPORT", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.8.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs8_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs8_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents(LogEvents, "ENABLE_EMAIL_USER_IMPORT", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs8_1) == 0
}
#--

###############
# GWS.GMAIL.9 #
###############

#
# Baseline GWS.GMAIL.9.1v0.1
#--
NonCompliantOUs9_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "IMAP_ACCESS", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "DISABLED"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests contains {
    "PolicyId": "GWS.GMAIL.9.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents(LogEvents, "IMAP_ACCESS", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.9.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs9_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs9_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents(LogEvents, "IMAP_ACCESS", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs9_1) == 0
}
#--

#
# Baseline GWS.GMAIL.9.2v0.1
#--
NonCompliantOUs9_2 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "ENABLE_POP_ACCESS", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests contains {
    "PolicyId": "GWS.GMAIL.9.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents(LogEvents, "ENABLE_POP_ACCESS", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.9.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs9_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs9_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents(LogEvents, "ENABLE_POP_ACCESS", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs9_2) == 0
}
#--


################
# GWS.GMAIL.10 #
################

#
# Baseline GWS.GMAIL.10.1v0.1
#--
NonCompliantOUs10_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "ENABLE_OUTLOOK_SYNC", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests contains {
    "PolicyId": "GWS.GMAIL.10.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents(LogEvents, "ENABLE_OUTLOOK_SYNC", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.10.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs10_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs10_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents(LogEvents, "ENABLE_OUTLOOK_SYNC", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs10_1) == 0
}
#--


################
# GWS.GMAIL.11 #
################

#
# Baseline GWS.GMAIL.11.1v0.1
#--
NonCompliantOUs11_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "ENABLE_EMAIL_AUTOFORWARDING", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests contains {
    "PolicyId": "GWS.GMAIL.11.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents(LogEvents, "ENABLE_EMAIL_AUTOFORWARDING", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.11.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs11_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs11_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents(LogEvents, "ENABLE_EMAIL_AUTOFORWARDING", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs11_1) == 0
}
#--


################
# GWS.GMAIL.12 #
################

#
# Baseline GWS.GMAIL.12.1v0.1
#--
NonCompliantOUs12_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "OUTBOUND_RELAY_ENABLED", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests contains {
    "PolicyId": "GWS.GMAIL.12.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEvents(LogEvents, "OUTBOUND_RELAY_ENABLED", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.12.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs12_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs12_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEvents(LogEvents, "OUTBOUND_RELAY_ENABLED", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs12_1) == 0
}
#--


################
# GWS.GMAIL.13 #
################

#
# Baseline GWS.GMAIL.13.1v0.1
#--
NonCompliantOUs13_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "OutOfDomainWarningProto disable_untrusted_recipient_warning", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.13.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "OutOfDomainWarningProto disable_untrusted_recipient_warning"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.13.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs13_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs13_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "OutOfDomainWarningProto disable_untrusted_recipient_warning"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs13_1) == 0
}
#--


################
# GWS.GMAIL.14 #
################

#
# Baseline GWS.GMAIL.14.1v0.1
#--
EmailAllowlistSettingDetailsStr(LastEvent) := Description if {
    LastEvent.NewValue != "[]"
    Description := concat("", [
        "<span class=setting>Email allowlists are enabled </span> in ",
        LastEvent.DomainName,
        "."
    ])
}

EmailAllowlistSettingDetailsStr(LastEvent) := Description if {
    LastEvent.NewValue == "[]"
    Description := concat("", [
        "<span class=setting>Email allowlists are not enabled </span> in ",
        LastEvent.DomainName,
        "."
    ])
}

tests contains {
    "PolicyId": "GWS.GMAIL.14.1v0.1",
    "Criticality": "Should",
    "ReportDetails": concat("", [
        "No relevant event in the current logs. ",
        "While we are unable to determine the state from the logs, ",
        "the default setting is non-compliant; manual check recommended."
    ]),
    "ActualValue": {"EMAIL_SPAM_ALLOWLIST": "No relevant event in the current logs"},
    "RequirementMet": false,
    "NoSuchEvent": true
}
if {
    Events := utils.FilterEventsNoOU(LogEvents, "EMAIL_SPAM_ALLOWLIST")
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.14.1v0.1",
    "Criticality": "Should",
    "ReportDetails": EmailAllowlistSettingDetailsStr(LastEvent),
    "ActualValue": {LastEvent.Setting: LastEvent.NewValue},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsNoOU(LogEvents, "EMAIL_SPAM_ALLOWLIST")
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    Status := LastEvent.NewValue == "[]"
}
#--


################
# GWS.GMAIL.15 #
################

#
# Baseline GWS.GMAIL.15.1v0.1
#--
NonCompliantOUs15_1 contains OU if {
    some OU in utils.OUsWithEvents
    SettingName := "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
    Events := utils.FilterEvents(LogEvents, SettingName, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.15.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.15.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs15_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs15_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs15_1) == 0
}
#--


################
# GWS.GMAIL.16 #
################

#
# Baseline GWS.GMAIL.16.1v0.1
#--
NonCompliantOUs16_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEvents(LogEvents, "AttachmentDeepScanningSettingsProto deep_scanning_enabled", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}


tests contains {
    "PolicyId": "GWS.GMAIL.16.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "AttachmentDeepScanningSettingsProto deep_scanning_enabled"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.16.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs16_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs16_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "AttachmentDeepScanningSettingsProto deep_scanning_enabled"
    Events := utils.FilterEvents(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs16_1) == 0
}
#--


################
# GWS.GMAIL.17 #
################

#
# Baseline GWS.GMAIL.17.1v0.1
#--
# At this time we are unable to test because settings are configured in the GWS Admin Console
# and not available within the generated logs
tests contains {
    "PolicyId": "GWS.GMAIL.17.1v0.1",
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
# Baseline GWS.GMAIL.18.1v0.1
#--
# At this time we are unable to test because settings are configured in the GWS Admin Console
# and not available within the generated logs
tests contains {
    "PolicyId": "GWS.GMAIL.18.1v0.1",
    "Criticality": "Should/Not-Implemented",
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
# Baseline GWS.GMAIL.19.1v0.1
#--
# At this time we are unable to test because settings are configured in the GWS Admin Console
# and not available within the generated logs
tests contains {
    "PolicyId": "GWS.GMAIL.19.1v0.1",
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--