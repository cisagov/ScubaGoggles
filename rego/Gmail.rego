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

AllDomains := {Domain | some Domain in input.domains}

LogEvents := utils.GetEvents("gmail_logs")

###############
# GWS.GMAIL.1 #
###############

#
# Baseline GWS.GMAIL.1.1v0.3
#--

# Cannot be controlled at group level
GetFriendlyValue1_1(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Mail delegation is set to",
        GetFriendlyValue1_1(LastEvent.NewValue)
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
    "PolicyId": "GWS.GMAIL.1.1v0.3",
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
    "PolicyId": "GWS.GMAIL.1.1v0.3",
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
# Baseline GWS.GMAIL.2.1v0.3
#--

# Not applicable at OU or Group level
DomainsWithDkim contains DkimRecord.domain if {
    some DkimRecord in input.dkim_records
    some Rdata in DkimRecord.rdata
    startswith(Rdata, "v=DKIM1;")
}

tests contains {
    "PolicyId": "GWS.GMAIL.2.1v0.3",
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
# Baseline GWS.GMAIL.3.1v0.3
#--

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
    "PolicyId": "GWS.GMAIL.3.1v0.3",
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
# Baseline GWS.GMAIL.4.1v0.3
#--

# Not applicable at OU or Group level
DomainsWithDmarc contains DmarcRecord.domain if {
    some DmarcRecord in input.dmarc_records
    some Rdata in DmarcRecord.rdata
    startswith(Rdata, "v=DMARC1;")
}

tests contains {
    "PolicyId": "GWS.GMAIL.4.1v0.3",
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
# Baseline GWS.GMAIL.4.2v0.3
#--

# Not applicable at OU or Group level
DomainsWithPreject contains DmarcRecord.domain if {
    some DmarcRecord in input.dmarc_records
    some Rdata in DmarcRecord.rdata
    contains(Rdata, "p=reject;")
}

tests contains {
    "PolicyId": "GWS.GMAIL.4.2v0.3",
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
# Baseline GWS.GMAIL.4.3v0.3
#--

# Not applicable at OU or Group level
DomainsWithDHSContact contains DmarcRecord.domain if {
    some DmarcRecord in input.dmarc_records
    some Rdata in DmarcRecord.rdata
    contains(Rdata, "mailto:reports@dmarc.cyber.dhs.gov")
}

tests contains {
    "PolicyId": "GWS.GMAIL.4.3v0.3",
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
# Baseline GWS.GMAIL.4.4v0.3
#--

# Not applicable at OU or Group level
DomainsWithAgencyContact contains DmarcRecord.domain if {
    some DmarcRecord in input.dmarc_records
    some Rdata in DmarcRecord.rdata
    count(split(Rdata, "@")) >= 3
}

tests contains {
    "PolicyId": "GWS.GMAIL.4.4v0.3",
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
# Baseline GWS.GMAIL.5.1v0.3
#--

# Cannot be controlled at group level

GetFriendlyValue5_1(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Protection against encrypted attachments from untrusted senders is set to",
        GetFriendlyValue5_1(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, 
                concat("", ["Attachment safety Enable: ",
                    "protect against encrypted attachments from untrusted senders"]), OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
} if {
    DefaultSafe := true
    SettingName := "Attachment safety Enable: protect against encrypted attachments from untrusted senders"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Attachment safety Enable: protect against encrypted attachments from untrusted senders"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_1) == 0
}

#
# Baseline GWS.GMAIL.5.2v0.3
#--

GetFriendlyValue5_2(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs5_2 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Protection against encrypted attachments with scripts from untrusted senders is set to",
        GetFriendlyValue5_2(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, 
                concat("", ["Attachment safety Enable: ",
                    "protect against attachments with scripts from untrusted senders"]), OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.2v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    SettingName := "Attachment safety Enable: protect against attachments with scripts from untrusted senders"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.2v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Attachment safety Enable: protect against attachments with scripts from untrusted senders"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_2) == 0
}

#--

#
# Baseline GWS.GMAIL.5.3v0.3
#--

GetFriendlyValue5_3(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs5_3 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Protection against anomalous attachment types in emails is set to",
        GetFriendlyValue5_3(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents,
                concat("", ["Attachment safety Enable: Protect against anomalous attachment types in emails"]), OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.3v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Attachment safety Enable: Protect against anomalous attachment types in emails"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.3v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_3, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Attachment safety Enable: Protect against anomalous attachment types in emails"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_3) == 0
}
#--

#
# Baseline GWS.GMAIL.5.4v0.3
#--

GetFriendlyValue5_4(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs5_4 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Automatically enables all future added settings is set to",
        GetFriendlyValue5_4(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, concat("", ["Attachment safety Enable: ",
                                                "automatically enables all future added settings"]), OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.4v0.3",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    SettingName := "Attachment safety Enable: automatically enables all future added settings"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.4v0.3",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_4, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Attachment safety Enable: automatically enables all future added settings"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_4) == 0
}
#--

#
# Baseline GWS.GMAIL.5.5v0.3
#--

default NoSuchEvent5_5 := false
NoSuchEvent5_5 := true if {
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

GetFriendlyValue5_5(NewValueA, NewValueB, NewValueC) :=
    "Emails with encrypted attachments from untrusted senders are kept in the inbox"
    if {
        NewValueA == "Show warning"
    } else := "Emails with attachments, with scripts from untrusted senders are kept in the inbox"
    if { NewValueB == "Show warning" }
    else := "Emails with anamolous attachements are kept in the inbox"
    if { NewValueC == "Show warning" }
    else := "Emails flagged by the attachment protection controls are not kept in the inbox"

NonCompliantOUs5_5 contains {
    "Name": OU,
    "Value": GetFriendlyValue5_5(LastEvent_A.NewValue, LastEvent_B.NewValue, LastEvent_C.NewValue)
} if {
    some OU in utils.OUsWithEvents
    Events_A := utils.FilterEventsOU(LogEvents, "Attachment safety Encrypted attachment protection setting action", OU)
    count(Events_A) > 0
    LastEvent_A := utils.GetLastEvent(Events_A)

    Events_B := utils.FilterEventsOU(LogEvents, "Attachment safety Attachment with scripts protection action", OU)
    count(Events_B) > 0
    LastEvent_B := utils.GetLastEvent(Events_B)

    Events_C := utils.FilterEventsOU(LogEvents, "Attachment safety Anomalous attachment protection setting action", OU)
    count(Events_C) > 0
    LastEvent_C := utils.GetLastEvent(Events_C)

    # OU is non-compliant if any of the following are true
    true in [
        LastEvent_A.NewValue == "Show warning",
        LastEvent_B.NewValue == "Show warning",
        LastEvent_C.NewValue == "Show warning"
    ]
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.5v0.3",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    NoSuchEvent5_5
}

tests contains {
    "PolicyId": "GWS.GMAIL.5.5v0.3",
    "Criticality": "Should",
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
# Baseline GWS.GMAIL.5.6v0.3
#--
# No implementation steps provided for this policy
tests contains {
    "PolicyId": "GWS.GMAIL.5.6v0.3",
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
# Baseline GWS.GMAIL.6.1v0.3
#--

GetFriendlyValue6_1(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs6_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Identify links behind shortened URLs is",
        GetFriendlyValue6_1(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents,
                concat("", ["Links and external images safety Enable: identify links behind shortened URLs"]), OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.6.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    SettingName := "Links and external images safety Enable: identify links behind shortened URLs"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.6.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs6_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Links and external images safety Enable: identify links behind shortened URLs"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs6_1) == 0
}
#--

#
# Baseline GWS.GMAIL.6.2v0.3
#--

GetFriendlyValue6_2(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs6_2 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Scan linked images is",
        GetFriendlyValue6_2(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "Links and external images safety Enable: scan linked images", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.6.2v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    SettingName := "Links and external images safety Enable: scan linked images"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.6.2v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs6_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Links and external images safety Enable: scan linked images"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs6_2) == 0
}
#--

#
# Baseline GWS.GMAIL.6.3v0.3
#--

GetFriendlyValue6_3(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs6_3 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Show warning prompt for click on links to untrusted domains is",
        GetFriendlyValue6_3(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, concat("", ["Links and external images safety Enable: ",
                "show warning prompt for click on links to unstrusted domains"]), OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.6.3v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    SettingName := concat("", [
        "Links and external images safety Enable: show warning prompt for click on links to ",
        "unstrusted domains" # NOTE: "unstrusted" really is the spelling the API uses
    ])
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.6.3v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs6_3, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := concat("", [
        "Links and external images safety Enable: show warning prompt for click on links to ",
        "unstrusted domains" # NOTE: "unstrusted" really is the spelling the API uses
    ])
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs6_3) == 0
}
#--

#
# Baseline GWS.GMAIL.6.4v0.3
#--

GetFriendlyValue6_4(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs6_4 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Apply future recommended settings automatically is",
        GetFriendlyValue6_4(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents,
                concat("", ["Links and external images safety Enable: ",
                    "automatically enables all future added settings"]), OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.6.4v0.3",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    SettingName := "Links and external images safety Enable: automatically enables all future added settings"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.6.4v0.3",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs6_4, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Links and external images safety Enable: automatically enables all future added settings"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs6_4) == 0
}
#--

#
# Baseline GWS.GMAIL.6.5v0.3
#--
# No implementation steps provided for this policy
tests contains {
    "PolicyId": "GWS.GMAIL.6.5v0.3",
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
# Baseline GWS.GMAIL.7.1v0.3
#--

# No group level control

GetFriendlyValue7_1(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs7_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Protect against domain spoofing using similar domain names is set to",
        GetFriendlyValue7_1(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, concat("", [
        "Spoofing and authentication safety Enable: protect against domain spoofing using ",
        "similar domain names"
    ]), OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    SettingName := concat("", [
        "Spoofing and authentication safety Enable: protect against domain spoofing using ",
        "similar domain names"
    ])
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := concat("", [
        "Spoofing and authentication safety Enable: protect against domain spoofing using ",
        "similar domain names"
    ])
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs7_1) == 0
}
#--

#
# Baseline GWS.GMAIL.7.2v0.3
#--

GetFriendlyValue7_2(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs7_2 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Protect against spoofing of employee names is set to",
        GetFriendlyValue7_2(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents,
                concat("", ["Spoofing and authentication safety Enable: ",
                    "protect against spoofing of employee names"]), OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.2v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    SettingName := concat("", ["Spoofing and authentication safety Enable: ",
                    "protect against spoofing of employee names"])
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.2v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := concat("", ["Spoofing and authentication safety Enable: ",
                    "protect against spoofing of employee names"])
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs7_2) == 0
}
#--

#
# Baseline GWS.GMAIL.7.3v0.3
#--

GetFriendlyValue7_3(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs7_3 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Protect against inbound emails spoofing your domain is set to",
        GetFriendlyValue7_3(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents,
                concat("", ["Spoofing and authentication safety Enable: ",
                "protect against inbound emails spoofing your domain"]), OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs7_3 contains OU if {
    some OU in utils.OUsWithEvents
    SettingName := "Spoofing and authentication safety Enable: protect against inbound emails spoofing your domain"
    Events := utils.FilterEventsOU(LogEvents, SettingName, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.3v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    SettingName := "Spoofing and authentication safety Enable: protect against inbound emails spoofing your domain"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.3v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_3, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Spoofing and authentication safety Enable: protect against inbound emails spoofing your domain"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs7_3) == 0
}
#--

#
# Baseline GWS.GMAIL.7.4v0.3
#--

GetFriendlyValue7_4(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs7_4 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Protect against any unauthenticated emails is set to",
        GetFriendlyValue7_4(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents,
                concat("", ["Spoofing and authentication safety Enable: ",
                    "protect against any unauthenticated emails"]), OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.4v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Spoofing and authentication safety Enable: protect against any unauthenticated emails"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.4v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_4, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Spoofing and authentication safety Enable: protect against any unauthenticated emails"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs7_4) == 0
}
#--

#
# Baseline GWS.GMAIL.7.5v0.3
#--

GetFriendlyValue7_5(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs7_5 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Protect your Groups from inbound emails spoofing your domain is set to",
        GetFriendlyValue7_5(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, concat("", [
        "Spoofing and authentication safety Enable: protect your Groups from inbound emails ",
        "spoofing your domain"
    ]), OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.5v0.3",
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
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.5v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_5, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_5},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := concat("", [
        "Spoofing and authentication safety Enable: protect your Groups from inbound emails ",
        "spoofing your domain"
    ])
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs7_5) == 0
}
#--

#
# Baseline GWS.GMAIL.7.6v0.3
#--

# No such event is true if any of the revelant settings doesn't having any events
default NoSuchEvent7_6 := false
NoSuchEvent7_6 := true if {
    SettingName :=
        "Spoofing and authentication safety Protect against domain spoofing based on similar domain names action"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
} else := true if {
    SettingName := "Spoofing and authentication safety Protect against spoofing of employee names action"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
} else := true if {
    SettingName := "Spoofing and authentication safety Protect against inbound emails spoofing your domain action"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
} else := true if {
    SettingName := "Spoofing and authentication safety Protect against any unauthenticated emails action"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
} else := true if {
    SettingName :=
        "Spoofing and authentication safety Protect your Groups from inbound emails spoofing your domain action"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

GetFriendlyValue7_6(NewValueA, NewValueB, NewValueC, NewValueD, NewValueE) :=
    "Inbound emails spoofing domain names are kept in the inbox"
    if {
        NewValueA == "Show warning"
    } else := "Inbound emails spoofing employee names are kept in the inbox"
    if { NewValueB == "Show warning" }
    else := "Inbound spoofing emails are kept in the inbox"
    if { NewValueC == "Show warning" }
    else := "Unauthenticated emails are kept in the inbox"
    if { NewValueD == "Show warning" }
    else := "Unauthenticated emails are kept in the inbox"
    if { NewValueD == "No action" }
    else := "Inbound spoofing emails addresed to groups are kept in the inbox"
    if { NewValueE == "Show warning" }
    else := "Emails flagged by the spoofing and authentication controls are not kept in the inbox"

NonCompliantOUs7_6 contains {
    "Name": OU,
    "Value": GetFriendlyValue7_6(LastEventA.NewValue, LastEventB.NewValue, LastEventC.NewValue,
        LastEventD.NewValue, LastEventE.NewValue)
} if {
    some OU in utils.OUsWithEvents

    SettingA := concat("", [
        "Spoofing and authentication safety Protect against domain spoofing based on ",
        "similar domain names action"
    ])
    EventsA := utils.FilterEventsOU(LogEvents, SettingA, OU)
    LastEventA := utils.GetLastEvent(EventsA)

    SettingB := "Spoofing and authentication safety Protect against spoofing of employee names action"
    EventsB := utils.FilterEventsOU(LogEvents, SettingB, OU)
    LastEventB := utils.GetLastEvent(EventsB)

    SettingC := "Spoofing and authentication safety Protect against inbound emails spoofing your domain action"
    EventsC := utils.FilterEventsOU(LogEvents, SettingC, OU)
    LastEventC := utils.GetLastEvent(EventsC)

    SettingD := "Spoofing and authentication safety Protect against any unauthenticated emails action"
    EventsD := utils.FilterEventsOU(LogEvents, SettingD, OU)
    LastEventD := utils.GetLastEvent(EventsD)

    SettingE := concat("", [
        "Spoofing and authentication safety Protect your Groups from inbound emails spoofing ",
        "your domain action"
    ])
    EventsE := utils.FilterEventsOU(LogEvents, SettingE, OU)
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
    "PolicyId": "GWS.GMAIL.7.6v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    NoSuchEvent7_6
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.6v0.3",
    "Criticality": "Should",
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
# Baseline GWS.GMAIL.7.7v0.3
#--

GetFriendlyValue7_7(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs7_7 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Automatically enable all future added settings is set to",
        GetFriendlyValue7_7(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents,
                concat("", ["Spoofing and authentication safety Enable: ",
                    "automatically enables all future added settings"]), OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.7.7v0.3",
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
    "PolicyId": "GWS.GMAIL.7.7v0.3",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_7, []),
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
# Baseline GWS.GMAIL.7.8v0.3
#--
# No implementation steps provided for this policy
tests contains {
    "PolicyId": "GWS.GMAIL.7.8v0.3",
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
# Baseline GWS.GMAIL.8.1v0.3
#--
GetFriendlyValue8_1(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs8_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "User email uploads is set to",
        GetFriendlyValue8_1(LastEvent.NewValue)
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
    "PolicyId": "GWS.GMAIL.8.1v0.3",
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
    "PolicyId": "GWS.GMAIL.8.1v0.3",
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
# Baseline GWS.GMAIL.9.1v0.3
#--
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

    ImapEnabled := (LastImapEvent.NewValue in ["DISABLED", "INHERIT_FROM_PARENT"]) == false
    PopEnabled := (LastPopEvent.NewValue in ["false", "INHERIT_FROM_PARENT"]) == false
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

    ImapEnabled := (LastImapEvent.NewValue in ["DISABLED", "INHERIT_FROM_PARENT"]) == false
    PopEnabled := (LastPopEvent.NewValue in ["false", "INHERIT_FROM_PARENT"]) == false
    true in {
        ImapEnabled,
        PopEnabled
    }
}

tests contains {
    "PolicyId": "GWS.GMAIL.9.1v0.3",
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
    "PolicyId": "GWS.GMAIL.9.1v0.3",
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
# Baseline GWS.GMAIL.10.1v0.3
#--

GetFriendlyValue10_1(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs10_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Automatically enable outlook sync is set to",
        GetFriendlyValue10_1(LastEvent.NewValue)
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
    "PolicyId": "GWS.GMAIL.10.1v0.3",
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
    "PolicyId": "GWS.GMAIL.10.1v0.3",
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
# Baseline GWS.GMAIL.10.2v0.3
#--
# No implementation steps provided for this policy
tests contains {
    "PolicyId": "GWS.GMAIL.10.2v0.3",
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
# Baseline GWS.GMAIL.11.1v0.3
#--

GetFriendlyValue11_1(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs11_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Automatically enable email autoforwarding is set to",
        GetFriendlyValue11_1(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_EMAIL_AUTOFORWARDING", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests contains {
    "PolicyId": "GWS.GMAIL.11.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_EMAIL_AUTOFORWARDING", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.11.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs11_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs11_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "ENABLE_EMAIL_AUTOFORWARDING", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs11_1) == 0
}
#--


################
# GWS.GMAIL.12 #
################

#
# Baseline GWS.GMAIL.12.1v0.3
#--

GetFriendlyValue12_1(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs12_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Allow per-user outbound gateways is set to",
        GetFriendlyValue12_1(LastEvent.NewValue)
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
    "PolicyId": "GWS.GMAIL.12.1v0.3",
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
    "PolicyId": "GWS.GMAIL.12.1v0.3",
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
# Baseline GWS.GMAIL.13.1v0.3
#--

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
    "PolicyId": "GWS.GMAIL.13.1v0.3",
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
    "PolicyId": "GWS.GMAIL.13.1v0.3",
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
# Baseline GWS.GMAIL.14.1v0.3
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
    "PolicyId": "GWS.GMAIL.14.1v0.3",
    "Criticality": "Should",
    "ReportDetails": concat("", [
        "No relevant event in the current logs. ",
        "While we are unable to determine the state from the logs, ",
        "the default setting is compliant; manual check recommended."
    ]),
    "ActualValue": {"EMAIL_SPAM_ALLOWLIST": "No relevant event in the current logs"},
    "RequirementMet": true,
    "NoSuchEvent": true
}
if {
    Events := utils.FilterEventsNoOU(LogEvents, "EMAIL_SPAM_ALLOWLIST")
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.14.1v0.3",
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
# Baseline GWS.GMAIL.15.1v0.3
#--

GetFriendlyValue15_1(Value) := "enabled" if {
    Value == "false"
} else := "disabled" if {
    Value == "true"
} else := Value

NonCompliantOUs15_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Enhanced pre-delivery message scanning is set to",
        GetFriendlyValue15_1(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, concat("",
                ["DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"]), OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.GMAIL.15.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    SettingName := "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GMAIL.15.1v0.3",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs15_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs15_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs15_1) == 0
}
#--

#
# Baseline GWS.GMAIL.15.2v0.3
#--
# No implementation steps provided for this policy
tests contains {
    "PolicyId": "GWS.GMAIL.15.2v0.3",
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
# Baseline GWS.GMAIL.16.1v0.3
#--

GetFriendlyValue16_1(Value) := "enabled" if {
    Value == "true"
} else := "disabled" if {
    Value == "false"
} else := Value

NonCompliantOUs16_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Security sandbox is",
        GetFriendlyValue16_1(LastEvent.NewValue)
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
    "PolicyId": "GWS.GMAIL.16.1v0.3",
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
    "PolicyId": "GWS.GMAIL.16.1v0.3",
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
# Baseline GWS.GMAIL.16.2v0.3
#--
# No implementation steps provided for this policy
tests contains {
    "PolicyId": "GWS.GMAIL.16.2v0.3",
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
# Baseline GWS.GMAIL.17.1v0.3
#--
# At this time we are unable to test because settings are configured in the GWS Admin Console
# and not available within the generated logs
tests contains {
    "PolicyId": "GWS.GMAIL.17.1v0.3",
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
# Baseline GWS.GMAIL.18.1v0.3
#--
# At this time we are unable to test because settings are configured in the GWS Admin Console
# and not available within the generated logs
tests contains {
    "PolicyId": "GWS.GMAIL.18.1v0.3",
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--

#
# Baseline GWS.GMAIL.18.2v0.3
#--
# At this time we are unable to test because settings are configured in the GWS Admin Console
# and not available within the generated logs
tests contains {
    "PolicyId": "GWS.GMAIL.18.2v0.3",
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--

#
# Baseline GWS.GMAIL.18.3v0.3
#--
# At this time we are unable to test because settings are configured in the GWS Admin Console
# and not available within the generated logs
tests contains {
    "PolicyId": "GWS.GMAIL.18.3v0.3",
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
# Baseline GWS.GMAIL.19.1v0.3
#--
# At this time we are unable to test because settings are configured in the GWS Admin Console
# and not available within the generated logs
tests contains {
    "PolicyId": "GWS.GMAIL.19.1v0.3",
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--

#
# Baseline GWS.GMAIL.19.2v0.3
#--
tests contains {
    "PolicyId": "GWS.GMAIL.19.2v0.3",
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--

#
# Baseline GWS.GMAIL.19.3v0.3
#--
tests contains {
    "PolicyId": "GWS.GMAIL.19.3v0.3",
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}
#--