package drive

import future.keywords
import data.utils
import data.utils.GetFriendlyEnabledValue
import data.utils.PolicyApiInUse

LogEvents := utils.GetEvents("drive_logs")

DriveEnabled(orgunit) := utils.AppEnabled(input.policies, "drive_and_docs", orgunit)

###################
# GWS.DRIVEDOCS.1 #
###################

#
# Baseline GWS.DRIVEDOCS.1.1
#--

DriveId1_1 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.1.1")

LogMessage1_1 := "SHARING_OUTSIDE_DOMAIN"

Check1_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage1_1, utils.TopLevelOU)
    count(events) > 0
}

Check1_1_OK if {PolicyApiInUse}

GetFriendlyValue1_1(Value) := "with Google accounts in compatible allowlisted domains" if {
    Value in {"TRUSTED_DOMAINS", "ALLOWLISTED_DOMAINS"}
} else := "outside of the organization" if {
    Value in {"SHARING_ALLOWED", "ALLOWED"}
} else := Value

NonComplianceMessage1_1(value) := sprintf("Files owned by users or shared drives can be shared %s",
                                          [value])

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1(GetFriendlyValue1_1(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage1_1, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    AcceptableValues := {"SHARING_NOT_ALLOWED", "INHERIT_FROM_PARENT",
    "SHARING_NOT_ALLOWED_BUT_MAY_RECEIVE_FILES"}
    not LastEvent.NewValue in AcceptableValues
}

NonCompliantGroups1_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage1_1(GetFriendlyValue1_1(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage1_1, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    AcceptableValues := {"SHARING_NOT_ALLOWED", "INHERIT_FROM_PARENT",
    "SHARING_NOT_ALLOWED_BUT_MAY_RECEIVE_FILES"}
    not LastEvent.NewValue in AcceptableValues
}

# There are subsequent baselines that apply only if external sharing is
# allowed.  For a given OU, sharing is enabled if either it's enabled in
# the top-level OU or it has been enabled explicitly in the OU.  First,
# we have to determine if the setting is even present in the OU.  If it
# is not present, the top-level OU setting is checked; otherwise the
# OU setting takes precedence.

ExternalSharingAllowed(OU) := true if {
    externalSharing := utils.GetApiSettingValue("drive_and_docs_external_sharing",
                                                "externalSharingMode",
                                                OU)
    externalSharing != "DISALLOWED"
}

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1(GetFriendlyValue1_1(externalSharing))
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    externalSharing := settings.drive_and_docs_external_sharing.externalSharingMode
    externalSharing != "DISALLOWED"
}

tests contains {
    "PolicyId": DriveId1_1,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check1_1_OK
}

tests contains {
    "PolicyId": DriveId1_1,
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, NonCompliantGroups1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1, "NonCompliantGroups": NonCompliantGroups1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check1_1_OK
    Conditions := {count(NonCompliantOUs1_1) == 0, count(NonCompliantGroups1_1) == 0 }
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.DRIVEDOCS.1.2
#--

DriveId1_2 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.1.2")

LogMessage1_2 := "SHARING_OUTSIDE_DOMAIN"

Check1_2_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage1_2, utils.TopLevelOU)
    count(events) > 0
}

Check1_2_OK if {PolicyApiInUse}

EventGetFriendlyValue1_2(Value) := "cannot" if {
    Value in {"SHARING_NOT_ALLOWED INHERIT_FROM_PARENT", false}
} else := "can"

EventNonComplianceMessage1_2(value) := sprintf("Users %s receive files outside the domain",
                                          [value])

GetSharingValue(ShareSetting) := "allowlisted" if {
    ShareSetting == "ALLOWLISTED_DOMAINS"
} else := "any" if {
    ShareSetting == "ALLOWED"
} else := "no" if {
    ShareSetting == "DISALLOWED"
} else := ShareSetting

NonComplianceMessage1_2(Value) := sprintf("File sharing with %s domains, %s",
                                          [Value, "receiving files permitted."])

NonCompliantOUs1_2 contains {
    "Name": OU,
    "Value": EventNonComplianceMessage1_2(EventGetFriendlyValue1_2(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage1_2, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    AcceptableValues = {"SHARING_NOT_ALLOWED", "INHERIT_FROM_PARENT",
        "TRUSTED_DOMAINS_ALLOWED", "TRUSTED_DOMAINS_ALLOWED_WITH_WARNING"}
    not LastEvent.NewValue in AcceptableValues
}

NonCompliantGroups1_2 contains {
    "Name": Group,
    "Value": EventNonComplianceMessage1_2(EventGetFriendlyValue1_2(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage1_2, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    AcceptableValues = {"SHARING_NOT_ALLOWED", "INHERIT_FROM_PARENT",
        "TRUSTED_DOMAINS_ALLOWED", "TRUSTED_DOMAINS_ALLOWED_WITH_WARNING"}
    not LastEvent.NewValue in AcceptableValues
    }

NonCompliantOUs1_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_2(GetSharingValue("DISALLOWED"))
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    not ExternalSharingAllowed(OU)
    receiveExternal := settings.drive_and_docs_external_sharing.allowReceivingExternalFiles
    receiveExternal != false
}

NonCompliantOUs1_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_2(GetSharingValue(extShare))
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    section := "drive_and_docs_external_sharing"
    shareSetting := "externalSharingMode"
    extShare := utils.GetApiSettingValue(section, shareSetting, OU)
    extShare == "ALLOWLISTED_DOMAINS"
    extShareSet := utils.ApiSettingExists(section, shareSetting, OU)
    receiveSetting := "allowReceivingFilesOutsideAllowlistedDomains"
    receiveExternal := utils.GetApiSettingValue(section, receiveSetting, OU)
    receiveExternal != false
    receiveExternalSet := utils.ApiSettingExists(section, receiveSetting, OU)
    true in {extShareSet, receiveExternalSet}
}

tests contains {
    "PolicyId": DriveId1_2,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check1_2_OK
}

tests contains {
    "PolicyId": DriveId1_2,
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_2, NonCompliantGroups1_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_2,
        "NonCompliantGroups": NonCompliantGroups1_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check1_2_OK
    Conditions := {count(NonCompliantOUs1_2) == 0, count(NonCompliantGroups1_2) == 0 }
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.DRIVEDOCS.1.3
#--

DriveId1_3 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.1.3")

LogMessage1_3 := "SHARING_OUTSIDE_DOMAIN"

Check1_3_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage1_3, utils.TopLevelOU)
    count(events) > 0
}

Check1_3_OK if {PolicyApiInUse}

AcceptableValues1_3 := {"SHARING_ALLOWED_WITH_WARNING",
                        "SHARING_NOT_ALLOWED",
                        "INHERIT_FROM_PARENT",
                        "SHARING_NOT_ALLOWED_BUT_MAY_RECEIVE_FILES",
                        "TRUSTED_DOMAINS_ALLOWED_WITH_WARNING",
                        "TRUSTED_DOMAINS_ALLOWED_WITH_WARNING_MAY_RECEIVE_FILES_FROM_ANYONE"}

EventGetFriendlyValue1_3(Value) := "enabled" if {
    Value in AcceptableValues1_3 == true
} else := "disabled"

EventNonComplianceMessage1_3(value) := sprintf("External Sharing Warning is %s",
                                          [value])

NonComplianceMessage1_3(Value) := sprintf("File sharing with %s domains, %s",
                                          [Value, "without warnings."])

NonCompliantOUs1_3 contains {
    "Name": OU,
    "Value": EventNonComplianceMessage1_3(EventGetFriendlyValue1_3(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage1_3, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    not LastEvent.NewValue in AcceptableValues1_3
}

NonCompliantGroups1_3 contains {
    "Name": Group,
    "Value": EventNonComplianceMessage1_3(EventGetFriendlyValue1_3(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage1_3, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    not LastEvent.NewValue in AcceptableValues1_3
}

NonCompliantOUs1_3 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_3(GetSharingValue(extShare))
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    section := "drive_and_docs_external_sharing"
    shareSetting := "externalSharingMode"
    extShare := utils.GetApiSettingValue(section, shareSetting, OU)
    extShare == "ALLOWLISTED_DOMAINS"
    extShareSet := utils.ApiSettingExists(section, shareSetting, OU)
    warnSetting := "warnForSharingOutsideAllowlistedDomains"
    warnShared := utils.GetApiSettingValue(section, warnSetting, OU)
    warnShared != true
    warnSharedSet := utils.ApiSettingExists(section, warnSetting, OU)
    true in {extShareSet, warnSharedSet}
}

NonCompliantOUs1_3 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_3(GetSharingValue(extShare))
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    section := "drive_and_docs_external_sharing"
    shareSetting := "externalSharingMode"
    extShare := utils.GetApiSettingValue(section, shareSetting, OU)
    extShare == "ALLOWED"
    extShareSet := utils.ApiSettingExists(section, shareSetting, OU)
    warnSetting := "warnForExternalSharing"
    warnShared := utils.GetApiSettingValue(section, warnSetting, OU)
    warnShared != true
    warnSharedSet := utils.ApiSettingExists(section, warnSetting, OU)
    true in {extShareSet, warnSharedSet}
}

tests contains {
    "PolicyId": DriveId1_3,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check1_3_OK
}

tests contains {
    "PolicyId": DriveId1_3,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_3, NonCompliantGroups1_3),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_3,
        "NonCompliantGroups": NonCompliantGroups1_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check1_3_OK
    Conditions := {count(NonCompliantOUs1_3) == 0, count(NonCompliantGroups1_3) == 0}
    Status := (false in Conditions) == false
}

#--

#
# Baseline GWS.DRIVEDOCS.1.4
#--

DriveId1_4 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.1.4")

LogMessage1_4_A := "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"

LogMessage1_4_B := "SHARING_OUTSIDE_DOMAIN"

default NoSuchEvent1_4(_) := false

NoSuchEvent1_4(TopLevelOU) := true if {
    Events_A := utils.FilterEvents(LogEvents, LogMessage1_4_A, TopLevelOU)
    count(Events_A) == 0
}

NoSuchEvent1_4(TopLevelOU) := true if {
    Events_B := utils.FilterEvents(LogEvents, LogMessage1_4_B, TopLevelOU)
    count(Events_B) == 0
}

Check1_4_OK if {
    not PolicyApiInUse
    not NoSuchEvent1_4(utils.TopLevelOU)
}

Check1_4_OK if {PolicyApiInUse}

AcceptableValues1_4_A := {"NOT_ALLOWED", "INHERIT_FROM_PARENT", true}

AcceptableValues1_4_B := {"SHARING_NOT_ALLOWED", "INHERIT_FROM_PARENT"}

EventGetFriendlyValue1_4(Value_A, Value_B) := "disabled" if {
    Value_B in AcceptableValues1_4_B
} else := "enabled but sharing items to non-google accounts is disabled" if {
    Value_A in AcceptableValues1_4_A
} else := "enabled and items can be shared to non-google accounts"

EventNonComplianceMessage1_4(value) := sprintf("External Sharing is %s",
                                          [value])

NonComplianceMessage1_4(Value) := sprintf("File sharing with %s domains, %s",
                                          [Value, "with non-Google users."])

NonCompliantOUs1_4 contains {
    "Name": OU,
    "Value": EventNonComplianceMessage1_4(EventGetFriendlyValue1_4(LastEvent_A.NewValue,
                                                                   LastEvent_B.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events_A := utils.FilterEventsOU(LogEvents, LogMessage1_4_A, OU)
    count(Events_A) > 0
    LastEvent_A := utils.GetLastEvent(Events_A)

    Events_B := utils.FilterEventsOU(LogEvents, LogMessage1_4_B, OU)
    count(Events_B) > 0
    LastEvent_B := utils.GetLastEvent(Events_B)

    not LastEvent_A.NewValue in AcceptableValues1_4_A
    not LastEvent_B.NewValue in AcceptableValues1_4_B
}

NonCompliantGroups1_4 contains {
    "Name": Group,
    "Value": EventNonComplianceMessage1_4(EventGetFriendlyValue1_4(LastEvent_A.NewValue,
                                                                   LastEvent_B.NewValue))
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events_A := utils.FilterEventsGroup(LogEvents, LogMessage1_4_A, Group)
    count(Events_A) > 0
    LastEvent_A := utils.GetLastEvent(Events_A)

    Events_B := utils.FilterEventsGroup(LogEvents, LogMessage1_4_B, Group)
    count(Events_B) > 0
    LastEvent_B := utils.GetLastEvent(Events_B)

    not LastEvent_A.NewValue in AcceptableValues1_4_A
    not LastEvent_B.NewValue in AcceptableValues1_4_B
}

NonCompliantOUs1_4 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_4(GetSharingValue(extShare))
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    section := "drive_and_docs_external_sharing"
    shareSetting := "externalSharingMode"
    extShare := utils.GetApiSettingValue(section, shareSetting, OU)
    extShare == "ALLOWLISTED_DOMAINS"
    extShareSet := utils.ApiSettingExists(section, shareSetting, OU)
    nonGoogleSetting := "allowNonGoogleInvitesInAllowlistedDomains"
    nonGoogle := utils.GetApiSettingValue(section, nonGoogleSetting, OU)
    nonGoogle != false
    nonGoogleSet := utils.ApiSettingExists(section, nonGoogleSetting, OU)
    true in {extShareSet, nonGoogleSet}
}

NonCompliantOUs1_4 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_4(GetSharingValue(extShare))
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    section := "drive_and_docs_external_sharing"
    shareSetting := "externalSharingMode"
    extShare := utils.GetApiSettingValue(section, shareSetting, OU)
    extShare == "ALLOWED"
    extShareSet := utils.ApiSettingExists(section, shareSetting, OU)
    nonGoogleSetting := "allowNonGoogleInvites"
    nonGoogle := utils.GetApiSettingValue(section, nonGoogleSetting, OU)
    nonGoogle != false
    nonGoogleSet := utils.ApiSettingExists(section, nonGoogleSetting, OU)
    true in {extShareSet, nonGoogleSet}
}

tests contains {
    "PolicyId": DriveId1_4,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check1_4_OK
}

tests contains {
    "PolicyId": DriveId1_4,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_4, NonCompliantGroups1_4),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_4,
        "NonCompliantGroups": NonCompliantGroups1_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check1_4_OK
    Conditions := {count(NonCompliantOUs1_4) == 0, count(NonCompliantGroups1_4) == 0}
    Status := (false in Conditions) == false
}

#--

#
# Baseline GWS.DRIVEDOCS.1.5
#--

DriveId1_5 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.1.5")

LogMessage1_5 := "PUBLISHING_TO_WEB"

Check1_5_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage1_5, utils.TopLevelOU)
    count(events) > 0
}

Check1_5_OK if {PolicyApiInUse}

NonComplianceMessage1_5 := "Published web content can be made visible to anyone with a link"

NonCompliantOUs1_5 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_5
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage1_5, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("ALLOWED", LastEvent.NewValue) == true
}

NonCompliantGroups1_5 contains {
    "Name": Group,
    "Value": NonComplianceMessage1_5
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage1_5, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("ALLOWED", LastEvent.NewValue) == true
}

NonCompliantOUs1_5 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_5
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    section := "drive_and_docs_external_sharing"
    shareSetting := "externalSharingMode"
    extShare := utils.GetApiSettingValue(section, shareSetting, OU)
    extShare != "DISALLOWED"
    extShareSet := utils.ApiSettingExists(section, shareSetting, OU)
    allowPublishSetting := "allowPublishingFiles"
    allowPublish := utils.GetApiSettingValue(section, allowPublishSetting, OU)
    allowPublish != false
    allowPublishSet := utils.ApiSettingExists(section, allowPublishSetting, OU)
    true in {extShareSet, allowPublishSet}
}

tests contains {
    "PolicyId": DriveId1_5,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check1_5_OK
}

tests contains {
    "PolicyId": DriveId1_5,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_5, NonCompliantGroups1_5),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_5,
        "NonCompliantGroups": NonCompliantGroups1_5},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check1_5_OK
    Conditions := {count(NonCompliantOUs1_5) == 0, count(NonCompliantGroups1_5) == 0}
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.DRIVEDOCS.1.6
#--

DriveId1_6 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.1.6")

LogMessage1_6 := "SHARING_ACCESS_CHECKER_OPTIONS"

Check1_6_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage1_6, utils.TopLevelOU)
    count(events) > 0
}

Check1_6_OK if {PolicyApiInUse}

NonComplianceMessage1_6(value) := sprintf("Access Checker allows users to share files to %s",
                                          [value])

GetFriendlyValue1_6(Value) :=
"recipients only, suggested target audience, or public (no Google account required)" if {
    Value in {"ALL", "RECIPIENTS_OR_AUDIENCE_OR_PUBLIC"}
} else := "recipients only, or suggested target audience" if {
    Value in {"DOMAIN_OR_NAMED_PARTIES", "RECIPIENTS_OR_AUDIENCE"}
} else := Value

NonCompliantOUs1_6 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_6(GetFriendlyValue1_6(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage1_6, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    AcceptableValues := {"NAMED_PARTIES_ONLY", "INHERIT_FROM_PARENT"}
    not LastEvent.NewValue in AcceptableValues
}

NonCompliantGroups1_6 contains {
    "Name":Group,
    "Value": NonComplianceMessage1_6(GetFriendlyValue1_6(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage1_6, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    AcceptableValues := {"NAMED_PARTIES_ONLY", "INHERIT_FROM_PARENT"}
    not LastEvent.NewValue in AcceptableValues
}

NonCompliantOUs1_6 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_6(GetFriendlyValue1_6(accessCheck))
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    accessCheck := settings.drive_and_docs_external_sharing.accessCheckerSuggestions
    accessCheck != "RECIPIENTS_ONLY"
}

tests contains {
    "PolicyId": DriveId1_6,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check1_6_OK
}

tests contains {
    "PolicyId": DriveId1_6,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_6, NonCompliantGroups1_6),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_6,
        "NonCompliantGroups": NonCompliantGroups1_6},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check1_6_OK
    Conditions := {count(NonCompliantOUs1_6) == 0, count(NonCompliantGroups1_6) == 0}
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.DRIVEDOCS.1.7
#--

DriveId1_7 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.1.7")

LogMessage1_7 := "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"

Check1_7_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage1_7, utils.TopLevelOU)
    count(events) > 0
}

Check1_7_OK if {PolicyApiInUse}

NonComplianceMessage1_7(value) := sprintf("%s can distribute content outside of the organization",
                                          [value])

GetFriendlyValue1_7(Value):= "Setting is compliant." if {
    Value in {"CROSS_DOMAIN_MOVES_BLOCKED", "NONE"}
} else := "Only users inside the organization" if {
    Value in {"CROSS_DOMAIN_FROM_INTERNAL_ONLY", "ELIGIBLE_INTERNAL_USERS"}
} else := "Anyone" if {
    Value in {"CROSS_DOMAIN_FROM_INTERNAL_OR_EXTERNAL", "ALL_ELIGIBLE_USERS"}
} else := Value

NonCompliantOUs1_7 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_7(GetFriendlyValue1_7(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage1_7, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    SettingValue := "CROSS_DOMAIN_MOVES_BLOCKED INHERIT_FROM_PARENT"
    contains(SettingValue, LastEvent.NewValue) == false
}

NonCompliantGroups1_7 contains {
    "Name": Group,
    "Value": GetFriendlyValue1_7(LastEvent.NewValue)
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage1_7, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    SettingValue := "CROSS_DOMAIN_MOVES_BLOCKED INHERIT_FROM_PARENT"
    contains(SettingValue, LastEvent.NewValue) == false
}

NonCompliantOUs1_7 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_7(GetFriendlyValue1_7(moveContent))
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    section := "drive_and_docs_external_sharing"
    shareSetting := "externalSharingMode"
    extShare := utils.GetApiSettingValue(section, shareSetting, OU)
    extShare != "DISALLOWED"
    extShareSet := utils.ApiSettingExists(section, shareSetting, OU)
    moveContentSetting := "allowedPartiesForDistributingContent"
    moveContent := utils.GetApiSettingValue(section, moveContentSetting, OU)
    moveContent != "NONE"
    moveContentSet := utils.ApiSettingExists(section, moveContentSetting, OU)
    true in {extShareSet, moveContentSet}
}

tests contains {
    "PolicyId": DriveId1_7,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check1_7_OK
}

tests contains {
    "PolicyId": DriveId1_7,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_7, NonCompliantGroups1_7),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_7, "NonCompliantGroups": NonCompliantGroups1_7},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check1_7_OK
    Conditions := {count(NonCompliantOUs1_7) == 0, count(NonCompliantGroups1_7) == 0}
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.DRIVEDOCS.1.8
#--

DriveId1_8 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.1.8")

LogMessage1_8 := "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"

Check1_8_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage1_8, utils.TopLevelOU)
    count(events) > 0
}

Check1_8_OK if {PolicyApiInUse}

NonComplianceMessage1_8(value) := sprintf("When users create items, the default access is set to: %s",
                                          [value])

GetFriendlyValue1_8(Value):= "private to the owner." if {
    Value in {"PRIVATE", "PRIVATE_TO_OWNER"}
} else := "the primary target audience can access the item if they have the link" if {
    Value in {"PEOPLE_WITH_LINK", "PRIMARY_AUDIENCE_WITH_LINK"}
} else := "the primary target audience can search and find the item." if {
    Value in {"PUBLIC", "PRIMARY_AUDIENCE_WITH_LINK_OR_SEARCH"}
} else := Value

NonCompliantOUs1_8 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_8(GetFriendlyValue1_8(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage1_8, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "PRIVATE"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

NonCompliantGroups1_8 contains {
    "Name": Group,
    "Value": NonComplianceMessage1_8(GetFriendlyValue1_8(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage1_8, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "PRIVATE"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

NonCompliantOUs1_8 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_8(GetFriendlyValue1_8(defaultAccess))
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    defaultAccess := settings.drive_and_docs_general_access_default.defaultFileAccess
    defaultAccess != "PRIVATE_TO_OWNER"
}

tests contains {
    "PolicyId": DriveId1_8,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check1_8_OK
}

tests contains {
    "PolicyId": DriveId1_8,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_8, NonCompliantGroups1_8),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_8, "NonCompliantGroups": NonCompliantGroups1_8},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check1_8_OK
    Conditions := {count(NonCompliantOUs1_8) == 0, count(NonCompliantGroups1_8) == 0}
    Status := (false in Conditions) == false
}
#--

###################
# GWS.DRIVEDOCS.2 #
###################

#
# Baseline GWS.DRIVEDOCS.2.1
#--

DriveId2_1 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.2.1")

LogMessage2_1 := "Shared Drive Creation new_team_drive_admin_only"

Check2_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage2_1, utils.TopLevelOU)
    count(events) > 0
}

Check2_1_OK if {PolicyApiInUse}

NonComplianceMessage2_1 := "Members with manager access can override shared drive settings."

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_1
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage2_1, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("true", LastEvent.NewValue) == false
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantGroups2_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage2_1
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage2_1, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("true", LastEvent.NewValue) == false
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_1
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    managerOverride := settings.drive_and_docs_shared_drive_creation.allowManagersToOverrideSettings
    managerOverride != false
}

tests contains {
    "PolicyId": DriveId2_1,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check2_1_OK
}

tests contains {
    "PolicyId": DriveId2_1,
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, NonCompliantGroups2_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1, "NonCompliantGroups": NonCompliantGroups2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check2_1_OK
    Conditions := {count(NonCompliantOUs2_1) == 0, count(NonCompliantGroups2_1) == 0 }
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.DRIVEDOCS.2.2
#--

DriveId2_2 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.2.2")

LogMessage2_2 := "Shared Drive Creation new_team_drive_restricts_cross_domain_access"

Check2_2_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage2_2, utils.TopLevelOU)
    count(events) > 0
}

Check2_2_OK if {PolicyApiInUse}

NonComplianceMessage2_2 := "Users outside the organization can access files in shared drives."

NonCompliantOUs2_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_2
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage2_2, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("true", LastEvent.NewValue) == false
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantGroups2_2 contains {
    "Name": Group,
    "Value": NonComplianceMessage2_2
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage2_2, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("true", LastEvent.NewValue) == false
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs2_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_2
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    externalAccess := settings.drive_and_docs_shared_drive_creation.allowExternalUserAccess
    externalAccess != false
}

tests contains {
    "PolicyId": DriveId2_2,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check2_2_OK
}

tests contains {
    "PolicyId": DriveId2_2,
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_2, NonCompliantGroups2_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_2, "NonCompliantGroups": NonCompliantGroups2_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check2_2_OK
    Conditions := {count(NonCompliantOUs2_2) == 0, count(NonCompliantGroups2_2) == 0 }
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.DRIVEDOCS.2.3
#--

DriveId2_3 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.2.3")

LogMessage2_3 := "Shared Drive Creation new_team_drive_restricts_direct_access"

Check2_3_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage2_3, utils.TopLevelOU)
    count(events) > 0
}

Check2_3_OK if {PolicyApiInUse}

NonComplianceMessage2_3 := "Users who aren't shared drive members are not allowed to be added to files."

NonCompliantOUs2_3 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_3
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage2_3, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("true", LastEvent.NewValue) == false
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}
NonCompliantGroups2_3 contains {
    "Name": Group,
    "Value": NonComplianceMessage2_3
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage2_3, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("true", LastEvent.NewValue) == false
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs2_3 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_3
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    nonMemberAccess := settings.drive_and_docs_shared_drive_creation.allowNonMemberAccess
    nonMemberAccess != true
}

tests contains {
    "PolicyId": DriveId2_3,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check2_3_OK
}

tests contains {
    "PolicyId": DriveId2_3,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_3, NonCompliantGroups2_3),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_3,
        "NonCompliantGroups": NonCompliantGroups2_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check2_3_OK
    Conditions := {count(NonCompliantOUs2_3) == 0, count(NonCompliantGroups2_3) == 0 }
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.DRIVEDOCS.2.4
#--

DriveId2_4 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.2.4")

LogMessage2_4 := "Shared Drive Creation new_team_drive_restricts_download"

Check2_4_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage2_4, utils.TopLevelOU)
    count(events) > 0
}

Check2_4_OK if {PolicyApiInUse}

NonComplianceMessage2_4 := "Viewers and commenters are allowed to download, print, and copy files."

NonCompliantOUs2_4 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_4
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage2_4, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("false", LastEvent.NewValue) == true
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantGroups2_4 contains {
    "Name": Group,
    "Value": NonComplianceMessage2_4
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage2_4, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    contains("false", LastEvent.NewValue) == true
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs2_4 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_4
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    allowPrint := settings.drive_and_docs_shared_drive_creation.allowedPartiesForDownloadPrintCopy
    allowPrint != "EDITORS_ONLY"
}

tests contains {
    "PolicyId": DriveId2_4,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check2_4_OK
}

tests contains {
    "PolicyId": DriveId2_4,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_4, NonCompliantGroups2_4),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_4,
        "NonCompliantGroups": NonCompliantGroups2_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check2_4_OK
    Conditions := {count(NonCompliantOUs2_4) == 0, count(NonCompliantGroups2_4) == 0 }
    Status := (false in Conditions) == false
}
#--

###################
# GWS.DRIVEDOCS.3 #
###################

#
# Baseline GWS.DRIVEDOCS.3.1
#--

DriveId3_1 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.3.1")

LogMessage3_1a := "Link Security Update Settings allow_less_secure_link_user_restore"
LogMessage3_1b := "Link Security Update Settings less_secure_link_option"

default NoSuchEvent3_1(_) := false

NoSuchEvent3_1(TopLevelOU) := true if {
    Events_A := utils.FilterEventsOU(LogEvents, LogMessage3_1a, TopLevelOU)
    count(Events_A) == 0
}

NoSuchEvent3_1(TopLevelOU) := true if {
    Events := utils.FilterEventsOU(LogEvents, LogMessage3_1b, TopLevelOU)
    count(Events) == 0
}

Check3_1_OK if {
    not PolicyApiInUse
    not NoSuchEvent3_1(utils.TopLevelOU)
}

Check3_1_OK if {PolicyApiInUse}

NonComplianceMessage3_1(securityUpdate, userUpdate) := "The security update is removed from all impacted files." if {
    securityUpdate in {"REQUIRE_LESS_SECURE_LINKS", "REMOVE_FROM_IMPACTED_FILES"}
}
else := "Users are allowed to remove/apply the security update for files they own or manage." if {
    userUpdate in {"true", true}
}

NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage3_1(LastEvent_B.NewValue, LastEvent_A.NewValue)
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events_A := utils.FilterEventsOU(LogEvents, LogMessage3_1a, OU)
    count(Events_A) > 0
    LastEvent_A := utils.GetLastEvent(Events_A)

    Events_B := utils.FilterEventsOU(LogEvents, LogMessage3_1b, OU)
    count(Events_B) > 0
    LastEvent_B := utils.GetLastEvent(Events_B)

    true in {
        LastEvent_A.NewValue != "false",
        LastEvent_B.NewValue != "REMOVE_LESS_SECURE_LINKS"
    }
}

NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage3_1(securityUpdate, userUpdate)
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    userUpdate := settings.drive_and_docs_file_security_update.allowUsersToManageUpdate
    securityUpdate := settings.drive_and_docs_file_security_update.securityUpdate

    true in {
        userUpdate != false,
        securityUpdate != "APPLY_TO_IMPACTED_FILES"
    }
}

tests contains {
    "PolicyId": DriveId3_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check3_1_OK
}

tests contains {
    "PolicyId": DriveId3_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs3_1, []),
    "ActualValue" : {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check3_1_OK
    Status := count(NonCompliantOUs3_1) == 0
}
#--

###################
# GWS.DRIVEDOCS.4 #
###################

#
# Baseline GWS.DRIVEDOCS.4.1
#--

DriveId4_1 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.4.1")

LogMessage4_1 := "ENABLE_DRIVE_APPS"

Check4_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage4_1, utils.TopLevelOU)
    count(events) > 0
}

Check4_1_OK if {PolicyApiInUse}

NonComplianceMessage4_1 := "Drive SDK is enabled."

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage4_1
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage4_1, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}
NonCompliantGroups4_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage4_1
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage4_1, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage4_1
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    sdkAccess := settings.drive_and_docs_drive_sdk.enableDriveSdkApiAccess
    sdkAccess != false
}

tests contains {
    "PolicyId": DriveId4_1,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check4_1_OK
}

tests contains {
    "PolicyId": DriveId4_1,
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs4_1, NonCompliantGroups4_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1, "NonCompliantGroups": NonCompliantGroups4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check4_1_OK
    Conditions := {count(NonCompliantOUs4_1) == 0, count(NonCompliantGroups4_1) == 0}
    Status := (false in Conditions) == false
}

#--

###################
# GWS.DRIVEDOCS.5 #
###################

#
# Baseline GWS.DRIVEDOCS.5.1
#--

DriveId5_1 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.5.1")

LogMessage5_1 := "ENABLE_DOCS_ADD_ONS"

Check5_1_OK if {
    # not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage5_1, utils.TopLevelOU)
    count(events) > 0
}

# Check5_1_OK if {PolicyApiInUse}

NonComplianceMessage5_1 := "Users can install Google Docs add-ons from add-ons store."

NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_1
}
if {
    # not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage5_1, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

NonCompliantGroups5_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage5_1
}
if {
    # not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage5_1, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

# NOT yet implemented in policy API
#NonCompliantOUs5_1 contains {
#    "Name": OU,
#    "Value": NonComplianceMessage5_1
#}
#if {
#    some OU, settings in input.policies
#    DriveEnabled(OU)
#    addOns := settings.drive_and_docs_drive_sdk.enableDriveSdkApiAccess
#    addOns != false
#}

tests contains {
    "PolicyId": DriveId5_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    # not PolicyApiInUse
    DefaultSafe := false
    not Check5_1_OK
}

tests contains {
    "PolicyId": DriveId5_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_1, NonCompliantGroups5_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1,
        "NonCompliantGroups": NonCompliantGroups5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check5_1_OK
    Conditions := {count(NonCompliantOUs5_1) == 0, count(NonCompliantGroups5_1) == 0}
    Status := (false in Conditions) == false
}
#--

###################
# GWS.DRIVEDOCS.6 #
###################

#
# Baseline GWS.DRIVEDOCS.6.1
#--

DriveId6_1 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.6.1")

LogMessage6_1 := "ENABLE_DOCS_ADD_ONS"

LogMessage6_1a := "DriveFsSettingsProto drive_fs_enabled"
LogMessage6_1b := "DriveFsSettingsProto company_owned_only_enabled"

default NoSuchEvent6_1(_) := true

NoSuchEvent6_1(TopLevelOU) := false if {
    Events := utils.FilterEventsOU(LogEvents, LogMessage6_1a, TopLevelOU)
    count(Events) != 0
}

NoSuchEvent6_1(TopLevelOU) := false if {
    Events := utils.FilterEventsOU(LogEvents, LogMessage6_1b, TopLevelOU)
    count(Events) != 0
}

Check6_1_OK if {
    not PolicyApiInUse
    not NoSuchEvent6_1(utils.TopLevelOU)
}

Check6_1_OK if {PolicyApiInUse}

NonComplianceMessage6_1(Value) := sprintf("Drive for Desktop is %s.", [Value])

GetFriendlyValue6_1(CompanyOnly, DesktopEnabled) := "enabled and can be used on any device" if {
        CompanyOnly in {"false", false}
        DesktopEnabled in {"true", true}
    }
    else := "disabled" if {
        DesktopEnabled in {"false", false}
    }
    else := "enabled but only on approved devices" if {
        CompanyOnly in {"true", true}
        DesktopEnabled in {"true", true}
    }

NonCompliantOUs6_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_1(GetFriendlyValue6_1(LastCompanyOnlyEvent.NewValue,
                                                         LastDriveEnabledEvent.NewValue))
}
if {
        not PolicyApiInUse
        some OU in utils.OUsWithEvents

        DriveEnabledEvents := utils.FilterEventsOU(LogEvents, LogMessage6_1a, OU)
        count(DriveEnabledEvents) > 0
        LastDriveEnabledEvent := utils.GetLastEvent(DriveEnabledEvents)
        LastDriveEnabledEvent.NewValue != "DELETE_APPLICATION_SETTING"

        CompanyOnlyEvents := utils.FilterEventsOU(LogEvents, LogMessage6_1b, OU)
        count(CompanyOnlyEvents) > 0
        LastCompanyOnlyEvent := utils.GetLastEvent(CompanyOnlyEvents)
        LastCompanyOnlyEvent.NewValue != "DELETE_APPLICATION_SETTING"

        LastDriveEnabledEvent.NewValue == "true"
        LastCompanyOnlyEvent.NewValue != "true"
    }

NonCompliantGroups6_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage6_1(GetFriendlyValue6_1(LastCompanyOnlyEvent.NewValue,
                                                         LastDriveEnabledEvent.NewValue))
}
if {
        not PolicyApiInUse
        some Group in utils.GroupsWithEvents

        DriveEnabledEvents := utils.FilterEventsGroup(LogEvents, LogMessage6_1a, Group)
        count(DriveEnabledEvents) > 0
        LastDriveEnabledEvent := utils.GetLastEvent(DriveEnabledEvents)
        LastDriveEnabledEvent.NewValue != "DELETE_APPLICATION_SETTING"

        CompanyOnlyEvents := utils.FilterEventsGroup(LogEvents, LogMessage6_1b, Group)
        count(CompanyOnlyEvents) > 0
        LastCompanyOnlyEvent := utils.GetLastEvent(CompanyOnlyEvents)
        LastCompanyOnlyEvent.NewValue != "DELETE_APPLICATION_SETTING"

        LastDriveEnabledEvent.NewValue == "true"
        LastCompanyOnlyEvent.NewValue != "true"
    }

NonCompliantOUs6_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_1(GetFriendlyValue6_1(allowAuthorized,
                                                         desktopEnabled))
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    desktopEnabled := utils.GetApiSettingValue("drive_and_docs_drive_for_desktop",
                                               "allowDriveForDesktop",
                                               OU)
    allowAuthorized := utils.GetApiSettingValue("drive_and_docs_drive_for_desktop",
                                                "restrictToAuthorizedDevices",
                                                OU)
    desktopEnabled
    not allowAuthorized
}

tests contains {
    "PolicyId": DriveId6_1,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check6_1_OK
}

tests contains {
    "PolicyId": DriveId6_1,
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs6_1, NonCompliantGroups6_1),
    "ActualValue" : {"NonCompliantOUs": NonCompliantOUs6_1, "NonCompliantGroups": NonCompliantGroups6_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check6_1_OK
    Conditions := {count(NonCompliantOUs6_1) == 0, count(NonCompliantGroups6_1) == 0}
    Status := (false in Conditions) == false
}
#--
