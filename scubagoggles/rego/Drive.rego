package drive

import future.keywords
import data.utils

LogEvents := utils.GetEvents("drive_logs")

DriveEnabled(orgunit) := utils.AppEnabled(input.policies, "drive_and_docs", orgunit)

###################
# GWS.DRIVEDOCS.1 #
###################

#
# Baseline GWS.DRIVEDOCS.1.1
#--

DriveId1_1 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.1.1")

GetFriendlyValue1_1(Value) := "with Google accounts in compatible allowlisted domains" if {
    Value == "ALLOWLISTED_DOMAINS"
} else := "outside of the organization" if {
    Value == "ALLOWED"
} else := Value

NonComplianceMessage1_1(value) := sprintf("Files owned by users or shared drives can be shared %s",
                                          [value])

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
    "Prerequisites": [
        "policy/drive_and_docs_external_sharing.externalSharingMode",
        "policy/drive_and_docs_service_status.serviceState"
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

#
# Baseline GWS.DRIVEDOCS.1.2
#--

DriveId1_2 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.1.2")

EventGetFriendlyValue1_2(Value) := "cannot" if {
    Value == false
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
    "Prerequisites": [
        "policy/drive_and_docs_external_sharing.externalSharingMode",
        "policy/drive_and_docs_external_sharing.allowReceivingFilesOutsideAllowlistedDomains",
        "policy/drive_and_docs_service_status.serviceState"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs1_2) == 0
}
#--

#
# Baseline GWS.DRIVEDOCS.1.3
#--

DriveId1_3 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.1.3")

NonComplianceMessage1_3(Value) := sprintf("File sharing with %s domains, %s",
                                          [Value, "without warnings."])

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
    "Prerequisites": [
        "policy/drive_and_docs_external_sharing.externalSharingMode",
        "policy/drive_and_docs_external_sharing.warnForExternalSharing",
        "policy/drive_and_docs_external_sharing.warnForSharingOutsideAllowlistedDomains",
        "policy/drive_and_docs_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_3, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs1_3) == 0
}

#--

#
# Baseline GWS.DRIVEDOCS.1.4
#--

DriveId1_4 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.1.4")

NonComplianceMessage1_4(Value) := sprintf("File sharing with %s domains, %s",
                                          [Value, "with non-Google users."])

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
    "Prerequisites": [
        "policy/drive_and_docs_external_sharing.externalSharingMode",
        "policy/drive_and_docs_external_sharing.allowNonGoogleInvites",
        "policy/drive_and_docs_external_sharing.allowNonGoogleInvitesInAllowlistedDomains",
        "policy/drive_and_docs_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_4, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs1_4) == 0
}

#--

#
# Baseline GWS.DRIVEDOCS.1.5
#--

DriveId1_5 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.1.5")

NonComplianceMessage1_5 := "Published web content can be made visible to anyone with a link"

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
    "Prerequisites": [
        "policy/drive_and_docs_external_sharing.externalSharingMode",
        "policy/drive_and_docs_external_sharing.allowPublishingFiles",
        "policy/drive_and_docs_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_5, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_5},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs1_5) == 0
}
#--

#
# Baseline GWS.DRIVEDOCS.1.6
#--

DriveId1_6 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.1.6")

NonComplianceMessage1_6(value) := sprintf("Access Checker allows users to share files to %s",
                                          [value])

GetFriendlyValue1_6(Value) :=
"recipients only, suggested target audience, or public (no Google account required)" if {
    Value == "RECIPIENTS_OR_AUDIENCE_OR_PUBLIC"
} else := "recipients only, or suggested target audience" if {
    Value == "RECIPIENTS_OR_AUDIENCE"
} else := Value

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
    "Prerequisites": [
        "policy/drive_and_docs_external_sharing.accessCheckerSuggestions",
        "policy/drive_and_docs_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_6, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_6},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs1_6) == 0
}
#--

#
# Baseline GWS.DRIVEDOCS.1.7
#--

DriveId1_7 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.1.7")

NonComplianceMessage1_7(value) := sprintf("%s can distribute content outside of the organization",
                                          [value])

GetFriendlyValue1_7(Value):= "Setting is compliant." if {
    Value == "NONE"
} else := "Only users inside the organization" if {
    Value == "ELIGIBLE_INTERNAL_USERS"
} else := "Anyone" if {
    Value == "ALL_ELIGIBLE_USERS"
} else := Value

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
    "Prerequisites": [
        "policy/drive_and_docs_external_sharing.externalSharingMode",
        "policy/drive_and_docs_external_sharing.allowedPartiesForDistributingContent",
        "policy/drive_and_docs_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_7, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_7},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs1_7) == 0
}
#--

#
# Baseline GWS.DRIVEDOCS.1.8
#--

DriveId1_8 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.1.8")

NonComplianceMessage1_8(value) := sprintf("When users create items, the default access is set to: %s",
                                          [value])

GetFriendlyValue1_8(Value):= "private to the owner." if {
    Value == "PRIVATE_TO_OWNER"
} else := "the primary target audience can access the item if they have the link" if {
    Value == "PRIMARY_AUDIENCE_WITH_LINK"
} else := "the primary target audience can search and find the item." if {
    Value == "PRIMARY_AUDIENCE_WITH_LINK_OR_SEARCH"
} else := Value

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
    "Prerequisites": [
        "policy/drive_and_docs_general_access_default.defaultFileAccess",
        "policy/drive_and_docs_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_8, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_8},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs1_8) == 0
}
#--

###################
# GWS.DRIVEDOCS.2 #
###################

#
# Baseline GWS.DRIVEDOCS.2.1
#--

DriveId2_1 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.2.1")

NonComplianceMessage2_1 := "Members with manager access can override shared drive settings."

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
    "Prerequisites": [
        "policy/drive_and_docs_shared_drive_creation.allowManagersToOverrideSettings",
        "policy/drive_and_docs_service_status.serviceState"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs2_1) == 0
}
#--

#
# Baseline GWS.DRIVEDOCS.2.2
#--

DriveId2_2 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.2.2")

NonComplianceMessage2_2 := "Users outside the organization can access files in shared drives."

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
    "Prerequisites": [
        "policy/drive_and_docs_shared_drive_creation.allowExternalUserAccess",
        "policy/drive_and_docs_service_status.serviceState"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs2_2) == 0
}
#--

#
# Baseline GWS.DRIVEDOCS.2.3
#--

DriveId2_3 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.2.3")

NonComplianceMessage2_3 := "Users who aren't shared drive members are not allowed to be added to files."

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
    "Prerequisites": [
        "policy/drive_and_docs_shared_drive_creation.allowNonMemberAccess",
        "policy/drive_and_docs_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_3, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs2_3) == 0
}
#--

#
# Baseline GWS.DRIVEDOCS.2.4
#--

DriveId2_4 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.2.4")

NonComplianceMessage2_4 := "Viewers and commenters are allowed to download, print, and copy files."

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
    "Prerequisites": [
        "policy/drive_and_docs_shared_drive_creation.allowedPartiesForDownloadPrintCopy",
        "policy/drive_and_docs_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_4, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs2_4) == 0
}
#--

###################
# GWS.DRIVEDOCS.3 #
###################

#
# Baseline GWS.DRIVEDOCS.3.1
#--

DriveId3_1 := utils.PolicyIdWithSuffix("GWS.DRIVEDOCS.3.1")

NonComplianceMessage3_1(securityUpdate, userUpdate) := "The security update is removed from all impacted files." if {
    securityUpdate == "REMOVE_FROM_IMPACTED_FILES"
}
else := "Users are allowed to remove/apply the security update for files they own or manage." if {
    userUpdate == true
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
    "Prerequisites": [
        "policy/drive_and_docs_file_security_update.allowUsersToManageUpdate",
        "policy/drive_and_docs_file_security_update.securityUpdate",
        "policy/drive_and_docs_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs3_1, []),
    "ActualValue" : {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
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

NonComplianceMessage4_1 := "Drive SDK is enabled."

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
    "Prerequisites": [
        "policy/drive_and_docs_drive_sdk.enableDriveSdkApiAccess",
        "policy/drive_and_docs_service_status.serviceState"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs4_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs4_1) == 0
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
    events := utils.FilterEventsOU(LogEvents, LogMessage5_1, utils.TopLevelOU)
    count(events) > 0
}

NonComplianceMessage5_1 := "Users can install Google Docs add-ons from add-ons store."

NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_1
}
if {
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
    "Prerequisites": ["reports/v1/activities/list"],
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    not Check5_1_OK
}

tests contains {
    "PolicyId": DriveId5_1,
    "Prerequisites": ["reports/v1/activities/list"],
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

NonComplianceMessage6_1(Value) := sprintf("Drive for Desktop is %s.", [Value])

GetFriendlyValue6_1(CompanyOnly, DesktopEnabled) := "enabled and can be used on any device" if {
        CompanyOnly == false
        DesktopEnabled == true
    }
    else := "disabled" if {
        DesktopEnabled == false
    }
    else := "enabled but only on approved devices" if {
        CompanyOnly == true
        DesktopEnabled == true
    }

NonCompliantOUs6_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_1(GetFriendlyValue6_1(allowAuthorized,
                                                         desktopEnabled))
}
if {
    some OU, settings in input.policies
    DriveEnabled(OU)
    section := "drive_and_docs_drive_for_desktop"
    desktopSetting := "allowDriveForDesktop"
    desktopEnabled := utils.GetApiSettingValue(section, desktopSetting, OU)
    desktopEnabled
    desktopSet := utils.ApiSettingExists(section, desktopSetting, OU)
    authDevicesSetting := "restrictToAuthorizedDevices"
    allowAuthorized := utils.GetApiSettingValue(section, authDevicesSetting, OU)
    not allowAuthorized
    authDevicesSet := utils.ApiSettingExists(section, authDevicesSetting, OU)
    true in {desktopSet, authDevicesSet}
}

tests contains {
    "PolicyId": DriveId6_1,
    "Prerequisites": [
        "policy/drive_and_docs_drive_for_desktop.allowDriveForDesktop",
        "policy/drive_and_docs_drive_for_desktop.restrictToAuthorizedDevices",
        "policy/drive_and_docs_service_status.serviceState"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs6_1, []),
    "ActualValue" : {"NonCompliantOUs": NonCompliantOUs6_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs6_1) == 0
}
#--
