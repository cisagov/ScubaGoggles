package assuredcontrols

import future.keywords
import data.utils

LogEvents := utils.GetEvents("assuredcontrols_logs")

########################
# GWS.ASSUREDCONTROLS.1 #
########################

#
# Baseline GWS.ASSUREDCONTROLS.1.1
#--

AssuredControlsId1_1 := utils.PolicyIdWithSuffix("GWS.ASSUREDCONTROLS.1.1")

NonComplianceMessage1_1 := "Access approvals setting is disabled."

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1
}
if {
    some OU, settings in input.policies
    section := settings.access_approval_axa_user_scoping
    customerApproval := section.requiresCustomerApproval
    customerApproval != true
}

tests contains {
    "PolicyId": AssuredControlsId1_1,
    "Prerequisites": ["policy/access_approval_axa_user_scoping.requiresCustomerApproval"],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status
}
if {
    Status := count(NonCompliantOUs1_1) == 0
}

#--

#
# Baseline GWS.ASSUREDCONTROLS.1.2
#--

AssuredControlsId1_2 := utils.PolicyIdWithSuffix("GWS.ASSUREDCONTROLS.1.2")

GetFriendlyValue1_2(Value) := "unspecified" if {
    Value == "PREFERENCE_UNSPECIFIED"
} else := "allowed for EU Google staff" if {
    Value == "EU_GOOGLE_STAFF"
} else := Value

NonComplianceMessage1_2(value) := sprintf("Data access management is %s.",
                                          [value])

NonCompliantOUs1_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_2(GetFriendlyValue1_2(allowedAudience))
}
if {
    some OU, settings in input.policies
    section := settings.access_management_user_scoping
    allowedAudience := section.accessManagementRegime
    not allowedAudience in {"CJIS_IRS_1075_GOOGLE_STAFF", "US_GOOGLE_STAFF"}
}

tests contains {
    "PolicyId": AssuredControlsId1_2,
    "Prerequisites": ["policy/access_management_user_scoping.accessManagementRegime"],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_2, []),
    "ActualValue": "",
    "RequirementMet": Status
}
if {
    Status := count(NonCompliantOUs1_2) == 0
}

#--

########################
# GWS.ASSUREDCONTROLS.2 #
########################

#
# Baseline GWS.ASSUREDCONTROLS.2.1
#--

AssuredControlsId2_1 := utils.PolicyIdWithSuffix("GWS.ASSUREDCONTROLS.2.1")

MultiRegionsSettings := [
    "CalendarNonRegionalizedFunctionalityStateSettingsProto state",
    "DocsNonRegionalizedFunctionalityStateSettingsProto state",
    "GmailNonRegionalizedFunctionalityStateSettingsProto state",
    "ChatNonRegionalizedFunctionalityStateSettingsProto state",
    "MeetNonRegionalizedFunctionalityStateSettingsProto state",
    "GeminiNonRegionalizedFunctionalityStateSettingsProto state"
]

AppDisplayName(Setting) := "Calendar" if {
    Setting == "CalendarNonRegionalizedFunctionalityStateSettingsProto"
} else := "Drive and Docs" if {
    Setting == "DocsNonRegionalizedFunctionalityStateSettingsProto"
} else := "Gmail" if {
    Setting == "GmailNonRegionalizedFunctionalityStateSettingsProto"
} else := "Google Chat and classic Hangouts" if {
    Setting == "ChatNonRegionalizedFunctionalityStateSettingsProto"
} else := "Google Meet" if {
    Setting == "MeetNonRegionalizedFunctionalityStateSettingsProto"
} else := "Gemini app and Gemini in Google Workspace apps" if {
    Setting == "GeminiNonRegionalizedFunctionalityStateSettingsProto"
} else := split(Setting, "NonRegionalizedFunctionalityStateSettingsProto")[0]

AppsWithMultiRegionEnabledbyOU contains {
    "OU": OU,
    "Name": AppDisplayName(Setting)
}
if {
    some OU in utils.OUsWithEvents
    some Setting in MultiRegionsSettings
    Events := utils.FilterEventsOU(LogEvents, Setting, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "ENABLED"
}

AppsWithMultiRegionEnabledbyGroup contains {
    "Group": Group,
    "Name": AppDisplayName(Setting)
}
if {
    some Group in utils.GroupsWithEvents
    some Setting in MultiRegionsSettings
    Events := utils.FilterEventsGroup(LogEvents, Setting, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "ENABLED"
}

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Features that may process data across multiple regions are enabled for",
        concat(", ", AppsEnabled)
    ])
}
if {
    some OU in utils.OUsWithEvents
    AppsEnabled := {App["Name"] | some App in AppsWithMultiRegionEnabledbyOU; App["OU"] == OU}
    count(AppsEnabled) > 0
}

NonCompliantGroups2_1 contains {
    "Name": Group,
    "Value": concat(" ", [
        "Features that may process data across multiple regions are enabled for",
        concat(", ", AppsEnabled)
    ])
}
if {
    some Group in utils.GroupsWithEvents
    AppsEnabled := {App["Name"] | some App in AppsWithMultiRegionEnabledbyGroup; App["Group"] == Group}
    count(AppsEnabled) > 0
}

# If we don't have an event for every setting relevent to this policy for the
# top level OU, mark this as no such event, as we don't have all the data
# needed to make a determination.
default NoSuchEvent2_1 := false
NoSuchEvent2_1 := true if {
    some Setting in MultiRegionsSettings
    Events := utils.FilterEventsOU(LogEvents, Setting, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": AssuredControlsId2_1,
    "Prerequisites": ["reports/v1/activities/list"],
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": false,
    "NoSuchEvent": true
} if {
    DefaultSafe := false
    NoSuchEvent2_1 == true
}

tests contains {
    "PolicyId": AssuredControlsId2_1,
    "Prerequisites": ["reports/v1/activities/list"],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, NonCompliantGroups2_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1, "NonCompliantGroups": NonCompliantGroups2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
} if {
    not NoSuchEvent2_1
    Conditions := {
        count(NonCompliantOUs2_1) == 0,
        count(NonCompliantGroups2_1) == 0
    }
    Status := (false in Conditions) == false
}
#--
