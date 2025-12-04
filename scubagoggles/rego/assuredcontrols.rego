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

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": "Access approvals is disabled.",
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "Access Approvals enabled", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
}

NonCompliantGroups1_1 contains {
    "Name": Group,
    "Value": "Access approvals is disabled.",
}
if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, "Access Approvals enabled", Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
}

tests contains {
    "PolicyId": AssuredControlsId1_1,
    "Prerequisites": ["reports/v1/activities/list"],
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Access Approvals enabled"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": AssuredControlsId1_1,
    "Prerequisites": ["reports/v1/activities/list"],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, NonCompliantGroups1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1, "NonCompliantGroups": NonCompliantGroups1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Access Approvals enabled"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Conditions := {
        count(NonCompliantOUs1_1) == 0,
        count(NonCompliantGroups1_1) == 0
    }
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.ASSUREDCONTROLS.1.2
#--

AssuredControlsId1_2 := utils.PolicyIdWithSuffix("GWS.ASSUREDCONTROLS.1.2")

GetFriendlyValueAccessManagement(Value) := "No preference" if {
    Value == "PREFERENCE_UNSPECIFIED"
} else := "Access by CJIS-authorized and IRS 1075-authorized Google staff only" if {
    Value == "CJIS_IRS_1075_GOOGLE_STAFF"
} else := "Access by U.S. Google staff only" if {
    Value == "US_GOOGLE_STAFF"
} else := "Access by EU Google staff or via EU virtual desktop" if {
    Value == "EU_GOOGLE_STAFF"
} else := Value

NonComplianceMessage1_2(Value) := concat(" ", [
    "Access management policy is set to ",
    GetFriendlyValueAccessManagement(Value)
])

NonCompliantOUs1_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_2(settings.access_management_user_scoping.accessManagementRegime)
}
if {
    some OU, settings in input.policies
    not settings.access_management_user_scoping.accessManagementRegime in [
        "CJIS_IRS_1075_GOOGLE_STAFF",
        "US_GOOGLE_STAFF"
    ]
}

tests contains {
    "PolicyId": AssuredControlsId1_2,
    "Prerequisites": ["policy/access_management_user_scoping.accessManagementRegime"],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_2, []),
    "ActualValue": "",
    "RequirementMet": Status,
    "NoSuchEvent": false
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

# CalendarNonRegionalizedFunctionalityStateSettingsProto
# DocsNonRegionalizedFunctionalityStateSettingsProto
# DocsNonRegionalizedFunctionalityStateSettingsProto
# GmailNonRegionalizedFunctionalityStateSettingsProto
# ChatNonRegionalizedFunctionalityStateSettingsProto
# MeetNonRegionalizedFunctionalityStateSettingsProto
# GeminiNonRegionalizedFunctionalityStateSettingsProto

tests contains {
    "PolicyId": AssuredControlsId2_1,
    "Prerequisites": [],
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--
