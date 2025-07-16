package gemini

import future.keywords
import data.utils

LogEvents := utils.GetEvents("gemini_logs")

GeminiEnabled(orgunit) := utils.AppEnabled(input.policies, "gemini_app", orgunit)

GeminiId1_1 := utils.PolicyIdWithSuffix("GWS.GEMINI.1.1")
GeminiId1_2 := utils.PolicyIdWithSuffix("GWS.GEMINI.1.2")
GeminiId2_1 := utils.PolicyIdWithSuffix("GWS.GEMINI.2.1")

ControlIDs := [GeminiId1_1, GeminiId1_2, GeminiId2_1]

GeminiSettings := {
    GeminiId1_1: "BardNonDuetEnablementProto enable_bard_non_duet_access",
    GeminiId1_2: "BardExtensionsFirstPartyProto allow_first_party_extensions",
    GeminiId2_1: "GenAiAlphaSettingsProto alpha_enabled"
}

GeminiNonCompDetails := {
    GeminiId1_1: "Gemini access regardless of license is enabled.",
    GeminiId1_2: "Gemini access to other Google apps is enabled.",
    GeminiId2_1: "Alpha Gemini features are enabled."
}

NonCompliantOUs contains {
    "Name": OU,
    "Value": GeminiNonCompDetails[data.ControlID]
} if {
    some OU in utils.OUsWithEvents
    GeminiEnabled(OU)
    Events := utils.FilterEventsOU(LogEvents, GeminiSettings[data.ControlID], OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

NonCompliantGroups contains {
    "Name": Group,
    "Value": GeminiNonCompDetails[data.ControlID]
} if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, GeminiSettings[data.ControlID], Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    GeminiEnabled(LastEvent.OrgUnit)
    LastEvent.NewValue == "true"
}

tests contains {
    "PolicyId": ControlID,
    "Prerequisites": [
        "reports/v1/activities/list",
        "policy/gemini_app_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    some ControlID in ControlIDs
    Events := utils.FilterEventsOU(LogEvents, GeminiSettings[ControlID], utils.TopLevelOU)
    count(Events) == 0
    DefaultSafe := true
}

tests contains {
    "PolicyId": ControlID,
    "Prerequisites": [
        "reports/v1/activities/list",
        "policy/gemini_app_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(OUs, Groups),
    "ActualValue": {"NonCompliantOUs": OUs, "NonCompliantGroups": Groups},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    some ControlID in ControlIDs
    Events := utils.FilterEventsOU(LogEvents, GeminiSettings[ControlID], utils.TopLevelOU)
    count(Events) > 0
    OUs := NonCompliantOUs with data.ControlID as ControlID
    Groups := NonCompliantGroups with data.ControlID as ControlID
    Conditions := {count(OUs) == 0, count(Groups) == 0}
    Status := (false in Conditions) == false
}
