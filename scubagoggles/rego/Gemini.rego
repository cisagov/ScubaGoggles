package gemini

import future.keywords
import data.utils

LogEvents := utils.GetEvents("gemini_logs")

GeminiAppEnabled(orgunit) := utils.AppEnabled(input.policies, "gemini_app", orgunit)

GeminiForWorkspaceEnabled(orgunit) := utils.AppEnabled(input.policies, "gemini_for_workspace", orgunit)

GeminiId1_1 := utils.PolicyIdWithSuffix("GWS.GEMINI.1.1")
GeminiId2_1 := utils.PolicyIdWithSuffix("GWS.GEMINI.2.1")

ControlIDs := [GeminiId1_1, GeminiId2_1]

GeminiSettings := {
    GeminiId1_1: "BardNonDuetEnablementProto enable_bard_non_duet_access",
    GeminiId2_1: "GenAiAlphaSettingsProto alpha_enabled"
}

GeminiNonCompDetails := {
    GeminiId1_1: "Gemini access regardless of license is enabled.",
    GeminiId2_1: "Alpha Gemini features are enabled."
}

# For GWS.GEMINI.1.1 (Gemini App Access)
NonCompliantOUs contains {
    "Name": OU,
    "Value": GeminiNonCompDetails[data.ControlID]
} if {
    some OU in utils.OUsWithEvents
    GeminiAppEnabled(OU)
    data.ControlID == GeminiId1_1
    Events := utils.FilterEventsOU(LogEvents, GeminiSettings[data.ControlID], OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

# For GWS.GEMINI.2.1 (Alpha Workspace features)
NonCompliantOUs contains {
    "Name": OU,
    "Value": GeminiNonCompDetails[data.ControlID]
} if {
    some OU in utils.OUsWithEvents
    GeminiForWorkspaceEnabled(OU)
    data.ControlID == GeminiId2_1
    Events := utils.FilterEventsOU(LogEvents, GeminiSettings[data.ControlID], OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

# For GWS.GEMINI.1.1 (Gemini App Access)
NonCompliantGroups contains {
    "Name": Group,
    "Value": GeminiNonCompDetails[data.ControlID]
} if {
    some Group in utils.GroupsWithEvents
    data.ControlID == GeminiId1_1
    Events := utils.FilterEventsGroup(LogEvents, GeminiSettings[data.ControlID], Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    GeminiAppEnabled(LastEvent.OrgUnit)
    LastEvent.NewValue == "true"
}

# For GWS.GEMINI.2.1 (Alpha Workspace features)
NonCompliantGroups contains {
    "Name": Group,
    "Value": GeminiNonCompDetails[data.ControlID]
} if {
    some Group in utils.GroupsWithEvents
    data.ControlID == GeminiId2_1
    Events := utils.FilterEventsGroup(LogEvents, GeminiSettings[data.ControlID], Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    GeminiForWorkspaceEnabled(LastEvent.OrgUnit)
    LastEvent.NewValue == "true"
}

# Test for GWS.GEMINI.1.1 with no events
tests contains {
    "PolicyId": GeminiId1_1,
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
    Events := utils.FilterEventsOU(LogEvents, GeminiSettings[GeminiId1_1], utils.TopLevelOU)
    count(Events) == 0
    DefaultSafe := true
}

# Test for GWS.GEMINI.2.1 with no events
tests contains {
    "PolicyId": GeminiId2_1,
    "Prerequisites": [
        "reports/v1/activities/list",
        "policy/gemini_for_workspace_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    Events := utils.FilterEventsOU(LogEvents, GeminiSettings[GeminiId2_1], utils.TopLevelOU)
    count(Events) == 0
    DefaultSafe := true
}

# Test for GWS.GEMINI.1.1 with events
tests contains {
    "PolicyId": GeminiId1_1,
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
    Events := utils.FilterEventsOU(LogEvents, GeminiSettings[GeminiId1_1], utils.TopLevelOU)
    count(Events) > 0
    OUs := NonCompliantOUs with data.ControlID as GeminiId1_1
    Groups := NonCompliantGroups with data.ControlID as GeminiId1_1
    Conditions := {count(OUs) == 0, count(Groups) == 0}
    Status := (false in Conditions) == false
}

# Test for GWS.GEMINI.2.1 with events
tests contains {
    "PolicyId": GeminiId2_1,
    "Prerequisites": [
        "reports/v1/activities/list",
        "policy/gemini_for_workspace_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(OUs, Groups),
    "ActualValue": {"NonCompliantOUs": OUs, "NonCompliantGroups": Groups},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, GeminiSettings[GeminiId2_1], utils.TopLevelOU)
    count(Events) > 0
    OUs := NonCompliantOUs with data.ControlID as GeminiId2_1
    Groups := NonCompliantGroups with data.ControlID as GeminiId2_1
    Conditions := {count(OUs) == 0, count(Groups) == 0}
    Status := (false in Conditions) == false
}
