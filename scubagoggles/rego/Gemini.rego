package gemini

import future.keywords
import data.utils

LogEvents := utils.GetEvents("gemini_logs")

#
# Baseline GWS.GEMINI.1.1
#--

GeminiId1_1 := utils.PolicyIdWithSuffix("GWS.GEMINI.1.1")

NonComplianceSetting1_1 := "BardNonDuetEnablementProto enable_bard_non_duet_access"

NonComplianceMessage1_1 := "Gemini access regardless of license is enabled."

GeminiEnabled(orgunit) := utils.AppEnabled(input.policies, "gemini_app", orgunit)

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1
} if {
    some OU in utils.OUsWithEvents
    GeminiEnabled(OU)
    Events := utils.FilterEventsOU(LogEvents, NonComplianceSetting1_1, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

NonCompliantGroups1_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage1_1
} if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, NonComplianceSetting1_1, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    GeminiEnabled(LastEvent.OrgUnit)
    LastEvent.NewValue == "true"
}

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
    Events := utils.FilterEventsOU(LogEvents, NonComplianceSetting1_1, utils.TopLevelOU)
    count(Events) == 0
    DefaultSafe := true
}

tests contains {
    "PolicyId": GeminiId1_1,
    "Prerequisites": [
        "reports/v1/activities/list",
        "policy/gemini_app_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, NonCompliantGroups1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1, "NonCompliantGroups": NonCompliantGroups1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, NonComplianceSetting1_1, utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs1_1) == 0, count(NonCompliantGroups1_1) == 0}
    Status := (false in Conditions) == false
}

#
# Baseline GWS.GEMINI.2.1
#--

GeminiId2_1 := utils.PolicyIdWithSuffix("GWS.GEMINI.2.1")

NonComplianceSetting2_1 := "GenAiAlphaSettingsProto alpha_enabled"

NonComplianceMessage2_1 := "Alpha Gemini features are enabled."

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_1
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, NonComplianceSetting2_1, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

NonCompliantGroups2_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage2_1
} if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, NonComplianceSetting2_1, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests contains {
    "PolicyId": GeminiId2_1,
    "Prerequisites": [
        "reports/v1/activities/list"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    Events := utils.FilterEventsOU(LogEvents, NonComplianceSetting2_1, utils.TopLevelOU)
    count(Events) == 0
    DefaultSafe := true
}

tests contains {
    "PolicyId": GeminiId2_1,
    "Prerequisites": [
        "reports/v1/activities/list",
        "policy/gemini_app_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, NonCompliantGroups2_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1, "NonCompliantGroups": NonCompliantGroups2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, NonComplianceSetting2_1, utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs2_1) == 0, count(NonCompliantGroups2_1) == 0}
    Status := (false in Conditions) == false
}