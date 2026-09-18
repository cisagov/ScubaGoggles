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

# Google renamed this setting from the Alpha proto name to a display name.
# Evaluate both and use the most recent event so a later OFF is not
# overridden by a stale Alpha event.
GeminiBetaSettings := [
    "GenAiAlphaSettingsProto alpha_enabled",
    "Beta Gemini Features Beta Features enabled"
]

NonComplianceMessage2_1 := "Gemini Beta features are enabled."

GeminiBetaEventsOU(OU) := {
    Event |
    some Setting in GeminiBetaSettings
    some Event in utils.FilterEventsOU(LogEvents, Setting, OU)
}

GeminiBetaEventsGroup(Group) := {
    Event |
    some Setting in GeminiBetaSettings
    some Event in utils.FilterEventsGroup(LogEvents, Setting, Group)
}

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_1
} if {
    some OU in utils.OUsWithEvents
    Events := GeminiBetaEventsOU(OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

NonCompliantGroups2_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage2_1
} if {
    some Group in utils.GroupsWithEvents
    Events := GeminiBetaEventsGroup(Group)
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
    Events := GeminiBetaEventsOU(utils.TopLevelOU)
    count(Events) == 0
    DefaultSafe := true
}

tests contains {
    "PolicyId": GeminiId2_1,
    "Prerequisites": [
        "reports/v1/activities/list"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, NonCompliantGroups2_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1, "NonCompliantGroups": NonCompliantGroups2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := GeminiBetaEventsOU(utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs2_1) == 0, count(NonCompliantGroups2_1) == 0}
    Status := (false in Conditions) == false
}

##############
# GWS.GEMINI.3 #
##############

#
# Baseline GWS.GEMINI.3.1
#--

GeminiId3_1 := utils.PolicyIdWithSuffix("GWS.GEMINI.3.1")

tests contains {
    "PolicyId": GeminiId3_1,
    "Prerequisites": [],
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#
# Baseline GWS.GEMINI.3.2
#--

GeminiId3_2 := utils.PolicyIdWithSuffix("GWS.GEMINI.3.2")

tests contains {
    "PolicyId": GeminiId3_2,
    "Prerequisites": [],
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

##############
# GWS.GEMINI.4 #
##############

#
# Baseline GWS.GEMINI.4.1
#--

GeminiId4_1 := utils.PolicyIdWithSuffix("GWS.GEMINI.4.1")

tests contains {
    "PolicyId": GeminiId4_1,
    "Prerequisites": [],
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--