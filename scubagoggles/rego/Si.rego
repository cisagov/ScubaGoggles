package si

import future.keywords
import data.utils

LogEvents := utils.GetEvents("si_logs")

#
# Baseline GWS.SI.1.1
#--

SIId1_1 := utils.PolicyIdWithSuffix("GWS.SI.1.1")

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
    "PolicyId": SIId1_1,
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
    "PolicyId": SIId1_1,
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
# Baseline GWS.SI.2.1
#--

SIId2_1 := utils.PolicyIdWithSuffix("GWS.SI.2.1")

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
    "PolicyId": SIId2_1,
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
    "PolicyId": SIId2_1,
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

##########
# GWS.SI.3 #
##########

#
# Baseline GWS.SI.3.1
#--

SIId3_1 := utils.PolicyIdWithSuffix("GWS.SI.3.1")

tests contains {
    "PolicyId": SIId3_1,
    "Prerequisites": [],
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#
# Baseline GWS.SI.3.2
#--

SIId3_2 := utils.PolicyIdWithSuffix("GWS.SI.3.2")

tests contains {
    "PolicyId": SIId3_2,
    "Prerequisites": [],
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

##########
# GWS.SI.4 #
##########

#
# Baseline GWS.SI.4.1
#--

SIId4_1 := utils.PolicyIdWithSuffix("GWS.SI.4.1")

tests contains {
    "PolicyId": SIId4_1,
    "Prerequisites": [],
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

##########
# GWS.SI.6 #
##########

#
# Baseline GWS.SI.6.1
#--

SIId6_1 := utils.PolicyIdWithSuffix("GWS.SI.6.1")

NonComplianceSetting6_1 := "MeetGenAiSmartNotesDocAccessProto manage_smart_notes_doc_access"

NonComplianceMessage6_1 := "Google AI notes sharing setting is set to: Allow hosts to change who notes are shared to."

NonCompliantOUs6_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_1
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, NonComplianceSetting6_1, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

NonCompliantGroups6_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage6_1
} if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, NonComplianceSetting6_1, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests contains {
    "PolicyId": SIId6_1,
    "Prerequisites": [
        "reports/v1/activities/list"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    Events := utils.FilterEventsOU(LogEvents, NonComplianceSetting6_1, utils.TopLevelOU)
    count(Events) == 0
    DefaultSafe := true
}

tests contains {
    "PolicyId": SIId6_1,
    "Prerequisites": [
        "reports/v1/activities/list"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs6_1, NonCompliantGroups6_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_1, "NonCompliantGroups": NonCompliantGroups6_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, NonComplianceSetting6_1, utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs6_1) == 0, count(NonCompliantGroups6_1) == 0}
    Status := (false in Conditions) == false
}

#--

#
# Baseline GWS.SI.6.2
#--

SIId6_2 := utils.PolicyIdWithSuffix("GWS.SI.6.2")

NonComplianceSetting6_2 := "MeetGenAiSmartNotesDocAccessProto default_smart_notes_doc_access"

NonComplianceMessage6_2 := "Default sharing setting for Google AI notes is set to: All invited guests."

NonCompliantOUs6_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage6_2
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, NonComplianceSetting6_2, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "EVERYONE"
}

NonCompliantGroups6_2 contains {
    "Name": Group,
    "Value": NonComplianceMessage6_2
} if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, NonComplianceSetting6_2, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "EVERYONE"
}

tests contains {
    "PolicyId": SIId6_2,
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
    Events := utils.FilterEventsOU(LogEvents, NonComplianceSetting6_2, utils.TopLevelOU)
    count(Events) == 0
    DefaultSafe := true
}

tests contains {
    "PolicyId": SIId6_2,
    "Prerequisites": [
        "reports/v1/activities/list"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs6_2, NonCompliantGroups6_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_2, "NonCompliantGroups": NonCompliantGroups6_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, NonComplianceSetting6_2, utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs6_2) == 0, count(NonCompliantGroups6_2) == 0}
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.SI.6.3
#--

SIId6_3 := utils.PolicyIdWithSuffix("GWS.SI.6.3")

tests contains {
    "PolicyId": SIId6_3,
    "Prerequisites": [],
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": false
}

#--

##########
# GWS.SI.7 #
##########

#
# Baseline GWS.SI.7.1
#--

SIId7_1 := utils.PolicyIdWithSuffix("GWS.SI.7.1")

NonComplianceSetting7_1 := "GeminiNonRegionalizedFunctionalityStateSettingsProto state"

NonComplianceMessage7_1 := concat(" ", [
    "Features that may process data across multiple regions are enabled for",
    "Gemini app and Gemini in Google Workspace apps"
])

NonCompliantOUs7_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage7_1
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, NonComplianceSetting7_1, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "ENABLED"
}

NonCompliantGroups7_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage7_1
} if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, NonComplianceSetting7_1, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "ENABLED"
}

# As with GWS.ASSUREDCONTROLS.2.1, without an event for the top-level OU
# there is no data to show that multi-region processing has been disabled.
tests contains {
    "PolicyId": SIId7_1,
    "Prerequisites": [
        "reports/v1/activities/list"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    Events := utils.FilterEventsOU(LogEvents, NonComplianceSetting7_1, utils.TopLevelOU)
    count(Events) == 0
    DefaultSafe := false
}

tests contains {
    "PolicyId": SIId7_1,
    "Prerequisites": [
        "reports/v1/activities/list"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs7_1, NonCompliantGroups7_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_1, "NonCompliantGroups": NonCompliantGroups7_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, NonComplianceSetting7_1, utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs7_1) == 0, count(NonCompliantGroups7_1) == 0}
    Status := (false in Conditions) == false
}
#--
