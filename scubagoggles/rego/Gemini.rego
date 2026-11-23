package gemini

import future.keywords
import data.utils

LogEvents := utils.GetEvents("gemini_logs")

#
# Baseline GWS.GEMINI.1.1
#--

GeminiId1_1 := utils.PolicyIdWithSuffix("GWS.GEMINI.1.1")

NonComplianceMessage1_1 := "Gemini access regardless of license is enabled."

GeminiEnabled(orgunit) := utils.AppEnabled(input.policies, "gemini_app", orgunit)

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1
} if {
    some OU, settings in input.policies
    GeminiEnabled(OU)
    settings.gemini_app_unlicensed_user_access.enabled == true
}

tests contains {
    "PolicyId": GeminiId1_1,
    "Prerequisites": [
        "policy/gemini_app_unlicensed_user_access.enabled",
        "policy/gemini_app_service_status.serviceState"
    ],
    "Criticality": "Shall",
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
# Baseline GWS.GEMINI.2.1
#--

GeminiId2_1 := utils.PolicyIdWithSuffix("GWS.GEMINI.2.1")

NonComplianceMessage2_1 := "Gemini Beta features are enabled."

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_1
} if {
    some OU, settings in input.policies
    settings.gemini_for_workspace_beta_features.enabled == true
}

tests contains {
    "PolicyId": GeminiId2_1,
    "Prerequisites": [
        "policy/gemini_for_workspace_beta_features.enabled"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs2_1) == 0
}
#--

##############
# GWS.GEMINI.3 #
##############

#
# Baseline GWS.GEMINI.3.1
#--

GeminiId3_1 := utils.PolicyIdWithSuffix("GWS.GEMINI.3.1")

NonComplianceMessage3_1 := "Gemini conversation history is disabled."

NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage3_1
} if {
    some OU, settings in input.policies
    GeminiEnabled(OU)
    settings.gemini_app_conversation_history.conversationHistoryState != "ENABLED"
}

tests contains {
    "PolicyId": GeminiId3_1,
    "Prerequisites": [
        "policy/gemini_app_conversation_history.conversationHistoryState",
        "policy/gemini_app_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs3_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs3_1) == 0
}
#--

#
# Baseline GWS.GEMINI.3.2
#--

GeminiId3_2 := utils.PolicyIdWithSuffix("GWS.GEMINI.3.2")

# Retention of at least 18 months is required.
CompliantRetentionValues := {"EIGHTEEN_MONTHS", "THIRTY_SIX_MONTHS"}

GetFriendlyValue3_2(Value) := "3 months" if {
    Value == "THREE_MONTHS"
} else := "18 months" if {
    Value == "EIGHTEEN_MONTHS"
} else := "36 months" if {
    Value == "THIRTY_SIX_MONTHS"
} else := "Unspecified" if {
    Value == "CONVERSATION_RETENTION_UNSPECIFIED"
} else := Value

NonComplianceMessage3_2(value) := sprintf("Conversation retention is set to: %s",
                                          [value])

NonCompliantOUs3_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage3_2(GetFriendlyValue3_2(Retention))
} if {
    some OU, settings in input.policies
    GeminiEnabled(OU)
    Retention := settings.gemini_app_conversation_history.conversationRetention
    not Retention in CompliantRetentionValues
}

tests contains {
    "PolicyId": GeminiId3_2,
    "Prerequisites": [
        "policy/gemini_app_conversation_history.conversationRetention",
        "policy/gemini_app_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs3_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs3_2) == 0
}
#--

##############
# GWS.GEMINI.4 #
##############

#
# Baseline GWS.GEMINI.4.1
#--

GeminiId4_1 := utils.PolicyIdWithSuffix("GWS.GEMINI.4.1")

GetFriendlyValue4_1(Value) := "Allow sharing via link" if {
    Value == "ALLOW_SHARING_VIA_LINK"
} else := "Allow sharing via Drive" if {
    Value == "ALLOW_SHARING_VIA_DRIVE"
} else := "Disabled" if {
    Value == "DISABLED"
} else := "Unspecified" if {
    Value == "CONVERSATION_SHARING_OPTION_UNSPECIFIED"
} else := Value

NonComplianceMessage4_1(value) := sprintf("Conversation sharing is set to: %s",
                                          [value])

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage4_1(GetFriendlyValue4_1(Sharing))
} if {
    some OU, settings in input.policies
    GeminiEnabled(OU)
    Sharing := settings.gemini_app_conversation_sharing.conversationSharingOption
    Sharing != "DISABLED"
}

tests contains {
    "PolicyId": GeminiId4_1,
    "Prerequisites": [
        "policy/gemini_app_conversation_sharing.conversationSharingOption",
        "policy/gemini_app_service_status.serviceState"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs4_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs4_1) == 0
}
#--

##############
# GWS.GEMINI.5 #
##############

#
# Baseline GWS.GEMINI.5.1
#--

GeminiId5_1 := utils.PolicyIdWithSuffix("GWS.GEMINI.5.1")

NonComplianceSetting5_1 := "VidsLikeness enabled"

NonComplianceMessage5_1 := "Personal avatars in Google Vids are enabled."

# Personal avatars are ON by default, so deleting the top-level OU
# setting reverts it to the non-compliant default.
PersonalAvatarEnabled(Event, _) if {
    Event.NewValue == "true"
}

PersonalAvatarEnabled(Event, OU) if {
    Event.NewValue == "DELETE_APPLICATION_SETTING"
    OU == utils.TopLevelOU
}

NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_1
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, NonComplianceSetting5_1, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    PersonalAvatarEnabled(LastEvent, OU)
}

NonCompliantGroups5_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage5_1
} if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, NonComplianceSetting5_1, Group)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests contains {
    "PolicyId": GeminiId5_1,
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
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, NonComplianceSetting5_1, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": GeminiId5_1,
    "Prerequisites": [
        "reports/v1/activities/list"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_1, NonCompliantGroups5_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1, "NonCompliantGroups": NonCompliantGroups5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, NonComplianceSetting5_1, utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs5_1) == 0, count(NonCompliantGroups5_1) == 0}
    Status := (false in Conditions) == false
}
#--
