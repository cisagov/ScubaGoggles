package chat

import future.keywords
import data.utils

LogEvents := utils.GetEvents("chat_logs")

ChatEnabled(orgunit) := utils.AppEnabled(input.policies, "chat", orgunit)

##############
# GWS.CHAT.1 #
##############

#
# Baseline GWS.CHAT.1
#--

ChatId1_1 := utils.PolicyIdWithSuffix("GWS.CHAT.1.1")

NonComplianceMessage1_1(value) := sprintf("Default conversation history is %s",
                                          [value])

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1(utils.GetFriendlyEnabledValue(chatHistory))
} if {
    some OU, settings in input.policies
    ChatEnabled(OU)
    chatHistory := settings.chat_chat_history.historyOnByDefault
    chatHistory == false
}

tests contains {
    "PolicyId": ChatId1_1,
    "Prerequisites": [
        "policy/chat_service_status.serviceState",
        "policy/chat_chat_history.historyOnByDefault"
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
# Baseline GWS.CHAT.1.2
#--

ChatId1_2 := utils.PolicyIdWithSuffix("GWS.CHAT.1.2")

GetFriendlyValue1_2(Value) := "are" if {
    Value == true
} else := "are not" if {
    Value == false
} else := Value

NonComplianceMessage1_2(value) := sprintf("Users %s allowed to change their history setting",
                                          [value])

NonCompliantOUs1_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_2(GetFriendlyValue1_2(changeHistory))
} if {
    some OU, settings in input.policies
    ChatEnabled(OU)
    changeHistory := settings.chat_chat_history.allowUserModification
    changeHistory != false
}

tests contains {
    "PolicyId": ChatId1_2,
    "Prerequisites": [
        "policy/chat_service_status.serviceState",
        "policy/chat_chat_history.allowUserModification"
    ],
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs1_2) == 0
}
#--

##############
# GWS.CHAT.2 #
##############

#
# Baseline GWS.CHAT.2.1
#--

ChatId2_1 := utils.PolicyIdWithSuffix("GWS.CHAT.2.1")

GetFriendlyValue2_1(Value) := "Allow all files" if {
    Value == "ALL_FILES"
} else := "Images only" if {
    Value == "IMAGES_ONLY"
} else := "Unspecified" if {
    Value == "FILE_SHARING_OPTION_UNSPECIFIED"
} else := Value

NonComplianceMessage2_1(value) := sprintf("External file sharing is set to: %s",
                                          [value])

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage2_1(GetFriendlyValue2_1(allowSharing))
} if {
    some OU, settings in input.policies
    ChatEnabled(OU)
    allowSharing := settings.chat_chat_file_sharing.externalFileSharing
    allowSharing != "NO_FILES"
}

tests contains {
    "PolicyId": ChatId2_1,
    "Prerequisites": [
        "policy/chat_service_status.serviceState",
        "policy/chat_chat_file_sharing.externalFileSharing"
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
# GWS.CHAT.3 #
##############

#
# Baseline GWS.CHAT.3.1
#--

ChatId3_1 := utils.PolicyIdWithSuffix("GWS.CHAT.3.1")

NonComplianceMessage3_1(value) := sprintf("Conversation history settings for spaces is set to: %s",
                                          [value])

GetFriendlyValue3_1(Value) := "OFF by default" if {
    Value == "DEFAULT_HISTORY_OFF"
} else := "ON by default" if {
    Value == "DEFAULT_HISTORY_ON"
} else := "ALWAYS ON" if {
    Value == "HISTORY_ALWAYS_ON"
} else := "Unspecified" if {
    Value == "HISTORY_STATE_UNSPECIFIED"
} else := "ALWAYS OFF" if {
    Value == "HISTORY_ALWAYS_OFF"
} else := Value

NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage3_1(GetFriendlyValue3_1(spaceHistory))
} if {
    some OU, settings in input.policies
    ChatEnabled(OU)
    spaceHistory := settings.chat_space_history.historyState
    not spaceHistory in ["DEFAULT_HISTORY_ON", "HISTORY_ALWAYS_ON"]
}

tests contains {
    "PolicyId": ChatId3_1,
    "Prerequisites": [
        "policy/chat_service_status.serviceState",
        "policy/chat_space_history.historyState"
    ],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs3_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Status := count(NonCompliantOUs3_1) == 0
}
#--

##############
# GWS.CHAT.4 #
##############

#
# Baseline GWS.CHAT.4.1
#--

ChatId4_1 := utils.PolicyIdWithSuffix("GWS.CHAT.4.1")

GetFriendlyValue4_1(Value) := "all domains" if {
    Value == "NO_RESTRICTION"
} else := "Unspecified" if {
    Value == "RESTRICTION_UNSPECIFIED"
} else := Value

NonComplianceMessage4_1(value) := sprintf("Allow external chat within: %s",
                                          [value])

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage4_1(GetFriendlyValue4_1(externalRestrict))
} if {
    some OU, settings in input.policies
    ChatEnabled(OU)
    externalEnable := settings.chat_external_chat_restriction.allowExternalChat
    externalEnable == true
    externalRestrict := settings.chat_external_chat_restriction.externalChatRestriction
    externalRestrict != "TRUSTED_DOMAINS"
}

tests contains {
    "PolicyId": ChatId4_1,
    "Prerequisites": [
        "policy/chat_service_status.serviceState",
        "policy/chat_external_chat_restriction.allowExternalChat",
        "policy/chat_external_chat_restriction.externalChatRestriction"
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
# GWS.CHAT.5 #
##############

# There is no setting that corresponds to the "Allow users to report content in Chat" button.
# That button in the UI acts more like a "Deselect all" button for the conversation types.
# Additionally, there is a quirk with it that makes it necessary for the top-level OU to be
# handled separately.
# 1. Setting a child OU to inherit results in DELETE_APPLICATION_SETTING events, as expected.
# 2. Deselecting the "Allow users to report content in Chat" also results in
# DELETE_APPLICATION_SETTING events, completely indistinguishable from the inheritance events.
# We know the top-level OU can't inherit, so if we see that there we know they turned off
# content reporting.
# Unfortunately, for the child OUs, from the log events alone you cannot distinguish between
# setting inheritance and completely disabling content reporting.
Chat5Warning := concat("", [
    "WARNING: from the log events alone, it is not possible to distinguish between ",
    "an OU inheriting settings from its parent and content reporting being disabled entirely. ",
    "It's possible this tool classified some child OUs as compliant due to this limitation; manual check ",
    "recommended for child OUs due to this edge case."
])

#
# GWS.CHAT.5.1
#--

ChatId5_1 := utils.PolicyIdWithSuffix("GWS.CHAT.5.1")

GetFriendlyValue5_1(NonCompBooleans) := Description if {
    StatusMessages = [
        "Content reporting for 1:1 direct messages is disabled.",
        "Content reporting for group direct messages is disabled.",
        "Content reporting for spaces is disabled.",
        "Content reporting for spaces is restricted to discoverable spaces only."
    ]
    # Note that this logic assumes the order of the booleans corresponds to the order listed above in the
    # StatusMessages array
    # regal ignore:prefer-some-in-iteration,use-some-for-output-vars
    Description := concat(" ", [StatusMessages[i] | some i, Status in NonCompBooleans; Status == true])
}

NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": GetFriendlyValue5_1(NonCompBooleans)
} if {
    some OU in utils.OUsWithEvents
    # Toplevel OU will be handled separately due to the quirk with DELETE_APPLICATION_SETTING events for
    # these settings.
    OU != utils.TopLevelOU

    OneOnOneEvents := utils.FilterEventsOU(LogEvents, "ContentReportingProto one_on_one_reporting", OU)
    GroupEvents := utils.FilterEventsOU(LogEvents, "ContentReportingProto group_chat_reporting", OU)
    SpacesEvents := utils.FilterEventsOU(LogEvents, "ContentReportingProto room_reporting", OU)

    # This setting corresponds to the "All spaces" or "Discoverable spaces only" toggle under the Spaces box
    SpacesRestrictionEvents := utils.FilterEventsOU(LogEvents, "ContentReportingProto room_restrictions", OU)

    # Ignore OUs without all event types. We're already asserting that the
    # top-level OU has at least one event for all types; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(OneOnOneEvents) > 0
    count(GroupEvents) > 0
    count(SpacesEvents) > 0
    count(SpacesRestrictionEvents) > 0

    # Get the last event for each setting
    LastEventOneOnOne := utils.GetLastEvent(OneOnOneEvents)
    LastEventGroup := utils.GetLastEvent(GroupEvents)
    LastEventSpaces := utils.GetLastEvent(SpacesEvents)
    LastEventSpaceRestriction := utils.GetLastEvent(SpacesRestrictionEvents)

    # A child-OU is non-compliant if any of the following are true
    NonCompBooleans := [
        LastEventOneOnOne.NewValue == "CONTENT_REPORTING_STATE_DISABLED",
        LastEventGroup.NewValue == "CONTENT_REPORTING_STATE_DISABLED",
        LastEventSpaces.NewValue == "CONTENT_REPORTING_STATE_DISABLED",
        LastEventSpaceRestriction.NewValue == "SPACE_RESTRICTIONS_DISCOVERABLE_SPACES_ONLY"
    ]
    true in NonCompBooleans
}

NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": GetFriendlyValue5_1(NonCompBooleans)
} if {
    # NOTE: the top-level OU is a special case, see comments above.
    OU := utils.TopLevelOU

    OneOnOneEvents := utils.FilterEventsOU(LogEvents, "ContentReportingProto one_on_one_reporting", OU)
    GroupEvents := utils.FilterEventsOU(LogEvents, "ContentReportingProto group_chat_reporting", OU)
    SpacesEvents := utils.FilterEventsOU(LogEvents, "ContentReportingProto room_reporting", OU)

    # This setting corresponds to the "All spaces" or "Discoverable spaces only" toggle under the Spaces box
    SpacesRestrictionEvents := utils.FilterEventsOU(LogEvents, "ContentReportingProto room_restrictions", OU)

    # Ignore OUs without all event types. We're already asserting that the
    # top-level OU has at least one event for all types; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(OneOnOneEvents) > 0
    count(GroupEvents) > 0
    count(SpacesEvents) > 0
    count(SpacesRestrictionEvents) > 0

    # Get the last event for each setting
    LastEventOneOnOne := utils.GetLastEvent(OneOnOneEvents)
    LastEventGroup := utils.GetLastEvent(GroupEvents)
    LastEventSpaces := utils.GetLastEvent(SpacesEvents)
    LastEventSpaceRestriction := utils.GetLastEvent(SpacesRestrictionEvents)

    # The top-level OU is non-compliant if any of the following are true
    NonCompBooleans := [
        LastEventOneOnOne.NewValue in {"CONTENT_REPORTING_STATE_DISABLED", "DELETE_APPLICATION_SETTING"},
        LastEventGroup.NewValue in {"CONTENT_REPORTING_STATE_DISABLED", "DELETE_APPLICATION_SETTING"},
        LastEventSpaces.NewValue in {"CONTENT_REPORTING_STATE_DISABLED", "DELETE_APPLICATION_SETTING"},
        LastEventSpaceRestriction.NewValue in {
            "SPACE_RESTRICTIONS_DISCOVERABLE_SPACES_ONLY",
            "DELETE_APPLICATION_SETTING"
        }
    ]
    true in NonCompBooleans
}

default NoSuchEvent5_1 := false
NoSuchEvent5_1 := true if {
    OU := utils.TopLevelOU
    OneOnOneEvents := utils.FilterEventsOU(LogEvents, "ContentReportingProto one_on_one_reporting", OU)
    GroupEvents := utils.FilterEventsOU(LogEvents, "ContentReportingProto group_chat_reporting", OU)
    SpacesEvents := utils.FilterEventsOU(LogEvents, "ContentReportingProto room_reporting", OU)
    SpacesRestrictionEvents := utils.FilterEventsOU(LogEvents, "ContentReportingProto room_restrictions", OU)

    true in {
        count(OneOnOneEvents) == 0,
        count(GroupEvents) == 0,
        count(SpacesEvents) == 0,
        count(SpacesRestrictionEvents) == 0
    }
}

tests contains {
    "PolicyId": ChatId5_1,
    "Prerequisites": ["reports/v1/activities/list"],
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    NoSuchEvent5_1 == true
}

tests contains {
    "PolicyId": ChatId5_1,
    "Prerequisites": ["reports/v1/activities/list"],
    "Criticality": "Shall",
    "ReportDetails": concat("<br>", [utils.ReportDetails(NonCompliantOUs5_1, []), Chat5Warning]),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    NoSuchEvent5_1 == false
    Status := count(NonCompliantOUs5_1) == 0
}
#--

#
# GWS.CHAT.5.2
#--

ChatId5_2 := utils.PolicyIdWithSuffix("GWS.CHAT.5.2")

AllReportingCategories := {
    "system_violation: HARASSMENT",
    "system_violation: DISCRIMINATION",
    "system_violation: EXPLICIT_CONTENT",
    "system_violation: SPAM",
    "system_violation: CONFIDENTIAL_INFORMATION",
    "system_violation: SENSITIVE_INFORMATION",
    "system_violation: OTHER"
}

GetFriendlyCategory(Category) := FriendlyCategory if {
    SplitStr := split(Category, " ")
    LastWord := SplitStr[1]
    FriendlyCategory := replace(lower(LastWord), "_", " ")
}

NonCompliantOUs5_2 contains {
    "Name": OU,
    "Value": concat("", [
        "The following reporting types are disabled: ",
        concat(", ", [GetFriendlyCategory(Cat) | some Cat in MissingCats])
    ])
} if {
    some OU in utils.OUsWithEvents
    # As with GWS.CHAT.5.1, the top-level OU is a special case.
    OU != utils.TopLevelOU
    Events := utils.FilterEventsOU(LogEvents, "ContentReportingProto report_types", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
    EnabledCats := {trim(cat, " []\n") | some cat in split(LastEvent.NewValue, ",")}
    MissingCats := AllReportingCategories - EnabledCats
    count(MissingCats) > 0
}

NonCompliantOUs5_2 contains {
    "Name": OU,
    "Value": concat("", [
        "The following reporting types are disabled: ",
        concat(", ", [GetFriendlyCategory(Cat) | some Cat in AllReportingCategories])
    ])
} if {
    # As with GWS.CHAT.5.1, the top-level OU is a special case.
    OU := utils.TopLevelOU
    Events := utils.FilterEventsOU(LogEvents, "ContentReportingProto report_types", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    # If we see DELETE_APPLICATION_SETTING in the top-level OU, we know it is non-compliant
    LastEvent.NewValue == "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs5_2 contains {
    "Name": OU,
    "Value": concat("", [
        "The following reporting types are disabled: ",
        concat(", ", [GetFriendlyCategory(Cat) | some Cat in MissingCats])
    ])
} if {
    # As with GWS.CHAT.5.1, the top-level OU is a special case.
    OU := utils.TopLevelOU
    Events := utils.FilterEventsOU(LogEvents, "ContentReportingProto report_types", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
    EnabledCats := {trim(cat, " []\n") | some cat in split(LastEvent.NewValue, ",")}
    MissingCats := AllReportingCategories - EnabledCats
    count(MissingCats) > 0
}

tests contains {
    "PolicyId": ChatId5_2,
    "Prerequisites": ["reports/v1/activities/list"],
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "ContentReportingProto report_types", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": ChatId5_2,
    "Prerequisites": ["reports/v1/activities/list"],
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "ContentReportingProto report_types", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_2) == 0
}
#--
