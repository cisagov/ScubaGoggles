package chat

import data.utils
import future.keywords

LogEvents := utils.GetEvents("chat_logs")

##############
# GWS.CHAT.1 #
##############

#
# Baseline GWS.CHAT.1v0.2
#--

GetFriendlyValue1_1(Value) := "History is OFF" if {
    Value == "true"
} else := "History is ON" if {
    Value == "false"
} else := Value

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Default conversation history is set to",
        GetFriendlyValue1_1(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "ChatArchivingProto chatsDefaultToOffTheRecord", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests contains {
    "PolicyId": "GWS.CHAT.1.1v0.2",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents,  "ChatArchivingProto chatsDefaultToOffTheRecord", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CHAT.1.1v0.2",
    "Criticality": "Shall",
    # Empty list in next line for non compliant groups, as this setting can't be changed at the group level
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents,  "ChatArchivingProto chatsDefaultToOffTheRecord", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_1) == 0
}
#--

#
# Baseline GWS.CHAT.1.2v0.2
#--
NonCompliantOUs1_2 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Allow users to change their history setting is set to",
        LastEvent.NewValue
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents,  "ChatArchivingProto allow_chat_archiving_setting_modification", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests contains {
    "PolicyId": "GWS.CHAT.1.2v0.2",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "ChatArchivingProto allow_chat_archiving_setting_modification"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CHAT.1.2v0.2",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "ChatArchivingProto allow_chat_archiving_setting_modification"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_2) == 0
}
#--


##############
# GWS.CHAT.2 #
##############

#
# Baseline GWS.CHAT.2.1v0.2
#--
GetFriendlyValue2_1(Value) := "Allow all files" if {
    Value == "ALL_FILES"
} else := "Images only" if {
    Value == "IMAGES_ONLY"
} else := Value

NonCompliantOUs2_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "External filesharing is set to",
        GetFriendlyValue2_1(LastEvent.NewValue)
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents,  "DynamiteFileSharingSettingsProto external_file_sharing_setting", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "NO_FILES"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.CHAT.2.1v0.2",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "DynamiteFileSharingSettingsProto external_file_sharing_setting"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CHAT.2.1v0.2",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs2_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "DynamiteFileSharingSettingsProto external_file_sharing_setting"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_1) == 0
}
#--

##############
# GWS.CHAT.3 #
##############

#
# Baseline GWS.CHAT.3.1v0.2
#--
GetFriendlyValue3_1(Value) := "History is OFF by default" if {
    Value == "DEFAULT_OFF_THE_RECORD"
} else := "History is ALWAYS OFF" if {
    Value == "ALWAYS_OFF_THE_RECORD"
} else := Value

NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Conversation history settings for spaces is set to",
        GetFriendlyValue3_1(LastEvent.NewValue)
    ])
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "RoomOtrSettingsProto otr_state", OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    not contains("DEFAULT_ON_THE_RECORD ALWAYS_ON_THE_RECORD", LastEvent.NewValue)
}

tests contains {
    "PolicyId": "GWS.CHAT.3.1v0.2",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents,  "RoomOtrSettingsProto otr_state", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CHAT.3.1v0.2",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs3_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents,  "RoomOtrSettingsProto otr_state", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs3_1) == 0
}
#--

##############
# GWS.CHAT.4 #
##############

#
# Baseline GWS.CHAT.4.1v0.2
#--
default NoSuchEvent4_1(_) := false

NoSuchEvent4_1(TopLevelOU) := true if {
    Events := utils.FilterEventsOU(LogEvents, "RestrictChatProto restrictChatToOrganization", TopLevelOU)
    count(Events) == 0
}

NoSuchEvent4_1(TopLevelOU) := true if {
    Events := utils.FilterEventsOU(LogEvents, "RestrictChatProto externalChatRestriction", TopLevelOU)
    count(Events) == 0
}

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": "External chat is enabled for all domains"
}
 if {
    some OU in utils.OUsWithEvents
    Events_A := utils.FilterEventsOU(LogEvents, "RestrictChatProto restrictChatToOrganization", OU)
    count(Events_A) > 0
    LastEvent_A := utils.GetLastEvent(Events_A)
    LastEvent_A.NewValue != "DELETE_APPLICATION_SETTING"

    Events_B := utils.FilterEventsOU(LogEvents, "RestrictChatProto externalChatRestriction", OU)
    count(Events_B) > 0
    LastEvent_B := utils.GetLastEvent(Events_B)
    LastEvent_B.NewValue != "DELETE_APPLICATION_SETTING"

    LastEvent_A.NewValue == "false"
    LastEvent_B.NewValue != "TRUSTED_DOMAINS"
}

tests contains {
    "PolicyId": "GWS.CHAT.4.1v0.2",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    NoSuchEvent4_1(utils.TopLevelOU)
}

tests contains {
    "PolicyId": "GWS.CHAT.4.1v0.2",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs4_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    not NoSuchEvent4_1(utils.TopLevelOU)
    Status := count(NonCompliantOUs4_1) == 0
}
#--

##############
# GWS.CHAT.5 #
##############

#
# GWS.CHAT.5.1v0.2
#--
tests contains {
    "PolicyId": "GWS.CHAT.5.1v0.2",
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

##############
# GWS.CHAT.6 #
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
Chat6Warning := concat("", [
    "WARNING: from the log events alone, it is not possible to distinguish between ",
    "an OU inheriting settings from its parent and content reporting being disabled entirely. ",
    "It's possible this tool classified some child OUs as compliant due to this limitation; manual check ",
    "recommended for child OUs due to this edge case."
])

#
# GWS.CHAT.6.1v0.2
#--

GetFriendlyValue6_1(NonCompBooleans) := Description if {
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

NonCompliantOUs6_1 contains {
    "Name": OU,
    "Value": GetFriendlyValue6_1(NonCompBooleans)
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

NonCompliantOUs6_1 contains {
    "Name": OU,
    "Value": GetFriendlyValue6_1(NonCompBooleans)
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

default NoSuchEvent6_1 := false
NoSuchEvent6_1 := true if {
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
    "PolicyId": "GWS.CHAT.6.1v0.2",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    NoSuchEvent6_1 == true
}

tests contains {
    "PolicyId": "GWS.CHAT.6.1v0.2",
    "Criticality": "Shall",
    "ReportDetails": concat("<br>", [utils.ReportDetails(NonCompliantOUs6_1, []), Chat6Warning]),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    NoSuchEvent6_1 == false
    Status := count(NonCompliantOUs6_1) == 0
}
#--

#
# GWS.CHAT.6.2v0.2
#--
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

NonCompliantOUs6_2 contains {
    "Name": OU,
    "Value": concat("", [
        "The following reporting types are disabled: ",
        concat(", ", [GetFriendlyCategory(Cat) | some Cat in MissingCats])
    ])
} if {
    some OU in utils.OUsWithEvents
    # As with GWS.CHAT.6.1, the top-level OU is a special case.
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

NonCompliantOUs6_2 contains {
    "Name": OU,
    "Value": concat("", [
        "The following reporting types are disabled: ",
        concat(", ", [GetFriendlyCategory(Cat) | some Cat in AllReportingCategories])
    ])
} if {
    # As with GWS.CHAT.6.1, the top-level OU is a special case.
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

NonCompliantOUs6_2 contains {
    "Name": OU,
    "Value": concat("", [
        "The following reporting types are disabled: ",
        concat(", ", [GetFriendlyCategory(Cat) | some Cat in MissingCats])
    ])
} if {
    # As with GWS.CHAT.6.1, the top-level OU is a special case.
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
    "PolicyId": "GWS.CHAT.6.2v0.2",
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
    "PolicyId": "GWS.CHAT.6.2v0.2",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs6_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "ContentReportingProto report_types", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs6_2) == 0
}
#--