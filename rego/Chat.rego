package chat

import data.utils
import future.keywords

LogEvents := utils.GetEvents("chat_logs")

##############
# GWS.CHAT.1 #
##############

#
# Baseline GWS.CHAT.1v1
#--
UserFriendlyValues1_1 := {
    "true": "History is OFF",
    "false": "History is ON"
}

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
    "PolicyId": "GWS.CHAT.1.1v0.1",
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
    "PolicyId": "GWS.CHAT.1.1v0.1",
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
# Baseline GWS.CHAT.1.2v0.1
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
    "PolicyId": "GWS.CHAT.1.2v0.1",
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
    "PolicyId": "GWS.CHAT.1.2v0.1",
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
# Baseline GWS.CHAT.2.1v0.1
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
    "PolicyId": "GWS.CHAT.2.1v0.1",
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
    "PolicyId": "GWS.CHAT.2.1v0.1",
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
# Baseline GWS.CHAT.3.1v0.1
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
    "PolicyId": "GWS.CHAT.3.1v0.1",
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
    "PolicyId": "GWS.CHAT.3.1v0.1",
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
# Baseline GWS.CHAT.4.1v0.1
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
    "PolicyId": "GWS.CHAT.4.1v0.1",
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
    "PolicyId": "GWS.CHAT.4.1v0.1",
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
# GWS.CHAT.5.1v0.1
#--
NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": concat(" ", [
        "Allow users to install Chat apps is set to",
        LastEvent.NewValue
    ])
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "Chat app Settings - Chat apps enabled", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests contains {
    "PolicyId": "GWS.CHAT.5.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents,  "Chat app Settings - Chat apps enabled", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CHAT.5.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents,  "Chat app Settings - Chat apps enabled", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_1) == 0
}
#--

##############
# GWS.CHAT.6 #
##############

#
# GWS.CHAT.6.1v0.1
#--
tests contains {
    "PolicyId": "GWS.CHAT.6.1v0.1",
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

##############
# GWS.CHAT.7 #
##############

#
# GWS.CHAT.7.1v0.1
#--
NonCompliantOUs7_1 contains OU if {
    # NOTE: The top-level OU needs to be handled separately in this case, as the log event for
    # disabling a conversation type does not follow the typical pattern of most admin log events.
    # - Setting a child OU to inherit results in a DELETE_APPLICATION_SETTING event, as expected.
    # - Disabling a conversation type in the top-level OU also results in a
    #   DELETE_APPLICATION_SETTING event -- a deviation from the normal pattern.
    # Typically, we assume inheritance whenever we see a DELETE_APPLICATION_SETTING event, but due
    # to the above quirk we need more fine-tuned logic.
    #
    # Also worth noting is that disabling a conversation type in a child OU *does not* result in a
    # DELETE_APPLICATION_SETTING event as it does in the top-level OU. Instead it results in either
    # a CREATE_APPLICATION_SETTING or CHANGE_APPLICATION_SETTING event (depending on if the OU had
    # already overwridden the top-level OU settings), with the new value set to
    # CONTENT_REPORTING_STATE_DISABLED.
    some OU in utils.OUsWithEvents
    OU != utils.TopLevelOU

    # There is no one setting that corresponds to the "Allow users to report content in Chat" button.
    # That button in the UI acts more like a "Deselect all" button for the conversation types.
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
    true in {
        LastEventOneOnOne.NewValue == "CONTENT_REPORTING_STATE_DISABLED",
        LastEventGroup.NewValue == "CONTENT_REPORTING_STATE_DISABLED",
        LastEventSpaces.NewValue == "CONTENT_REPORTING_STATE_DISABLED",
        LastEventSpaceRestriction.NewValue == "SPACE_RESTRICTIONS_DISCOVERABLE_SPACES_ONLY"
    }
}

NonCompliantOUs7_1 contains OU if {
    # NOTE: the top-level OU is a special case, see comments above.
    OU := utils.TopLevelOU

    # There is no one setting that corresponds to the "Allow users to report content in Chat" button.
    # That button in the UI acts more like a "Deselect all" button for the conversation types.
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
    true in {
        LastEventOneOnOne.NewValue != "CONTENT_REPORTING_STATE_ENABLED",
        LastEventGroup.NewValue != "CONTENT_REPORTING_STATE_ENABLED",
        LastEventSpaces.NewValue != "CONTENT_REPORTING_STATE_ENABLED",
        LastEventSpaceRestriction.NewValue != "SPACE_RESTRICTIONS_NO_RESTRICTIONS"
    }
}

default NoSuchEvent7_1 := false
NoSuchEvent7_1 := true if {
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
    "PolicyId": "GWS.CHAT.7.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    NoSuchEvent7_1 == true
}

tests contains {
    "PolicyId": "GWS.CHAT.7.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs7_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    NoSuchEvent7_1 == false
    Status := count(NonCompliantOUs7_1) == 0
}
#--

#
# GWS.CHAT.7.2v0.1
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

NonCompliantOUs7_2 contains OU if {
    some OU in utils.OUsWithEvents
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

NonCompliantOUs7_2 contains OU if {
    OU := utils.TopLevelOU
    Events := utils.FilterEventsOU(LogEvents, "ContentReportingProto report_types", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    # As with GWS.CHAT.7.1, the top-level OU is a special case.
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.CHAT.7.2v0.1",
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
    "PolicyId": "GWS.CHAT.7.2v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs7_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs7_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "ContentReportingProto report_types", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs7_2) == 0
}
#--