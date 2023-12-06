package chat
import future.keywords
import data.utils.ReportDetailsOUs
import data.utils.NoSuchEventDetails

FilterEvents(SettingName) := FilteredEvents if {
    Events := SettingChangeEvents
    FilteredEvents := [Event | Event = Events[_]; Event.Setting == SettingName]
}

FilterEventsOU(ServiceName, OrgUnit) := FilteredEvents if {
    # If there exists at least the root OU and 1 more OU
    # filter out organizational units that don't exist
    input.organizational_unit_names
    count(input.organizational_unit_names) >=2

    # Filter the events by both ServiceName and OrgUnit
    Events := FilterEvents(ServiceName)
    FilteredEvents := [
        Event | Event = Events[_];
        Event.OrgUnit == OrgUnit;
        Event.OrgUnit in input.organizational_unit_names
    ]
}

FilterEventsOU(ServiceName, OrgUnit) := FilteredEvents if {
    # If there exists at least the root OU and 1 more OU
    # filter out organizational units that don't exist
    input.organizational_unit_names
    count(input.organizational_unit_names) >=2

    # Filter the events by both ServiceName and OrgUnit
    Events := FilterEvents(ServiceName)
    FilteredEvents := [
        Event | Event = Events[_];
        Event.OrgUnit == OrgUnit;
        Event.OrgUnit in input.organizational_unit_names
    ]
}

FilterEventsOU(SettingName, OrgUnit) := FilteredEvents if {
    # If only the root OU exists run like normal
    input.organizational_unit_names
    count(input.organizational_unit_names) < 2

    # Filter the events by both SettingName and OrgUnit
    Events := FilterEvents(SettingName)
    FilteredEvents := [Event | Event = Events[_]; Event.OrgUnit == OrgUnit]
}

FilterEventsOU(SettingName, OrgUnit) := FilteredEvents if {
    # If OUs variable does not exist run like normal
    not input.organizational_unit_names

    # Filter the events by both SettingName and OrgUnit
    Events := FilterEvents(SettingName)
    FilteredEvents := [Event | Event = Events[_]; Event.OrgUnit == OrgUnit]
}

GetTopLevelOU() := name if {
    # Simplest case: if input.tenant_info.topLevelOU is
    # non-empty, it contains the name of the top-level OU.
    input.tenant_info.topLevelOU != ""
    name := input.tenant_info.topLevelOU
}

GetTopLevelOU() := name if {
    # input.tenant_info.topLevelOU will be empty when
    # no custom OUs have been created, as in this case
    # the top-level OU cannot be determined via the API.
    # Fortunately, in this case, we know there's literally
    # only one OU, so we can grab the OU listed on any of
    # the events and know that it is the top-level OU
    input.tenant_info.topLevelOU == ""
    count(SettingChangeEvents) > 0
    name := GetLastEvent(SettingChangeEvents).OrgUnit
}

GetTopLevelOU() := name if {
    # Extreme edge case: no custom OUs have been made
    # and the logs are empty. In this case, we really
    # have no way of determining the top-level OU name.
    input.tenant_info.topLevelOU == ""
    count(SettingChangeEvents) == 0
    name := ""
}

OUsWithEvents[Event.OrgUnit] {
    Event := SettingChangeEvents[_]
}

SettingChangeEvents[{"Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "NewValue": NewValue,
    "Setting": Setting,
    "OrgUnit": OrgUnit}] {

    Item := input.chat_logs.items[_] # For each item...
    Event := Item.events[_] # For each event in the item...

    # Does this event have the parameters we're looking for?
    "SETTING_NAME" in [Parameter.name | Parameter = Event.parameters[_]] 
    "NEW_VALUE" in [Parameter.name | Parameter = Event.parameters[_]]
    "ORG_UNIT_NAME" in [Parameter.name | Parameter = Event.parameters[_]]

    # Extract the values
    Setting := [Parameter.value | Parameter = Event.parameters[_]; Parameter.name == "SETTING_NAME"][0]
    NewValue := [Parameter.value | Parameter = Event.parameters[_]; Parameter.name == "NEW_VALUE"][0]
    OrgUnit := [Parameter.value | Parameter = Event.parameters[_]; Parameter.name == "ORG_UNIT_NAME"][0]
}

# Secondary case that looks for the DELETE_APPLICATION_SETTING events.
# These events don't have a NEW_VALUE. To make these events work with
# minimal special logic, this rule adds the DELETE_APPLICATION_SETTING
# to the SettingChangeEvents set, with "DELETE_APPLICATION_SETTING" as
# the NewValue.
SettingChangeEvents[{"Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "NewValue": NewValue,
    "Setting": Setting,
    "OrgUnit": OrgUnit}] {

    Item := input.chat_logs.items[_] # For each item...
    Event := Item.events[_] # For each event in the item...
    Event.name == "DELETE_APPLICATION_SETTING" # Only look at delete events

    # Does this event have the parameters we're looking for?
    "SETTING_NAME" in [Parameter.name | Parameter = Event.parameters[_]] 
    "ORG_UNIT_NAME" in [Parameter.name | Parameter = Event.parameters[_]]

    # Extract the values
    Setting := [Parameter.value | Parameter = Event.parameters[_]; Parameter.name == "SETTING_NAME"][0]
    NewValue := "DELETE_APPLICATION_SETTING"
    OrgUnit := [Parameter.value | Parameter = Event.parameters[_]; Parameter.name == "ORG_UNIT_NAME"][0]
}

GetLastEvent(Events) := Event if {
    MaxTs := max([Event.Timestamp | Event = Events[_]])
    Event := Events[_]
    Event.Timestamp == MaxTs
}

################
# GWS.CHAT.1   #
################

#
# Baseline GWS.CHAT.1v1
#--

NonCompliantOUs1_1[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("ChatArchivingProto chatsDefaultToOffTheRecord", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests[{ "PolicyId": "GWS.CHAT.1.1v0.1",
        "Criticality": "Should",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}]{
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("ChatArchivingProto chatsDefaultToOffTheRecord", TopLevelOU)    
    count(Events) == 0
}

tests[{ "PolicyId": "GWS.CHAT.1.1v0.1",
        "Criticality": "Should",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_1),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
        "RequirementMet": Status,
        "NoSuchEvent": false}]{
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("ChatArchivingProto chatsDefaultToOffTheRecord", TopLevelOU)    
    count(Events) > 0
    Status := count(NonCompliantOUs1_1) == 0
}
#--

#
# Baseline GWS.CHAT.1.2v0.1
#--

NonCompliantOUs1_2[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("ChatArchivingProto allow_chat_archiving_setting_modification", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests[{ "PolicyId": "GWS.CHAT.1.2v0.1",
        "Criticality": "Shall",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}]{
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("ChatArchivingProto allow_chat_archiving_setting_modification", TopLevelOU)    
    count(Events) == 0
}

tests[{ "PolicyId": "GWS.CHAT.1.2v0.1",
        "Criticality": "Shall",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_2),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_2},
        "RequirementMet": Status,
        "NoSuchEvent": false}]{
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("ChatArchivingProto allow_chat_archiving_setting_modification", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_2) == 0
}
#--


################
# GWS.CHAT.2   #
################

#
# Baseline GWS.CHAT.2.2v0.1
#--

NonCompliantOUs2_1[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("DynamiteFileSharingSettingsProto external_file_sharing_setting", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "NO_FILES"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests[{ "PolicyId": "GWS.CHAT.2.1v0.1",
        "Criticality": "Shall",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}]{
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("DynamiteFileSharingSettingsProto external_file_sharing_setting", TopLevelOU)    
    count(Events) == 0
}

tests[{ "PolicyId": "GWS.CHAT.2.1v0.1",
        "Criticality": "Shall",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs2_1),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
        "RequirementMet": Status,
        "NoSuchEvent": false}]{
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("DynamiteFileSharingSettingsProto external_file_sharing_setting", TopLevelOU)      
    count(Events) > 0
    Status := count(NonCompliantOUs2_1) == 0
}
#--

################
# GWS.CHAT.3   #
################

#
# Baseline GWS.CHAT.3.1v0.1
#--

NonCompliantOUs3_1[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("RoomOtrSettingsProto otr_state", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    not contains("DEFAULT_ON_THE_RECORD ALWAYS_ON_THE_RECORD", LastEvent.NewValue)
}

tests[{ "PolicyId": "GWS.CHAT.3.1v0.1",
        "Criticality": "Should",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}]{
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("RoomOtrSettingsProto otr_state", TopLevelOU)
    count(Events) == 0
}

tests[{ "PolicyId": "GWS.CHAT.3.1v0.1",
        "Criticality": "Should",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs3_1),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
        "RequirementMet": Status,
        "NoSuchEvent": false}]{
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("RoomOtrSettingsProto otr_state", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs3_1) == 0
}
#--

################
# GWS.CHAT.4   #
################

#
# Baseline GWS.CHAT.4.1v0.1
#--
NonCompliantOUs4_1[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("RestrictChatProto restrictChatToOrganization", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests[{ "PolicyId": "GWS.CHAT.4.1v0.1",
        "Criticality": "Shall",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}]{
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("RestrictChatProto restrictChatToOrganization", TopLevelOU)
    count(Events) == 0
}

tests[{ "PolicyId": "GWS.CHAT.4.1v0.1",
        "Criticality": "Shall",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs4_1),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
        "RequirementMet": Status,
        "NoSuchEvent": false}]{
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("RestrictChatProto restrictChatToOrganization", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_1) == 0
}
#--

#
# Baseline GWS.CHAT.4.2v0.1
#--
NonCompliantOUs4_2[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("RestrictChatProto externalChatRestriction", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue == "NO_RESTRICTION"
}

tests[{ "PolicyId": "GWS.CHAT.4.2v0.1",
        "Criticality": "Shall",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}]{
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("RestrictChatProto externalChatRestriction", TopLevelOU)
    count(Events) == 0
}

tests[{ "PolicyId": "GWS.CHAT.4.2v0.1",
        "Criticality": "Shall",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs4_2),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_2},
        "RequirementMet": Status,
        "NoSuchEvent": false}]{
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("RestrictChatProto externalChatRestriction", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_2) == 0
}
#--

################
# GWS.CHAT.5   #
################

#
# GWS.CHAT.5.1v0.1
#--

NonCompliantOUs5_1[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("Chat app Settings - Chat apps enabled", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests[{ "PolicyId": "GWS.CHAT.5.1v0.1",
        "Criticality": "Shall",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}]{
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("Chat app Settings - Chat apps enabled", TopLevelOU)
    count(Events) == 0
}

tests[{ "PolicyId": "GWS.CHAT.5.1v0.1",
        "Criticality": "Shall",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs5_1),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1},
        "RequirementMet": Status,
        "NoSuchEvent": false}]{
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("Chat app Settings - Chat apps enabled", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_1) == 0
}
#--

tests[{ "PolicyId": "GWS.CHAT.6.1v0.1",
        "Criticality": "Should/Not-Implemented",
        "ReportDetails": "Currently not able to be tested automatically; please manually check.",
        "ActualValue": "",
        "RequirementMet": false,
        "NoSuchEvent": true}]{
    true
}
#--