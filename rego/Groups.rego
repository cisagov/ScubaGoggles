package groups
import future.keywords
import data.utils.ReportDetailsOUs
import data.utils.NoSuchEventDetails

NoGroupsDetails(Groups) = "No Groups found in Organization." if {count(Groups) == 0}
ReportDetailsGroups(Groups) = "Requirement met in all Groups." if {count(Groups) == 0}
ReportDetailsGroups(Groups) = Message if {
    count(Groups) > 0
    Message := concat("", ["Requirement failed in ", concat(", ", Groups), "."])
}

FilterEvents(SettingName) := FilteredEvents if {
    # Filter the events by SettingName
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

    Item := input.groups_logs.items[_] # For each item...
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

GetLastEvent(Events) := Event if {
    # Because CalendarSharingEvents returns a set instead
    # of an array, we can't just index it and get the last
    # value
    MaxTs := max([Event.Timestamp | Event = Events[_]])
    Event := Events[_]
    Event.Timestamp == MaxTs
}


################
# Baseline 1   #
################
#
# Baseline GWS.GROUPS.1.1v0.1
#--

NonCompliantOUs1_1[OU] {
     OU := OUsWithEvents[_]
     Events := FilterEventsOU("GroupsSharingSettingsProto collaboration_policy", OU)
     count(Events) > 0 # Ignore OUs without any events. We're already
     # asserting that the top-level OU has at least one event; for all
     # other OUs we assume they inherit from a parent OU if they have
     # no events.
     LastEvent := GetLastEvent(Events)
     LastEvent.NewValue != "CLOSED"
 }

tests[{ "PolicyId" : "GWS.GROUPS.1.1v0.1",
        "Criticality" : "Shall",
        "ReportDetails" : NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue" : "No relevant event in the current logs",
        "RequirementMet" : DefaultSafe,
        "NoSuchEvent": true}]{
        DefaultSafe := false
        TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("GroupsSharingSettingsProto collaboration_policy", TopLevelOU)
    count(Events) == 0 #If no events were logged, then the default 
}

tests[{ "PolicyId" : "GWS.GROUPS.1.1v0.1",
        "Criticality" : "Shall",
        "ReportDetails" : ReportDetailsOUs(NonCompliantOUs1_1),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
        "RequirementMet" : Status,
        "NoSuchEvent": false}]{
        TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("GroupsSharingSettingsProto collaboration_policy", TopLevelOU)
    count(Events) > 0
    Status :=count(NonCompliantOUs1_1) == 0
}
#--


################
# Baseline 2   #
################

#
# Baseline GWS.GROUPS.2.1v0.1
#--

NonCompliantOUs2_1[OU] {
     OU := OUsWithEvents[_]
     Events := FilterEventsOU("GroupsSharingSettingsProto owners_can_allow_external_members", OU)
     count(Events) > 0 # Ignore OUs without any events. We're already
     # asserting that the top-level OU has at least one event; for all
     # other OUs we assume they inherit from a parent OU if they have
     # no events.
     LastEvent := GetLastEvent(Events)
     LastEvent.NewValue != "false"
 }
tests[{ "PolicyId" : "GWS.GROUPS.2.1v0.1",
        "Criticality" : "Should",
        "ReportDetails" : NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue" : "No relevant event in the current logs",
        "RequirementMet" : DefaultSafe,
        "NoSuchEvent": true}]{
    DefaultSafe := false
    TopLevelOU = GetTopLevelOU()
    Events := FilterEventsOU("GroupsSharingSettingsProto owners_can_allow_external_members", TopLevelOU)
    count(Events) == 0 #If no events were logged, then the default 
}

tests[{ "PolicyId" : "GWS.GROUPS.2.1v0.1",
        "Criticality" : "Should",
        "ReportDetails" : ReportDetailsOUs(NonCompliantOUs2_1),
        "ActualValue" : {"NonCompliantOUs":NonCompliantOUs2_1},
        "RequirementMet" : Status,
        "NoSuchEvent": false}]{
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("GroupsSharingSettingsProto owners_can_allow_external_members", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_1) == 0
}
#--

################
# Baseline 3   #
################
#
# Baseline GWS.GROUPS.3.1v0.1
#--
NonCompliantOUs3_1[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

tests[{ "PolicyId" : "GWS.GROUPS.3.1v0.1",
        "Criticality" : "Should",
        "ReportDetails" : NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue" : "No relevant event in the current logs",
        "RequirementMet" : DefaultSafe,
        "NoSuchEvent": true}]{
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public", TopLevelOU)
    count(Events) == 0 #If no events were logged, then the default 
}

tests[{ "PolicyId" : "GWS.GROUPS.3.1v0.1",
        "Criticality" : "Should",
        "ReportDetails" : ReportDetailsOUs(NonCompliantOUs3_1),
        "ActualValue" : {"NonCompliantOUs": NonCompliantOUs3_1},
        "RequirementMet" : Status,
        "NoSuchEvent": false}]{
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs3_1) == 0
}
#--


################
# Baseline 4   #
################
#
# Baseline GWS.GROUPS.4.1v0.1
#--
NonCompliantOUs4_1[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("GroupsSharingSettingsProto who_can_create_groups", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "ADMIN_ONLY"
}
tests[{ "PolicyId" : "GWS.GROUPS.4.1v0.1",
        "Criticality" : "Should",
        "ReportDetails" :NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue" : "No relevant event in the current logs",
        "RequirementMet" : DefaultSafe,
        "NoSuchEvent": true}]{
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("GroupsSharingSettingsProto who_can_create_groups", TopLevelOU)
    count(Events) == 0 #If no events were logged, then the default 
}

tests[{ "PolicyId" : "GWS.GROUPS.4.1v0.1",
        "Criticality" : "Should",
        "ReportDetails" : ReportDetailsOUs(NonCompliantOUs4_1),
        "ActualValue" : {"NonCompliantOUs": NonCompliantOUs4_1},
        "RequirementMet" : Status,
        "NoSuchEvent": false}]{
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("GroupsSharingSettingsProto who_can_create_groups", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_1) == 0
}
#--


################
# Baseline 5   #
################

#
# Baseline GWS.GROUPS.5.1v0.1
#--

NonCompliantOUs5_1[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("GroupsSharingSettingsProto default_view_topics_access_level", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "MEMBERS"
}
tests[{ "PolicyId" : "GWS.GROUPS.5.1v0.1",
        "Criticality" : "Should",
        "ReportDetails" : NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue" : "No relevant event in the current logs",
        "RequirementMet" : DefaultSafe,
        "NoSuchEvent": true}]{
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("GroupsSharingSettingsProto default_view_topics_access_level", TopLevelOU)
    count(Events) == 0 #If no events were logged, then the default
}

tests[{ "PolicyId" : "GWS.GROUPS.5.1v0.1",
        "Criticality" : "Should",
        "ReportDetails" : ReportDetailsOUs(NonCompliantOUs5_1),
        "ActualValue" : {"NonCompliantOUs": NonCompliantOUs5_1},
        "RequirementMet" : Status,
        "NoSuchEvent": false}]{
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("GroupsSharingSettingsProto default_view_topics_access_level", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_1) == 0
}
#--


################
# Baseline 6   #
################
#
# Baseline GWS.GROUPS.6.1v0.1
#--

NonCompliantOUs6_1[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("GroupsSharingSettingsProto allow_unlisted_groups", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "false"
}
tests[{ "PolicyId" : "GWS.GROUPS.6.1v0.1",
        "Criticality" : "Shall",
        "ReportDetails" : NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue" :"No relevant event in the current logs",
        "RequirementMet" : DefaultSafe,
        "NoSuchEvent": true}]{
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("GroupsSharingSettingsProto allow_unlisted_groups", TopLevelOU)
    count(Events) == 0 #If no events were logged, then the default 
}

tests[{ "PolicyId" : "GWS.GROUPS.6.1v0.1",
        "Criticality" : "Shall",
        "ReportDetails" :ReportDetailsOUs(NonCompliantOUs6_1),
        "ActualValue" : {"NonCompliantOUs": NonCompliantOUs6_1},
        "RequirementMet" : Status,
        "NoSuchEvent": false}]{
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("GroupsSharingSettingsProto allow_unlisted_groups", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs6_1) == 0
}
#--

################
# Baseline 7   #
################
#
# Baseline GWS.GROUPS.7.1v0.1
#--

# This sets up for a logical OR between all the settings. If one of them is false, it will trigger the function and add the group to the list.
IsGroupRestricted(group) {
    group.whoCanJoin != "CAN_REQUEST_TO_JOIN"
}

IsGroupRestricted(group) {
    group.whoCanViewMembership != "ALL_MEMBERS_CAN_VIEW"
}

IsGroupRestricted(group) {
    group.whoCanViewGroup != "ALL_MEMBERS_CAN_VIEW" 
}

IsGroupRestricted(group) {
    group.whoCanModerateMembers != "OWNERS_AND_MANAGERS"
}

IsGroupRestricted(group) {
    group.allowExternalMembers != "false" 
}

IsGroupRestricted(group) {
    group.whoCanPostMessage != "ALL_MEMBERS_CAN_POST"
}

IsGroupRestricted(group) {
    group.whoCanContactOwner != "ANYONE_CAN_CONTACT"
}

NonCompliantGroups7_1[group.name] { 
    group := input.group_settings[_]
    IsGroupRestricted(group)
}

# if there are no groups, it has to be safe.
tests[{ "PolicyId" : "GWS.GROUPS.7.1v0.1",
        "Criticality" : "Should",
        "ReportDetails" : NoGroupsDetails(Groups),
        "ActualValue" : NoGroupsDetails(Groups),
        "RequirementMet" : true,
        "NoSuchEvent": false}]{
    Groups := [Group.email | Group = input.group_settings[_]]
    count(Groups) == 0
}

# if there are groups
tests[{ "PolicyId" : "GWS.GROUPS.7.1v0.1",
        "Criticality" : "Should",
        "ReportDetails" : ReportDetailsGroups(NonCompliantGroups7_1),
        "ActualValue" : {"NonCompliantGroups": NonCompliantGroups7_1},
        "RequirementMet" : Status,
        "NoSuchEvent": false}]{
    Groups := [Group.email | Group = input.group_settings[_]]
    count(Groups) > 0
    Status := count(NonCompliantGroups7_1) == 0 
}
#--