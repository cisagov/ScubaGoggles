package groups
import future.keywords
import data.utils.TopLevelOU
import data.utils.OUsWithEvents
import data.utils.ReportDetailsOUs
import data.utils.NoSuchEventDetails

NoGroupsDetails(Groups) := "No Groups found in Organization." if {
    count(Groups) == 0
}

ReportDetailsGroups(Groups) := "Requirement met in all Groups." if {
    count(Groups) == 0
}

ReportDetailsGroups(Groups) := Message if {
    count(Groups) > 0
    Message := concat("", ["Requirement failed in ", concat(", ", Groups), "."])
}

FilterEvents(SettingName) := FilteredEvents if {
    # Filter the events by SettingName
    Events := SettingChangeEvents
    FilteredEvents := {Event | some Event in Events; Event.Setting == SettingName}
}

FilterEventsOU(SettingName, OrgUnit) := FilteredEvents if {
    # If there exists at least the root OU and 1 more OU
    # filter out organizational units that don't exist
    input.organizational_unit_names
    count(input.organizational_unit_names) >=2

    # Filter the events by both SettingName and OrgUnit
    Events := FilterEvents(SettingName)
    FilteredEvents := {
        Event | some Event in Events;
        Event.OrgUnit == OrgUnit;
        Event.OrgUnit in input.organizational_unit_names
    }
}

FilterEventsOU(SettingName, OrgUnit) := FilteredEvents if {
    # If only the root OU exists run like normal
    input.organizational_unit_names
    count(input.organizational_unit_names) < 2

    # Filter the events by both SettingName and OrgUnit
    Events := FilterEvents(SettingName)
    FilteredEvents := {Event | some Event in Events; Event.OrgUnit == OrgUnit}
}

FilterEventsOU(SettingName, OrgUnit) := FilteredEvents if {
    # If OUs variable does not exist run like normal
    not input.organizational_unit_names

    # Filter the events by both SettingName and OrgUnit
    Events := FilterEvents(SettingName)
    FilteredEvents := {Event | some Event in Events; Event.OrgUnit == OrgUnit}
}

SettingChangeEvents contains {
    "Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "NewValue": NewValue,
    "Setting": Setting,
    "OrgUnit": OrgUnit
}
if {
    some Item in input.groups_logs.items # For each item...
    some Event in Item.events # For each event in the item...

    # Does this event have the parameters we're looking for?
    "SETTING_NAME" in {Parameter.name | some Parameter in Event.parameters}
    "NEW_VALUE" in {Parameter.name | some Parameter in Event.parameters}
    "ORG_UNIT_NAME" in {Parameter.name | some Parameter in Event.parameters}

    # Extract the values
    Setting := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "SETTING_NAME"][0]
    NewValue := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "NEW_VALUE"][0]
    OrgUnit := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "ORG_UNIT_NAME"][0]
}

GetLastEvent(Events) := Event if {
    # Because CalendarSharingEvents returns a set instead
    # of an array, we can't just index it and get the last
    # value
    MaxTs := max({Event.Timestamp | some Event in Events})
    some Event in Events
    Event.Timestamp == MaxTs
}


################
# GWS.GROUPS.1 #
################

#
# Baseline GWS.GROUPS.1.1v0.1
#--
NonCompliantOUs1_1 contains OU if {
     some OU in OUsWithEvents
     Events := FilterEventsOU("GroupsSharingSettingsProto collaboration_policy", OU)
     count(Events) > 0 # Ignore OUs without any events. We're already
     # asserting that the top-level OU has at least one event; for all
     # other OUs we assume they inherit from a parent OU if they have
     # no events.
     LastEvent := GetLastEvent(Events)
     LastEvent.NewValue != "CLOSED"
 }

tests[{ "PolicyId": "GWS.GROUPS.1.1v0.1",
        "Criticality": "Shall",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}]{
        DefaultSafe := false
    Events := FilterEventsOU("GroupsSharingSettingsProto collaboration_policy", TopLevelOU)
    count(Events) == 0
}

tests[{ "PolicyId": "GWS.GROUPS.1.1v0.1",
        "Criticality": "Shall",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_1),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
        "RequirementMet": Status,
        "NoSuchEvent": false}]{
    Events := FilterEventsOU("GroupsSharingSettingsProto collaboration_policy", TopLevelOU)
    count(Events) > 0
    Status :=count(NonCompliantOUs1_1) == 0
}
#--


################
# GWS.GROUPS.2 #
################

#
# Baseline GWS.GROUPS.2.1v0.1
#--
NonCompliantOUs2_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEventsOU("GroupsSharingSettingsProto owners_can_allow_external_members", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

tests contains {
    "PolicyId": "GWS.GROUPS.2.1v0.1",
    "Criticality": "Should",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEventsOU("GroupsSharingSettingsProto owners_can_allow_external_members", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.2.1v0.1",
    "Criticality": "Should",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs2_1),
    "ActualValue": {"NonCompliantOUs":NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEventsOU("GroupsSharingSettingsProto owners_can_allow_external_members", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_1) == 0
}
#--

################
# GWS.GROUPS.3 #
################

#
# Baseline GWS.GROUPS.3.1v0.1
#--
NonCompliantOUs3_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEventsOU("GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

tests contains {
    "PolicyId": "GWS.GROUPS.3.1v0.1",
    "Criticality": "Should",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEventsOU("GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.3.1v0.1",
    "Criticality": "Should",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs3_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEventsOU("GroupsSharingSettingsProto owners_can_allow_incoming_mail_from_public", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs3_1) == 0
}
#--


################
# GWS.GROUPS.4 #
################

#
# Baseline GWS.GROUPS.4.1v0.1
#--
NonCompliantOUs4_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEventsOU("GroupsSharingSettingsProto who_can_create_groups", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "ADMIN_ONLY"
}

tests contains {
    "PolicyId": "GWS.GROUPS.4.1v0.1",
    "Criticality": "Should",
    "ReportDetails":NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEventsOU("GroupsSharingSettingsProto who_can_create_groups", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.4.1v0.1",
    "Criticality": "Should",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs4_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEventsOU("GroupsSharingSettingsProto who_can_create_groups", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_1) == 0
}
#--


################
# GWS.GROUPS.5 #
################

#
# Baseline GWS.GROUPS.5.1v0.1
#--
NonCompliantOUs5_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEventsOU("GroupsSharingSettingsProto default_view_topics_access_level", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "MEMBERS"
}

tests contains {
    "PolicyId": "GWS.GROUPS.5.1v0.1",
    "Criticality": "Should",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEventsOU("GroupsSharingSettingsProto default_view_topics_access_level", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.5.1v0.1",
    "Criticality": "Should",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs5_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEventsOU("GroupsSharingSettingsProto default_view_topics_access_level", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_1) == 0
}
#--


################
# GWS.GROUPS.6 #
################

#
# Baseline GWS.GROUPS.6.1v0.1
#--
NonCompliantOUs6_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEventsOU("GroupsSharingSettingsProto allow_unlisted_groups", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

tests contains {
    "PolicyId": "GWS.GROUPS.6.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue":"No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEventsOU("GroupsSharingSettingsProto allow_unlisted_groups", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.GROUPS.6.1v0.1",
    "Criticality": "Shall",
    "ReportDetails":ReportDetailsOUs(NonCompliantOUs6_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs6_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEventsOU("GroupsSharingSettingsProto allow_unlisted_groups", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs6_1) == 0
}
#--

################
# GWS.GROUPS.7 #
################

#
# Baseline GWS.GROUPS.7.1v0.1
#--
# This sets up for a logical OR between all the settings. If one of them is false,
# it will trigger the function and add the group to the list.
IsGroupRestricted(Group) {
    Group.whoCanJoin != "CAN_REQUEST_TO_JOIN"
}

IsGroupRestricted(Group) {
    Group.whoCanViewMembership != "ALL_MEMBERS_CAN_VIEW"
}

IsGroupRestricted(Group) {
    Group.whoCanViewGroup != "ALL_MEMBERS_CAN_VIEW"
}

IsGroupRestricted(Group) {
    Group.whoCanModerateMembers != "OWNERS_AND_MANAGERS"
}

IsGroupRestricted(Group) {
    Group.allowExternalMembers != "false"
}

IsGroupRestricted(Group) {
    Group.whoCanPostMessage != "ALL_MEMBERS_CAN_POST"
}

IsGroupRestricted(Group) {
    Group.whoCanContactOwner != "ANYONE_CAN_CONTACT"
}

NonCompliantGroups7_1 contains Group.name if {
    some Group in input.group_settings
    IsGroupRestricted(Group)
}

# if there are no groups, it has to be safe.
tests contains {
    "PolicyId": "GWS.GROUPS.7.1v0.1",
    "Criticality": "Should",
    "ReportDetails": NoGroupsDetails(Groups),
    "ActualValue": NoGroupsDetails(Groups),
    "RequirementMet": true,
    "NoSuchEvent": false
}
if {
    Groups := {Group.email | some Group in input.group_settings}
    count(Groups) == 0
}

# if there are groups
tests contains {
    "PolicyId": "GWS.GROUPS.7.1v0.1",
    "Criticality": "Should",
    "ReportDetails": ReportDetailsGroups(NonCompliantGroups7_1),
    "ActualValue": {"NonCompliantGroups": NonCompliantGroups7_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Groups := {Group.email | some Group in input.group_settings}
    count(Groups) > 0
    Status := count(NonCompliantGroups7_1) == 0
}
#--