package utils
import future.keywords

NoSuchEventDetails(DefaultSafe, TopLevelOU) := Message if {
    DefaultSafe == true
    Message := concat("", [
        "No relevant event in the current logs for the top-level OU, ",
        TopLevelOU,
        ". While we are unable to determine the state from the logs, the default setting is compliant",
        "; manual check recommended."
    ])
}

NoSuchEventDetails(DefaultSafe, TopLevelOU) := Message if {
    DefaultSafe == false
    Message := concat("", [
        "No relevant event in the current logs for the top-level OU, ",
        TopLevelOU,
        ". While we are unable to determine the state from the logs, the default setting is non-compliant",
        "; manual check recommended."
    ])
}

ReportDetailsOUs(OUs) := "Requirement met in all OUs." if {
    count(OUs) == 0
}

ReportDetailsOUs(OUs) := Message if {
    count(OUs) > 0
    Message := concat("", ["Requirement failed in ", concat(", ", OUs), "."])
}

NoGroupsDetails(Groups) := "No groups found in Organization." if {
    count(Groups) == 0
}

ReportDetailsGroups(Groups) := "Requirement met in all groups." if {
    count(Groups) == 0
}

ReportDetailsGroups(Groups) := Message if {
    count(Groups) > 0
    Message := concat("", ["Requirement failed in ", concat(", ", Groups), "."])
}

ReportDetailsBoolean(true) := "Requirement met."

ReportDetailsBoolean(false) := "Requirement not met."

ReportDetailsDetailedOU(_, NonCompOUs) := "Requirement met in all OUs." if {
    count(NonCompOUs) == 0
}

# Create a html formatted list detailing the settings for each OU
# - NonCompOUs: a set of dicts, each with a "Name" and "Value" fields
EnumOUSettings(NonCompOUs) := concat("", [
    "The following OUs are non-compliant:",
    "<ul>",
    concat("", [concat("", [
        "<li>",
        OU.Name,
        ": ",
        OU.Value,
        "</li>"
    ]) | some OU in NonCompOUs]),
    "</ul>"
])

# Create a html formatted list detailing the settings for each group
# - NonCompGroups: a set of dicts, each with a "Name" and "Value" fields
EnumGroupSettings(NonCompGroups) := concat("", [
    "The following groups are non-compliant:",
    "<ul>",
    concat("", [concat("", [
        "<li>",
        Group.Name,
        ": ",
        Group.Value,
        "</li>"
    ]) | some Group in NonCompGroups]),
    "</ul>"
])

ReportDetails(NonCompOUs, NonCompGroups) := Description if {
    count(NonCompOUs) > 0
    count(NonCompGroups) > 0
    Description := concat("<br>", [
        EnumOUSettings(NonCompOUs),
        EnumGroupSettings(NonCompGroups),
    ])
}

ReportDetails(NonCompOUs, NonCompGroups) := Description if {
    count(NonCompOUs) > 0
    count(NonCompGroups) == 0
    Description := EnumOUSettings(NonCompOUs)
}

ReportDetails(NonCompOUs, NonCompGroups) := Description if {
    count(NonCompOUs) == 0
    count(NonCompGroups) > 0
    Description := EnumGroupSettings(NonCompGroups)
}

ReportDetails(NonCompOUs, NonCompGroups) := Description if {
    count(NonCompOUs) == 0
    count(NonCompGroups) == 0
    Description := "Requirement met in all OUs and groups."
}

OUsWithEvents contains OrgUnit if {
    some Log in input
    some Item in Log.items
    some Event in Item.events
    some Parameter in Event.parameters
    Parameter.name == "ORG_UNIT_NAME"
    OrgUnit := Parameter.value
}

GroupsWithEvents contains Group if {
    some Log in input
    some Item in Log.items
    some Event in Item.events
    some Parameter in Event.parameters
    Parameter.name == "GROUP_EMAIL"
    Group := Parameter.value
}

# Simplest case: if input.tenant_info.topLevelOU is
# non-empty, it contains the name of the top-level OU.
TopLevelOU := Name if {
    input.tenant_info.topLevelOU != ""
    Name := input.tenant_info.topLevelOU
}

# input.tenant_info.topLevelOU will be empty when
# no custom OUs have been created, as in this case
# the top-level OU cannot be determined via the API.
# Fortunately, in this case, we know there's literally
# only one OU, so we can grab the OU listed on any of
# the events and know that it is the top-level OU
TopLevelOU := OU if {
    input.tenant_info.topLevelOU == ""
    count(OUsWithEvents) == 1
    some OU in OUsWithEvents
}

# Extreme edge case: input.tenant_info.topLevelOU is empty
# because no custom OUs currently exist, but multiple OUs
# are present in the events, likely due to an custom OU
# that was deleted. In this case, we have no way of determining
# which of OUs is the current OU.
TopLevelOU := Name if {
    input.tenant_info.topLevelOU == ""
    count(OUsWithEvents) > 1
    Name := ""
}

# Extreme edge case: no custom OUs have been made
# and the logs are empty. In this case, we really
# have no way of determining the top-level OU name.
TopLevelOU := Name if {
    input.tenant_info.topLevelOU == ""
    count(OUsWithEvents) == 0
    Name := ""
}

GetLastEvent(Events) := Event if {
    MaxTs := max({Event.Timestamp | some Event in Events})
    some Event in Events
    Event.Timestamp == MaxTs
}

# Helper function so that the regular SettingChangeEvents
# rule will work even for events that don't include the
# domain name
GetEventDomain(Event) := DomainName if {
    "DOMAIN_NAME" in {Parameter.name | some Parameter in Event.parameters}
    DomainName := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "DOMAIN_NAME"][0]
}

GetEventDomain(Event) := "None" if {
    not "DOMAIN_NAME" in {Parameter.name | some Parameter in Event.parameters}
}

# Helper function so that the regular SettingChangeEvents
# rule will work even for events that don't include the
# application name
GetEventApp(Event) := AppName if {
    "APPLICATION_NAME" in {Parameter.name | some Parameter in Event.parameters}
    AppName := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "APPLICATION_NAME"][0]
}

GetEventApp(Event) := "None" if {
    not "APPLICATION_NAME" in {Parameter.name | some Parameter in Event.parameters}
}

# Helper function so that the regular SettingChangeEvents
# rule will work even for events that don't include the
# OU name
GetEventOu(Event) := OrgUnit if {
    "ORG_UNIT_NAME" in {Parameter.name | some Parameter in Event.parameters}
    OrgUnit := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "ORG_UNIT_NAME"][0]
}

GetEventOu(Event) := "None" if {
    not "ORG_UNIT_NAME" in {Parameter.name | some Parameter in Event.parameters}
}

# Helper function so that the regular SettingChangeEvents
# rule will work even for events that don't include the
# Group name
GetEventGroup(Event) := Group if {
    "GROUP_EMAIL" in {Parameter.name | some Parameter in Event.parameters}
    Group := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "GROUP_EMAIL"][0]
}

GetEventGroup(Event) := "" if {
    not "GROUP_EMAIL" in {Parameter.name | some Parameter in Event.parameters}
}

SettingChangeEvents contains {
    "Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "NewValue": NewValue,
    "Setting": Setting,
    "OrgUnit": OrgUnit,
    "Group": Group,
    "DomainName": DomainName,
    "AppName": AppName
}
if {
    some Item in input[data.LogName].items
    some Event in Item.events

    # Does this event have the parameters we're looking for?
    "SETTING_NAME" in {Parameter.name | some Parameter in Event.parameters}
    "NEW_VALUE" in {Parameter.name | some Parameter in Event.parameters}

    # Extract the values that are there for every event
    Setting := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "SETTING_NAME"][0]
    NewValue := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "NEW_VALUE"][0]

    # Extract the values that are there for only some of the events
    DomainName := GetEventDomain(Event)
    AppName := GetEventApp(Event)
    OrgUnit := GetEventOu(Event)
    Group := GetEventGroup(Event)
}

# Secondary case that looks for the DELETE_APPLICATION_SETTING events.
# These events don't have a NEW_VALUE. To make these events work with
# minimal special logic, this rule adds the DELETE_APPLICATION_SETTING
# to the SettingChangeEvents set, with "DELETE_APPLICATION_SETTING" as
# the NewValue.
SettingChangeEvents contains {
    "Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "NewValue": NewValue,
    "Setting": Setting,
    "OrgUnit": OrgUnit,
    "Group": Group,
    "DomainName": DomainName,
    "AppName": AppName
}
if {
    some Item in input[data.LogName].items
    some Event in Item.events
    Event.name == "DELETE_APPLICATION_SETTING" # Only look at delete events

    # Does this event have the parameters we're looking for?
    "SETTING_NAME" in {Parameter.name | some Parameter in Event.parameters}

    NewValue := "DELETE_APPLICATION_SETTING"

    # Extract the values that are there for every event
    Setting := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "SETTING_NAME"][0]

    # Extract the values that are there for only some of the events
    DomainName := GetEventDomain(Event)
    AppName := GetEventApp(Event)
    OrgUnit := GetEventOu(Event)
    Group := GetEventGroup(Event)
}

# Special case needed for Common Controls, Russian localization setting
SettingChangeEvents contains {
    "Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "NewValue": NewValue,
    "OrgUnit": OrgUnit,
    "Group": Group,
    "Setting": "CHANGE_DATA_LOCALIZATION_FOR_RUSSIA",
    "AppName": "NA"
}
if {
    some Item in input[data.LogName].items
    some Event in Item.events

    Event.name == "CHANGE_DATA_LOCALIZATION_FOR_RUSSIA"

    # Does this event have the parameters we're looking for?
    "NEW_VALUE" in {Parameter.name | some Parameter in Event.parameters}

    # Extract the values
    NewValue := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "NEW_VALUE"][0]
    OrgUnit := GetEventOu(Event)
    Group := GetEventGroup(Event)
}

FilterEventsGroup(Events, SettingName, Group) := {
    Event | some Event in Events;
    Event.Group == Group;
    Event.Setting == SettingName
}

# The FilterEvents(...) function is only here to maintain backwards compatability.
# After https://github.com/cisagov/ScubaGoggles/issues/190 is complete, delete
# this function.
FilterEvents(Events, SettingName, OrgUnit) := FilteredEvents if {
    # If there exists at least the root OU and 1 more OU
    # filter out organizational units that don't exist
    input.organizational_unit_names
    count(input.organizational_unit_names) >= 2

    # Filter the events by both SettingName and OrgUnit
    FilteredEvents := {
        Event | some Event in Events;
        Event.OrgUnit == OrgUnit;
        Event.Setting == SettingName;
        Event.OrgUnit in input.organizational_unit_names
    }
}

FilterEvents(Events, SettingName, OrgUnit) := FilteredEvents if {
    # If only the root OU exists run like normal
    input.organizational_unit_names
    count(input.organizational_unit_names) < 2

    # Filter the events by both SettingName and OrgUnit
    FilteredEvents := {
        Event | some Event in Events;
        Event.OrgUnit == OrgUnit;
        Event.Setting == SettingName
    }
}

FilterEvents(Events, SettingName, OrgUnit) := FilteredEvents if {
    # If OUs variable does not exist run like normal
    not input.organizational_unit_names

    # Filter the events by both SettingName and OrgUnit
    FilteredEvents := {
        Event | some Event in Events;
        Event.OrgUnit == OrgUnit;
        Event.Setting == SettingName
    }
}


FilterEventsOU(Events, SettingName, OrgUnit) := FilteredEvents if {
    # If there exists at least the root OU and 1 more OU
    # filter out organizational units that don't exist
    input.organizational_unit_names
    count(input.organizational_unit_names) >= 2

    # Filter the events by both SettingName and OrgUnit
    FilteredEvents := {
        Event | some Event in Events;
        # Ignore the events that apply to groups
        Event.Group == "";
        Event.OrgUnit == OrgUnit;
        Event.Setting == SettingName;
        Event.OrgUnit in input.organizational_unit_names
    }
}

FilterEventsOU(Events, SettingName, OrgUnit) := FilteredEvents if {
    # If only the root OU exists run like normal
    input.organizational_unit_names
    count(input.organizational_unit_names) < 2

    # Filter the events by both SettingName and OrgUnit
    FilteredEvents := {
        Event | some Event in Events;
        # Ignore the events that apply to groups
        Event.Group == "";
        Event.OrgUnit == OrgUnit;
        Event.Setting == SettingName
    }
}

FilterEventsOU(Events, SettingName, OrgUnit) := FilteredEvents if {
    # If OUs variable does not exist run like normal
    not input.organizational_unit_names

    # Filter the events by both SettingName and OrgUnit
    FilteredEvents := {
        Event | some Event in Events;
        # Ignore the events that apply to groups
        Event.Group == "";
        Event.OrgUnit == OrgUnit;
        Event.Setting == SettingName
    }
}

# Filter the events by just SettingName, ignoring OU
FilterEventsNoOU(Events, SettingName) := {
    Event | some Event in Events;
    Event.Setting == SettingName
}

GetEvents(LogName) := Events if {
    Events := SettingChangeEvents with data.LogName as LogName
}

# Returns all conditions that match passed value (true/false)
# Commonly used for OR/Any conditions
FilterArray(Conditions, Boolean) := [Condition | some Condition in Conditions; Condition == Boolean]