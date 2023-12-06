package sites
import future.keywords
import data.utils.ReportDetailsOUs
import data.utils.NoSuchEventDetails

FilterEvents(ServiceName) := FilteredEvents if
{
    Events := ServiceChangeEvents
    FilteredEvents := [Event | Event = Events[_]; Event.Service == ServiceName]
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

ServiceChangeEvents[{"Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "NewValue": NewValue,
    "Service": Service,
    "OrgUnit": OrgUnit}] {

    Item := input.sites_logs.items[_] # For each item...
    Event := Item.events[_] # For each event in the item...

    # Does this event have the parameters we're looking for?
    "SERVICE_NAME" in [Parameter.name | Parameter = Event.parameters[_]]
    "NEW_VALUE" in [Parameter.name | Parameter = Event.parameters[_]]
    "ORG_UNIT_NAME" in [Parameter.name | Parameter = Event.parameters[_]]

    # Extract the values
    Service := [Parameter.value | Parameter = Event.parameters[_]; Parameter.name == "SERVICE_NAME"][0]
    NewValue := [Parameter.value | Parameter = Event.parameters[_]; Parameter.name == "NEW_VALUE"][0]
    OrgUnit := [Parameter.value | Parameter = Event.parameters[_]; Parameter.name == "ORG_UNIT_NAME"][0]
}

GetLastEvent(Events) := Event if {
    MaxTs := max([Event.Timestamp | Event = Events[_]])
    Event := Events[_]
    Event.Timestamp == MaxTs
}

FilterEventsAlt(EventName) := Events if {
    # Many of the events for common controls are structured differently.
    # Instead of having Service_NAME as one of the parameters, the event
    # name is set to what would normally be the Service name.
    Events := ServiceChangeEventsAlt with data.EventName as EventName
}

FilterEventsAltOU(EventName, OrgUnit) := FilteredEvents if {
    # Filter the events by both EventName and OrgUnit
    Events := FilterEventsAlt(EventName)
    FilteredEvents := [Event | Event = Events[_]; Event.OrgUnit == OrgUnit]
}

GetEventOu(Event) := OrgUnit if {
    # Helper function that helps the ServiceChange rules always work,
    # even if the org unit isn't actually listed with the event
    "ORG_UNIT_NAME" in [Parameter.name | Parameter = Event.parameters[_]]
    OrgUnit := [Parameter.value | Parameter = Event.parameters[_]; Parameter.name == "ORG_UNIT_NAME"][0]
}

GetEventOu(Event) := "None" if {
    not "ORG_UNIT_NAME" in [Parameter.name | Parameter = Event.parameters[_]]
}

ServiceChangeEventsAlt[{"Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "NewValue": NewValue,
    "OrgUnit": OrgUnit}] {
    Item := input.sites_logs.items[_] # For each item...
    Event := Item.events[_]
    Event.name == data.EventName # Note the data.EventName. This means this
    # rule will only work if called like this:
    # ServiceChangeEventsAlt with data.EventName as ExampleEventName

    "NEW_VALUE" in [Parameter.name | Parameter = Event.parameters[_]]
    NewValue := [Parameter.value | Parameter = Event.parameters[_]; Parameter.name == "NEW_VALUE"][0]
    OrgUnit := GetEventOu(Event)
}

ServiceChangeEventsAlt[{"Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "NewValue": NewValue,
    "OrgUnit": OrgUnit}] {
    Item := input.sites_logs.items[_] # For each item...
    Event := Item.events[_]
    Event.name == data.EventName

    not "NEW_VALUE" in [Parameter.name | Parameter = Event.parameters[_]]
    # If NEW_VALUE isn't a parameter, then the parameter name will be
    # data.EventName minus the leading CHANGE_ and the trailing S, e.g.,
    # CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS -> ALLOWED_TWO_STEP_VERIFICATION_METHOD
    EventName := trim_suffix(trim_prefix(data.EventName, "CHANGE_"), "S")
    NewValue := [Parameter.value | Parameter = Event.parameters[_]; Parameter.name == EventName][0]
    OrgUnit := GetEventOu(Event)
}

GetTopLevelOU() := Name if {
    # Simplest case: if input.tenant_info.topLevelOU is
    # non-empty, it contains the name of the top-level OU.
    input.tenant_info.topLevelOU != ""
    Name := input.tenant_info.topLevelOU
}

GetTopLevelOU() := Name if {
    # input.tenant_info.topLevelOU will be empty when
    # no custom OUs have been created, as in this case
    # the top-level OU cannot be determined via the API.
    # Fortunately, in this case, we know there's literally
    # only one OU, so we can grab the OU listed on any of
    # the events and know that it is the top-level OU
    input.tenant_info.topLevelOU == ""
    count(ServiceChangeEvents) > 0
    Name := GetLastEvent(ServiceChangeEvents).OrgUnit
}

GetTopLevelOU() := Name if {
    # Extreme edge case: no custom OUs have been made
    # and the logs are empty. In this case, we really
    # have no way of determining the top-level OU name.
    input.tenant_info.topLevelOU == ""
    count(ServiceChangeEvents) == 0
    Name := ""
}


OUsWithEvents[OrgUnit] {
    Item := input.sites_logs.items[_]
    Event := Item.events[_]
    "ORG_UNIT_NAME" in [Parameter.name | Parameter = Event.parameters[_]]
    OrgUnit := [Parameter.value | Parameter = Event.parameters[_]; Parameter.name == "ORG_UNIT_NAME"][0]
}


################
# GWS.SITES.1  #
################

#
# Baseline GWS.SITES.1.1v0.1
#--

NonCompliantOUs1_1[OU] {
    OU := OUsWithEvents[_]
    #Events := FilterEventsAltOU("TOGGLE_SERVICE_ENABLED", OU)
    Events := FilterEventsOU("Sites", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests[{
        "PolicyId" : "GWS.SITES.1.1v0.1",
        "Criticality": "Should",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}] {
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("Sites", TopLevelOU)
    count(Events) == 0
}

tests[{
        "PolicyId": "GWS.SITES.1.1v0.1",
        "Criticality": "Should",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_1),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
        "RequirementMet": Status,
        "NoSuchEvent": false}] {
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("Sites", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_1) == 0
}
