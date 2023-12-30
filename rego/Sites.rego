package sites
import future.keywords
import data.utils.ReportDetailsOUs
import data.utils.NoSuchEventDetails

FilterEventsOU(OrgUnit) := FilteredEvents if {
    # If there exists at least the root OU and 1 more OU
    # filter out organizational units that don't exist
    input.organizational_unit_names
    count(input.organizational_unit_names) >=2

    # Filter the events by OrgUnit
    Events := ToggleServiceEvents
    FilteredEvents := {
        Event | some Event in Events;
        Event.OrgUnit == OrgUnit;
        Event.OrgUnit in input.organizational_unit_names
    }
}

FilterEventsOU(OrgUnit) := FilteredEvents if {
    # If only the root OU exists run like normal
    input.organizational_unit_names
    count(input.organizational_unit_names) < 2

    # Filter the events by OrgUnit
    Events := ToggleServiceEvents
    FilteredEvents := {Event | some Event in Events; Event.OrgUnit == OrgUnit}
}

FilterEventsOU(OrgUnit) := FilteredEvents if {
    # If OUs variable does not exist run like normal
    not input.organizational_unit_names

    # Filter the events by OrgUnit
    Events := ToggleServiceEvents
    FilteredEvents := {Event | some Event in Events; Event.OrgUnit == OrgUnit}
}

GetLastEvent(Events) := Event if {
    MaxTs := max({Event.Timestamp | some Event in Events})
    some Event in Events
    Event.Timestamp == MaxTs
}

ToggleServiceEvents contains {
    "Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "NewValue": NewValue,
    "OrgUnit": OrgUnit
}
if {
    some Item in input.sites_logs.items
    some Event in Item.events
    Event.name == "TOGGLE_SERVICE_ENABLED"

    "SERVICE_NAME" in [Parameter.name | some Parameter in Event.parameters]
    "ORG_UNIT_NAME" in [Parameter.name | some Parameter in Event.parameters]
    "NEW_VALUE" in [Parameter.name | some Parameter in Event.parameters]

    ServiceName := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "SERVICE_NAME"][0]
    NewValue := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "NEW_VALUE"][0]
    OrgUnit := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "ORG_UNIT_NAME"][0]

    ServiceName == "Sites"
}

OUsWithEvents contains OrgUnit if {
    some Item in input.sites_logs.items
    some Event in Item.events
    some Parameter in Event.parameters
    Parameter.name == "ORG_UNIT_NAME"
    OrgUnit := Parameter.value
}

TopLevelOU := Name if {
    # Simplest case: if input.tenant_info.topLevelOU is
    # non-empty, it contains the name of the top-level OU.
    input.tenant_info.topLevelOU != ""
    Name := input.tenant_info.topLevelOU
}

TopLevelOU := OU if {
    # input.tenant_info.topLevelOU will be empty when
    # no custom OUs have been created, as in this case
    # the top-level OU cannot be determined via the API.
    # Fortunately, in this case, we know there's literally
    # only one OU, so we can grab the OU listed on any of
    # the events and know that it is the top-level OU
    input.tenant_info.topLevelOU == ""
    some OU in OUsWithEvents
}

TopLevelOU := Name if {
    # Extreme edge case: no custom OUs have been made
    # and the logs are empty. In this case, we really
    # have no way of determining the top-level OU name.
    input.tenant_info.topLevelOU == ""
    count(OUsWithEvents) == 0
    Name := ""
}

###############
# GWS.SITES.1 #
###############

#
# Baseline GWS.SITES.1.1v0.1
#--
NonCompliantOUs1_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEventsOU(OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests contains {
    "PolicyId": "GWS.SITES.1.1v0.1",
    "Criticality": "Should",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEventsOU(TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.SITES.1.1v0.1",
    "Criticality": "Should",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEventsOU(TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_1) == 0
}
#--