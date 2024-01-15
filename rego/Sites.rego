package sites

import data.utils
import future.keywords

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

    "SERVICE_NAME" in {Parameter.name | some Parameter in Event.parameters}
    "ORG_UNIT_NAME" in {Parameter.name | some Parameter in Event.parameters}
    "NEW_VALUE" in {Parameter.name | some Parameter in Event.parameters}

    ServiceName := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "SERVICE_NAME"][0]
    NewValue := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "NEW_VALUE"][0]
    OrgUnit := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "ORG_UNIT_NAME"][0]

    ServiceName == "Sites"
}

###############
# GWS.SITES.1 #
###############

#
# Baseline GWS.SITES.1.1v0.1
#--
NonCompliantOUs1_1 contains OU if {
    some OU in utils.OUsWithEvents
    Events := FilterEventsOU(OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests contains {
    "PolicyId": "GWS.SITES.1.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEventsOU(utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.SITES.1.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsOUs(NonCompliantOUs1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEventsOU(utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_1) == 0
}
#--