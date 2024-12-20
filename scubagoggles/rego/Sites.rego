package sites

import future.keywords
import data.utils
import data.utils.PolicyApiInUse

SitesEnabled(orgunit) := utils.AppEnabled(input.policies, "sites", orgunit)

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

FilterEventsGroup(Group) := FilteredEvents if {
    Events := ToggleServiceEvents
    FilteredEvents := {Event | some Event in Events; Event.Group == Group}
}

ToggleServiceEvents contains {
    "Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "NewValue": NewValue,
    "OrgUnit": OrgUnit,
    "Group": Group
}
if {
    some Item in input.sites_logs.items
    some Event in Item.events
    Event.name == "TOGGLE_SERVICE_ENABLED"

    "SERVICE_NAME" in {Parameter.name | some Parameter in Event.parameters}
    "NEW_VALUE" in {Parameter.name | some Parameter in Event.parameters}

    ServiceName := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "SERVICE_NAME"][0]
    NewValue := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "NEW_VALUE"][0]
    OrgUnit := utils.GetEventOu(Event)
    Group := utils.GetEventGroup(Event)

    ServiceName == "Sites"
}

###############
# GWS.SITES.1 #
###############

#
# Baseline GWS.SITES.1.1
#--
ServiceStatusOnMessage := "Service status for Sites is ON."

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": ServiceStatusOnMessage
} if {
    not PolicyApiInUse
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

NonCompliantGroups1_1 contains {
    "Name": Group,
    "Value": ServiceStatusOnMessage
} if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := FilterEventsGroup(Group)
    # Ignore Groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

NonCompliantOUs1_1  contains {
    "Name": OU,
    "Value": ServiceStatusOnMessage
} if {
    some OU, settings in input.policies
    SitesEnabled(OU)
}

# This check is done a few times below.  It's True if either the policy API
# is in use or there is at least one event returned for the top-level orgunit.

CheckOK if {
    not PolicyApiInUse
    events := FilterEventsOU(utils.TopLevelOU)
    count(events) > 0
}

CheckOK if {PolicyApiInUse}

SitesId1_1 := utils.PolicyIdWithSuffix("GWS.SITES.1.1")

tests contains {
    "PolicyId": SitesId1_1,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not CheckOK
}

tests contains {
    "PolicyId": SitesId1_1,
    "Criticality": "Should",
    "ReportDetails":utils.ReportDetails(NonCompliantOUs1_1,
                                        NonCompliantGroups1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1,
                    "NonCompliantGroups": NonCompliantGroups1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    CheckOK
    Conditions := {count(NonCompliantOUs1_1) == 0,
                   count(NonCompliantGroups1_1) == 0}
    Status := (false in Conditions) == false
}
#--
