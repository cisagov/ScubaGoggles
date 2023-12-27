package calendar
import future.keywords
import data.utils.ReportDetailsOUs
import data.utils.NoSuchEventDetails

OUsWithEvents contains Event.OrgUnit if {
    some Event in SettingChangeEvents
}

FilterEvents(SettingName) := FilteredEvents if {
    # Filter the events by SettingName
    Events := SettingChangeEvents
    FilteredEvents := [Event | some Event in Events; Event.Setting == SettingName]
}

FilterEventsOU(ServiceName, OrgUnit) := FilteredEvents if {
    # If there exists at least the root OU and 1 more OU
    # filter out organizational units that don't exist
    input.organizational_unit_names
    count(input.organizational_unit_names) >=2

    # Filter the events by both ServiceName and OrgUnit
    Events := FilterEvents(ServiceName)
    FilteredEvents := [
        Event | some Event in Events;
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
    FilteredEvents := [Event | some Event in Events; Event.OrgUnit == OrgUnit]
}

FilterEventsOU(SettingName, OrgUnit) := FilteredEvents if {
    # If OUs variable does not exist run like normal
    not input.organizational_unit_names

    # Filter the events by both SettingName and OrgUnit
    Events := FilterEvents(SettingName)
    FilteredEvents := [Event | some Event in Events; Event.OrgUnit == OrgUnit]
}

TopLevelOU := Name if {
    # Simplest case: if input.tenant_info.topLevelOU is
    # non-empty, it contains the name of the top-level OU.
    input.tenant_info.topLevelOU != ""
    Name := input.tenant_info.topLevelOU
}

TopLevelOU := Name if {
    # input.tenant_info.topLevelOU will be empty when
    # no custom OUs have been created, as in this case
    # the top-level OU cannot be determined via the API.
    # Fortunately, in this case, we know there's literally
    # only one OU, so we can grab the OU listed on any of
    # the events and know that it is the top-level OU
    input.tenant_info.topLevelOU == ""
    count(SettingChangeEvents) > 0
    Name := GetLastEvent(SettingChangeEvents).OrgUnit
}

TopLevelOU := Name if {
    # Extreme edge case: no custom OUs have been made
    # and the logs are empty. In this case, we really
    # have no way of determining the top-level OU name.
    input.tenant_info.topLevelOU == ""
    count(SettingChangeEvents) == 0
    count(SettingChangeEventsNoDomain) == 0
    Name := ""
}

TopLevelOU := name if {
    # input.tenant_info.topLevelOU will be empty when
    # no custom OUs have been created, as in this case
    # the top-level OU cannot be determined via the API.
    # Fortunately, in this case, we know there's literally
    # only one OU, so we can grab the OU listed on any of
    # the events and know that it is the top-level OU
    input.tenant_info.topLevelOU == ""
    count(SettingChangeEvents) == 0
    count(SettingChangeEventsNoDomain) > 0
    name := GetLastEvent(SettingChangeEventsNoDomain).OrgUnit
}

SettingChangeEvents contains {
    "Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "NewValue": NewValue,
    "Setting": Setting,
    "OrgUnit": OrgUnit,
    "DomainName": DomainName
}
if {
    some Item in input.calendar_logs.items # For each item...
    some Event in Item.events # For each event in the item...

    # Does this event have the parameters we're looking for?
    "SETTING_NAME" in {Parameter.name | some Parameter in Event.parameters}
    "NEW_VALUE" in {Parameter.name | some Parameter in Event.parameters}
    "ORG_UNIT_NAME" in {Parameter.name | some Parameter in Event.parameters}
    "DOMAIN_NAME" in {Parameter.name | some Parameter in Event.parameters}

    # Extract the values
    Setting := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "SETTING_NAME"][0]
    NewValue := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "NEW_VALUE"][0]
    OrgUnit := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "ORG_UNIT_NAME"][0]
    DomainName := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "DOMAIN_NAME"][0]
}

GetLastEvent(Events) := Event if {
    # Because CalendarSharingEvents returns a set instead
    # of an array, we can't just index it and get the last
    # value
    MaxTs := max([Event.Timestamp | some Event in Events])
    some Event in Events
    Event.Timestamp == MaxTs
}


##################
# GWS.CALENDAR.1 #
##################

#
# Baseline GWS.CALENDAR.1.1v0.1
#--
NonCompliantOUs1_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEventsOU("SHARING_OUTSIDE_DOMAIN", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "SHOW_ONLY_FREE_BUSY_INFORMATION"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests contains {
    "PolicyId": "GWS.CALENDAR.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs.",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEventsOU("SHARING_OUTSIDE_DOMAIN", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CALENDAR.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEventsOU("SHARING_OUTSIDE_DOMAIN", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_1) == 0
}
#--

#
# Baseline GWS.CALENDAR.1.2v0.1
#--
tests contains {
    "PolicyId": "GWS.CALENDAR.1.2v0.1",
    "Criticality": "May/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

##################
# GWS.CALENDAR.2 #
##################

#
# Baseline GWS.CALENDAR.2.1v0.1
#--
NonCompliantOUs2_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEventsOU("ENABLE_EXTERNAL_GUEST_PROMPT", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue == "false"
}

tests contains {
    "PolicyId": "GWS.CALENDAR.2.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEventsOU("ENABLE_EXTERNAL_GUEST_PROMPT", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CALENDAR.2.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs2_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEventsOU("ENABLE_EXTERNAL_GUEST_PROMPT", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_1) == 0
}
#--


##################
# GWS.CALENDAR.3 #
##################

ExtSharingSecondaryCalSettingDetailsStr(LastEvent) := Description if {
    LastEvent.NewValue == "SHOW_ONLY_FREE_BUSY_INFORMATION"
    Description := concat("", [
        "<span class=setting>Only free busy/information for secondary calendars </span> is shared outside ",
        LastEvent.DomainName
    ])
}

ExtSharingSecondaryCalSettingDetailsStr(LastEvent) := Description if {
    LastEvent.NewValue == "READ_ONLY_ACCESS"
    Description := concat("", [
        "<span class=setting>All information for secondary calendars </span> is shared outside ",
        LastEvent.DomainName,
        " but outsiders cannot change calendars."
    ])
}

ExtSharingSecondaryCalSettingDetailsStr(LastEvent) := Description if {
    LastEvent.NewValue == "READ_WRITE_ACCESS"
    Description := concat("", [
        "<span class=setting>All information for secondary calendars </span> is shared outside ",
        LastEvent.DomainName,
        " and outsiders can change calendars."
    ])
}

ExtSharingSecondaryCalSettingDetailsStr(LastEvent) := Description if {
    LastEvent.NewValue == "MANAGE_ACCESS"
    Description := concat("", [
        "<span class=setting>All information for secondary calendars </span> is shared outside ",
        LastEvent.DomainName,
        " and outsiders can manage calendars"
    ])
}

#
# Baseline GWS.CALENDAR.3.1v0.1
#--
tests contains {
    "PolicyId": "GWS.CALENDAR.3.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEvents("SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR")
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CALENDAR.3.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": ExtSharingSecondaryCalSettingDetailsStr(LastEvent),
    "ActualValue": {LastEvent.Setting: LastEvent.NewValue},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEvents("SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR")
    count(Events) > 0
    LastEvent := GetLastEvent(Events)
    Status := LastEvent.NewValue == "SHOW_ONLY_FREE_BUSY_INFORMATION"
}
#--

#
# Baseline GWS.CALENDAR.3.2v0.1
#--
tests contains {
    "PolicyId": "GWS.CALENDAR.3.2v0.1",
    "Criticality": "May/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--



##################
# GWS.CALENDAR.4 #
##################

CalInteropManSettingDetailsStr(LastEvent) := Description if {
    LastEvent.NewValue == "true"
    Description := concat("", [
        "<span class=setting>Calendar interop is enabled </span> for ",
        LastEvent.DomainName
    ])
}

CalInteropManSettingDetailsStr(LastEvent) := Description if {
    LastEvent.NewValue == "false"
    Description := concat("", [
        "<span class=setting>Calendar interop is not enabled </span> for ",
        LastEvent.DomainName
    ])
}

#
# Baseline GWS.CALENDAR.4.1v0.1
#--
tests contains {
    "PolicyId": "GWS.CALENDAR.4.1v0.1",
    "Criticality": "Should",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEvents("ENABLE_EWS_INTEROP")
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CALENDAR.4.1v0.1",
    "Criticality": "Should",
    "ReportDetails": CalInteropManSettingDetailsStr(LastEvent),
    "ActualValue": {LastEvent.Setting: LastEvent.NewValue},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEvents("ENABLE_EWS_INTEROP")
    count(Events) > 0
    LastEvent := GetLastEvent(Events)
    Status := LastEvent.NewValue == "false"
}
#--


#
# Baseline GWS.CALENDAR.4.2v0.1
#--
tests contains {
    "PolicyId": "GWS.CALENDAR.4.2v0.1",
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

##################
# GWS.CALENDAR.5 #
##################

# Extreme outlier. Logs for this event have no Domain
# As such we need to create custom FilterEventsOU function and SettingChangeEvent
# Functions
SettingChangeEventsNoDomain contains {
    "Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "NewValue": NewValue,
    "Setting": Setting,
    "OrgUnit": OrgUnit
}
if {
    some Item in input.calendar_logs.items # For each item...
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

FilterEventsNoDomain(SettingName) := FilteredEvents if {
    # Filter the events by SettingName
    Events := SettingChangeEventsNoDomain
    FilteredEvents := [Event | some Event in Events; Event.Setting == SettingName]
}

FilterNoDomainEventsOU(ServiceName, OrgUnit) := FilteredEvents if {
    # If there exists at least the root OU and 1 more OU
    # filter out organizational units that don't exist
    input.organizational_unit_names
    count(input.organizational_unit_names) >=2

    # Filter the events by both ServiceName and OrgUnit
    Events := FilterEventsNoDomain(ServiceName)
    FilteredEvents := [
        Event | some Event in Events;
        Event.OrgUnit == OrgUnit;
        Event.OrgUnit in input.organizational_unit_names
    ]
}

FilterNoDomainEventsOU(SettingName, OrgUnit) := FilteredEvents if {
    # If only the root OU exists run like normal
    input.organizational_unit_names
    count(input.organizational_unit_names) < 2

    # Filter the events by both SettingName and OrgUnit
    Events := FilterEventsNoDomain(SettingName)
    FilteredEvents := [Event | some Event in Events; Event.OrgUnit == OrgUnit]
}

FilterNoDomainEventsOU(SettingName, OrgUnit) := FilteredEvents if {
    # If OUs variable does not exist run like normal
    not input.organizational_unit_names
    # Filter the events by both SettingName and OrgUnit
    Events := FilterEventsNoDomain(SettingName)
    FilteredEvents := [Event | some Event in Events; Event.OrgUnit == OrgUnit]
}

OUsWithEventsNoDomain contains Event.OrgUnit if {
    some Event in SettingChangeEventsNoDomain
}

NonCompliantOUs5_1 contains OU if {
    some OU in OUsWithEventsNoDomain
    Events := FilterNoDomainEventsOU("CalendarAppointmentSlotAdminSettingsProto payments_enabled", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "false"
}

#
# Baseline GWS.CALENDAR.5.1v0.1
#--
tests contains {
    "PolicyId": "GWS.CALENDAR.5.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs.",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterNoDomainEventsOU("CalendarAppointmentSlotAdminSettingsProto payments_enabled", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CALENDAR.5.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs5_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterNoDomainEventsOU("CalendarAppointmentSlotAdminSettingsProto payments_enabled", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_1) == 0
}
#--