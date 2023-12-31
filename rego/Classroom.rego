package classroom
import future.keywords
import data.utils.TopLevelOU
import data.utils.OUsWithEvents
import data.utils.ReportDetailsOUs
import data.utils.NoSuchEventDetails

FilterEvents(SettingName) := FilteredEvents if {
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
    some Item in input.classroom_logs.items # For each item...
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
    "OrgUnit": OrgUnit
}
if {
    some Item in input.classroom_logs.items # For each item...
    some Event in Item.events # For each event in the item...
    Event.name == "DELETE_APPLICATION_SETTING" # Only look at delete events

    # Does this event have the parameters we're looking for?
    "SETTING_NAME" in {Parameter.name | some Parameter in Event.parameters}
    "ORG_UNIT_NAME" in {Parameter.name | some Parameter in Event.parameters}

    # Extract the values
    Setting := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "SETTING_NAME"][0]
    NewValue := "DELETE_APPLICATION_SETTING"
    OrgUnit := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "ORG_UNIT_NAME"][0]
}

GetLastEvent(Events) := Event if {
    MaxTs := max({Event.Timestamp | some Event in Events})
    some Event in Events
    Event.Timestamp == MaxTs
}

###################
# GWS.CLASSROOM.1 #
###################

#
# Baseline GWS.CLASSROOM.1.1v0.1
#--
NonCompliantOUs1_1 contains OU if {
   some OU in OUsWithEvents
    Events := FilterEventsOU("ClassMembershipSettingsGroup who_can_join_classes", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "1"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false

    Events := FilterEventsOU("ClassMembershipSettingsGroup who_can_join_classes", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {

    Events := FilterEventsOU("ClassMembershipSettingsGroup who_can_join_classes", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_1) == 0
}
#--

#
# Baseline GWS.CLASSROOM.1.2v0.1
#--
NonCompliantOUs1_2 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEventsOU("ClassMembershipSettingsGroup which_classes_can_users_join", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "1"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.1.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEventsOU("ClassMembershipSettingsGroup which_classes_can_users_join", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.1.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEventsOU("ClassMembershipSettingsGroup which_classes_can_users_join", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_2) == 0
}
#--

###################
# GWS.CLASSROOM.2 #
###################

#
# Baseline GWS.CLASSROOM.2.1v0.1
#--
NonCompliantOUs2_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEventsOU("ApiDataAccessSettingProto api_access_enabled", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.2.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEventsOU("ApiDataAccessSettingProto api_access_enabled", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.2.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs2_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEventsOU("ApiDataAccessSettingProto api_access_enabled", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_1) == 0
}
#--

###################
# GWS.CLASSROOM.3 #
###################

#
# Baseline GWS.CLASSROOM.3.1v0.1
#--
NonCompliantOUs3_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEventsOU("RosterImportSettingsProto sis_integrator", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "SIS_INTEGRATOR_NONE"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.3.1v0.1",
    "Criticality": "Should",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    Events := FilterEventsOU("RosterImportSettingsProto sis_integrator", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.3.1v0.1",
    "Criticality": "Should",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs3_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEventsOU("RosterImportSettingsProto sis_integrator", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs3_1) == 0
}
#--

###################
# GWS.CLASSROOM.4 #
###################

#
# Baseline GWS.CLASSROOM.4.1v0.1
#--
NonCompliantOUs4_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEventsOU("StudentUnenrollmentSettingsProto who_can_unenroll_students", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "ONLY_TEACHERS_CAN_UNENROLL_STUDENTS"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    Events := FilterEventsOU("StudentUnenrollmentSettingsProto who_can_unenroll_students", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs4_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEventsOU("StudentUnenrollmentSettingsProto who_can_unenroll_students", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_1) == 0
}
#--
