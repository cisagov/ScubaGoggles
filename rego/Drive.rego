package drive
import future.keywords
import data.utils.NoSuchEventDetails
import data.utils.ReportDetailsOUs

OUsWithEvents[Event.OrgUnit] {
    Event := SettingChangeEvents[_]
}

FilterEvents(SettingName) := FilteredEvents if
{
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

SettingChangeEvents[{"Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "NewValue": NewValue,
    "Setting": Setting,
    "OrgUnit": OrgUnit}] {

    Item := input.drive_logs.items[_] # For each item...
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

    Item := input.drive_logs.items[_] # For each item...
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
    # Because CalendarSharingEvents returns a set instead
    # of an array, we can't just index it and get the last
    # value
    MaxTs := max([Event.Timestamp | Event = Events[_]])
    Event := Events[_]
    Event.Timestamp == MaxTs
}

################
# GWS.DRIVEDOCS.1 #
################

#
# Baseline GWS.DRIVEDOCS.1.1v0.1
#--
# TODO: OU inheritence implementation pending after SCB updates, refer to #328
NonCompliantOUs1_1[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("SHARING_OUTSIDE_DOMAIN", OU)
    count(Events) > 0 
    LastEvent := GetLastEvent(Events)
    contains("SHARING_NOT_ALLOWED SHARING_NOT_ALLOWED_BUT_MAY_RECEIVE_FILES INHERIT_FROM_PARENT", LastEvent.NewValue) == false
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.1.1v0.1",
        "Criticality": "Should",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}] {
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("SHARING_OUTSIDE_DOMAIN", TopLevelOU)    
    count(Events) == 0 # If no Events were logged, then the default
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.1.1v0.1",
        "Criticality": "Should",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_1),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
        "RequirementMet": Status,
        "NoSuchEvent": false}] {
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("SHARING_OUTSIDE_DOMAIN", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_1) == 0
}
#--

#
# Baseline GWS.DRIVEDOCS.1.2v0.1
#--
NonCompliantOUs1_2[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("SHARING_OUTSIDE_DOMAIN", OU)
    count(Events) > 0
    LastEvent := GetLastEvent(Events)
    contains("SHARING_NOT_ALLOWED INHERIT_FROM_PARENT", LastEvent.NewValue) == false
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.1.2v0.1",
        "Criticality": "Should",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}] {
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("SHARING_OUTSIDE_DOMAIN", TopLevelOU)
    count(Events) == 0 # If no Events were logged, then the default
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.1.2v0.1",
        "Criticality": "Should",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_2),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_2},
        "RequirementMet": Status,
        "NoSuchEvent": false}] {
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("SHARING_OUTSIDE_DOMAIN", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_2) == 0
}
#--

#
# Baseline GWS.DRIVEDOCS.1.3v0.1
#--
NonCompliantOUs1_3[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("SHARING_OUTSIDE_DOMAIN", OU)
    count(Events) > 0 
    LastEvent := GetLastEvent(Events)
    contains("SHARING_ALLOWED INHERIT_FROM_PARENT", LastEvent.NewValue) == true
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.1.3v0.1",
        "Criticality": "Should",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}] {
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("SHARING_OUTSIDE_DOMAIN", TopLevelOU)
    count(Events) == 0 # If no Events were logged, then the default
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.1.3v0.1",
        "Criticality": "Should",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_3),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_3},
        "RequirementMet": Status,
        "NoSuchEvent": false}] {
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("SHARING_OUTSIDE_DOMAIN", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_3) == 0
}
#--

#
# Baseline GWS.DRIVEDOCS.1.4v0.1
#--
NonCompliantOUs1_4[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS", OU)
    count(Events) > 0 
    LastEvent := GetLastEvent(Events)
    contains("NOT_ALLOWED INHERIT_FROM_PARENT", LastEvent.NewValue) == false
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.1.4v0.1",
        "Criticality": "Shall",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}] {
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS", TopLevelOU)    
    count(Events) == 0 # If no Events were logged, then the default
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.1.4v0.1",
        "Criticality": "Shall",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_4),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_4},
        "RequirementMet": Status,
        "NoSuchEvent": false}] {
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_4) == 0
}
#--

#
# Baseline GWS.DRIVEDOCS.1.5v0.1
#--
NonCompliantOUs1_5[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("PUBLISHING_TO_WEB", OU)
    count(Events) > 0 
    LastEvent := GetLastEvent(Events)
    contains("ALLOWED", LastEvent.NewValue) == true
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.1.5v0.1",
        "Criticality": "Shall",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}] {
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("PUBLISHING_TO_WEB", TopLevelOU)    
    count(Events) == 0 # If no Events were logged, then the default
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.1.5v0.1",
        "Criticality": "Shall",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_5),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_5},
        "RequirementMet": Status,
        "NoSuchEvent": false}] {
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("PUBLISHING_TO_WEB", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_5) == 0
}
#--

#
# Baseline GWS.DRIVEDOCS.1.6v0.1
#--
NonCompliantOUs1_6[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("SHARING_ACCESS_CHECKER_OPTIONS", OU)
    count(Events) > 0 
    LastEvent := GetLastEvent(Events)
    contains("NAMED_PARTIES_ONLY DOMAIN_OR_NAMED_PARTIES INHERIT_FROM_PARENT", LastEvent.NewValue) == false
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.1.6v0.1",
        "Criticality": "Shall",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent":true}] {
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("SHARING_ACCESS_CHECKER_OPTIONS",TopLevelOU)    
    count(Events) == 0 # If no Events were logged, then the default 
    # value is still active
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.1.6v0.1",
        "Criticality": "Shall",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_6),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_6},
        "RequirementMet": Status,
        "NoSuchEvent": false}] {
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("SHARING_ACCESS_CHECKER_OPTIONS", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_6) == 0
}
#--

#
# Baseline GWS.DRIVEDOCS.1.7v0.1
#--
NonCompliantOUs1_7[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS", OU)
    count(Events) > 0 
    LastEvent := GetLastEvent(Events)
    contains("CROSS_DOMAIN_FROM_INTERNAL_ONLY CROSS_DOMAIN_MOVES_BLOCKED INHERIT_FROM_PARENT", LastEvent.NewValue) == false
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.1.7v0.1",
        "Criticality": "Shall",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}] {
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS", TopLevelOU)    
    count(Events) == 0 # If no Events were logged, then the default 
    # value is still active
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.1.7v0.1",
        "Criticality": "Shall",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_7),
        "ActualValue": {"NonComplaintOUs": NonCompliantOUs1_7},
        "RequirementMet": Status,
        "NoSuchEvent": false}] {
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_7) == 0
}
#--

#
# Baseline GWS.DRIVEDOCS.1.8v0.1
#--
NonCompliantOUs1_8[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("DEFAULT_LINK_SHARING_FOR_NEW_DOCS", OU)
    count(Events) > 0 
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "PRIVATE"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.1.8v0.1",
        "Criticality": "Shall",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent":true}] {
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("DEFAULT_LINK_SHARING_FOR_NEW_DOCS",TopLevelOU)    
    count(Events) == 0 # If no Events were logged, then the default 
    # value is still active
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.1.8v0.1",
        "Criticality": "Shall",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_8),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_8},
        "RequirementMet": Status,
        "NoSuchEvent": false}] {
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("DEFAULT_LINK_SHARING_FOR_NEW_DOCS", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_8) == 0
}
#--

################
# GWS.DRIVEDOCS.2 #
################

#
# Baseline GWS.DRIVEDOCS.2.1v0.1
#--
NonCompliantOUs2_1[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("Shared Drive Creation CanCreateSharedDrives", OU)
    count(Events) > 0
    LastEvent := GetLastEvent(Events)
    contains("true", LastEvent.NewValue) == false
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.2.1v0.1",
        "Criticality": "Should",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}] {
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("Shared Drive Creation CanCreateSharedDrives", TopLevelOU)    
    count(Events) == 0 # If no Events were logged, then the default 
    # value is still active
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.2.1v0.1",
        "Criticality": "Should",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs2_1),
        "ActualValue": {"NonComplaintOUs": NonCompliantOUs2_1},
        "RequirementMet": Status,
        "NoSuchEvent": false}] {
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("Shared Drive Creation CanCreateSharedDrives", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_1) == 0
}
#--

#
# Baseline GWS.DRIVEDOCS.2.2v0.1
#--
NonCompliantOUs2_2[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("Shared Drive Creation new_team_drive_admin_only", OU)
    count(Events) > 0 
    LastEvent := GetLastEvent(Events)
    contains("true", LastEvent.NewValue) == false
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.2.2v0.1",
        "Criticality": "Should",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}] {
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("Shared Drive Creation new_team_drive_admin_only", TopLevelOU)    
    count(Events) == 0 # If no Events were logged, then the default 
    # value is still active
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.2.2v0.1",
        "Criticality": "Should",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs2_2),
        "ActualValue": {"NonComplaintOUs": NonCompliantOUs2_2},
        "RequirementMet": Status,
        "NoSuchEvent": false}] {
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("Shared Drive Creation new_team_drive_admin_only", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_2) == 0
}
#--

#
# Baseline GWS.DRIVEDOCS.2.3v0.1
#--
NonCompliantOUs2_3[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("Shared Drive Creation new_team_drive_restricts_cross_domain_access", OU)
    count(Events) > 0 
    LastEvent := GetLastEvent(Events)
    contains("true", LastEvent.NewValue) == false
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.2.3v0.1",
        "Criticality": "Should",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}] {
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("Shared Drive Creation new_team_drive_restricts_cross_domain_access", TopLevelOU)    
    count(Events) == 0 # If no Events were logged, then the default 
    # value is still active
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.2.3v0.1",
        "Criticality": "Should",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs2_3),
        "ActualValue": {"NonComplaintOUs": NonCompliantOUs2_3},
        "RequirementMet": Status,
        "NoSuchEvent": false}] {
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("Shared Drive Creation new_team_drive_restricts_cross_domain_access", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_3) == 0
}
#--

#
# Baseline GWS.DRIVEDOCS.2.4v0.1
#--
NonCompliantOUs2_4[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("Shared Drive Creation new_team_drive_restricts_direct_access", OU)
    count(Events) > 0
    LastEvent := GetLastEvent(Events)
    contains("true", LastEvent.NewValue) == false
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.2.4v0.1",
        "Criticality": "Shall",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}] {
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("Shared Drive Creation new_team_drive_restricts_direct_access", TopLevelOU)    
    count(Events) == 0 # If no Events were logged, then the default 
    # value is still active
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.2.4v0.1",
        "Criticality": "Shall",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs2_4),
        "ActualValue": {"NonComplaintOUs": NonCompliantOUs2_4},
        "RequirementMet": Status,
        "NoSuchEvent": false}] {
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("Shared Drive Creation new_team_drive_restricts_direct_access", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_4) == 0
}
#--

#
# Baseline GWS.DRIVEDOCS.2.5v0.1
#--
NonCompliantOUs2_5[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("Shared Drive Creation new_team_drive_restricts_download", OU)
    count(Events) > 0
    LastEvent := GetLastEvent(Events)
    contains("false", LastEvent.NewValue) == false
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.2.5v0.1",
        "Criticality": "Shall",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}] {
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("Shared Drive Creation new_team_drive_restricts_download", TopLevelOU)
    count(Events) == 0 # If no Events were logged, then the default
    # value is still active
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.2.5v0.1",
        "Criticality": "Shall",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs2_5),
        "ActualValue": {"NonComplaintOUs": NonCompliantOUs2_5},
        "RequirementMet": Status,
        "NoSuchEvent": false}] {
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("Shared Drive Creation new_team_drive_restricts_download", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_5) == 0
}
#--



################
# GWS.DRIVEDOCS.3 
################

#
# Baseline GWS.DRIVEDOCS.3.1v0.1
#--

NoSuchEvent3_1(TopLevelOU) := true if {
    # No such event...
    Events_A := FilterEventsOU("Link Security Update Settings allow_less_secure_link_user_restore", TopLevelOU) 
    count(Events_A) == 0
}

NoSuchEvent3_1(TopLevelOU) := true if {
    # No such event...
    Events := FilterEventsOU("Link Security Update Settings less_secure_link_option", TopLevelOU) 
    count(Events) == 0
}

default NoSuchEvent3_1(_) := false

NonCompliantOUs3_1[OU] {
    OU := OUsWithEvents[_]
    Events_A := FilterEventsOU("Link Security Update Settings allow_less_secure_link_user_restore", OU)
    count(Events_A) > 0  
    LastEvent_A := GetLastEvent(Events_A)
    
    Events_B := FilterEventsOU("Link Security Update Settings less_secure_link_option", OU)
    count(Events_B) > 0  
    LastEvent_B := GetLastEvent(Events_B)

    Conditions := [LastEvent_A.NewValue != "false", LastEvent_B.NewValue != "REMOVE_LESS_SECURE_LINKS"]
    count([Condition | Condition = Conditions[_]; Condition == true]) > 0
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.3.1v0.1",
        "Criticality": "Shall",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}] {
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    NoSuchEvent3_1(TopLevelOU)
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.3.1v0.1",
        "Criticality": "Shall",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs3_1),
        "ActualValue" : {"NonComplaintOUs": NonCompliantOUs3_1},
        "RequirementMet": Status,
        "NoSuchEvent": false}] {
    TopLevelOU := GetTopLevelOU()
    not NoSuchEvent3_1(TopLevelOU)
    Status := count(NonCompliantOUs3_1) == 0
}
#--

################
# GWS.DRIVEDOCS.4#
################

#
# Baseline GWS.DRIVEDOCS.4.1v0.1
#--
NonCompliantOUs4_1[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("ENABLE_DRIVE_APPS", OU)
    count(Events) > 0
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.4.1v0.1",
        "Criticality": "Should",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent":true}] {
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("ENABLE_DRIVE_APPS", TopLevelOU)
    count(Events) == 0 # If no Events were logged, then the default
    # value is still active

}

tests[{ "PolicyId": "GWS.DRIVEDOCS.4.1v0.1",
        "Criticality": "Should",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs4_1),
        "ActualValue": {"NonComplaintOUs": NonCompliantOUs4_1},
        "RequirementMet": Status,
        "NoSuchEvent": false}] {
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("ENABLE_DRIVE_APPS", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_1) == 0
}
#--


################
# GWS.DRIVEDOCS.5 #
################

#
# Baseline GWS.DRIVEDOCS.5.1v0.1
#--
NonCompliantOUs5_1[OU] {
    OU := OUsWithEvents[_]
    Events := FilterEventsOU("ENABLE_DOCS_ADD_ONS", OU)
    count(Events) > 0 
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.5.1v0.1",
        "Criticality": "Shall",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}] {
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("ENABLE_DOCS_ADD_ONS", TopLevelOU)    
    count(Events) == 0 # If no Events were logged, then the default 
    # value is still active

}

tests[{ "PolicyId": "GWS.DRIVEDOCS.5.1v0.1",
        "Criticality": "Shall",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs5_1),
        "ActualValue": {"NonComplaintOUs": NonCompliantOUs5_1},
        "RequirementMet": Status,
        "NoSuchEvent": false}] {
    TopLevelOU := GetTopLevelOU()
    Events := FilterEventsOU("ENABLE_DOCS_ADD_ONS", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_1) == 0
}
#--

################
# GWS.DRIVEDOCS.6 
################

#
# Baseline GWS.DRIVEDOCS.6.1v0.1
#--

default NoSuchEvent6_1(_) := true

NoSuchEvent6_1(TopLevelOU) := false if {
    Events := FilterEventsOU("DriveFsSettingsProto drive_fs_enabled", TopLevelOU)
    count(Events) != 0
}

NoSuchEvent6_1(TopLevelOU) := false if {
    # No such event...
    Events := FilterEventsOU("DriveFsSettingsProto company_owned_only_enabled", TopLevelOU)
    count(Events) != 0
}

NonCompliantOUs6_1[OU] {
    OU := OUsWithEvents[_]
    Events_A := FilterEventsOU("DriveFsSettingsProto drive_fs_enabled", OU)
    count(Events_A) > 0
    LastEvent_A := GetLastEvent(Events_A)
    LastEvent_A.NewValue != "DELETE_APPLICATION_SETTING"

    Events_B := FilterEventsOU("DriveFsSettingsProto company_owned_only_enabled", OU)
    count(Events_B) > 0
    LastEvent_B := GetLastEvent(Events_B)
    LastEvent_B.NewValue != "DELETE_APPLICATION_SETTING"
    
    Conditions := [LastEvent_A.NewValue != "true", LastEvent_B.NewValue != "true"]
    count([Condition | Condition = Conditions[_]; Condition == true]) > 0
    
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.6.1v0.1",
        "Criticality": "Should",
        "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
        "ActualValue": "No relevant event for the top-level OU in the current logs",
        "RequirementMet": DefaultSafe,
        "NoSuchEvent": true}] {
    DefaultSafe := false
    TopLevelOU := GetTopLevelOU()
    NoSuchEvent6_1(TopLevelOU)
}

tests[{ "PolicyId": "GWS.DRIVEDOCS.6.1v0.1",
        "Criticality": "Should",
        "ReportDetails": ReportDetailsOUs(NonCompliantOUs6_1),
        "ActualValue" : {"NonComplaintOUs": NonCompliantOUs6_1},
        "RequirementMet": Status,
        "NoSuchEvent": false}] {
    TopLevelOU := GetTopLevelOU()
    not NoSuchEvent6_1(TopLevelOU)
    Status := count(NonCompliantOUs6_1) == 0
}

#--

################
# GWS.DRIVEDOCS.7 
################

# not implementable: Need a way to see when a rule is created. The fact that a rule is created gets logged but the rule's contents are not. 

#
# Baseline GWS.DRIVEDOCS.7.1v0.1
#--

tests[{ "PolicyId": "GWS.DRIVEDOCS.7.1v0.1",
        "Criticality": "Should/Not-Implemented",
        "ReportDetails": "Currently not able to be tested automatically; please manually check.",
        "ActualValue": "",
        "RequirementMet": false,
        "NoSuchEvent": true}] {
    true

}
#--