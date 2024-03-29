package commoncontrols

import data.utils
import future.keywords

# Note that we need to implement custom FilterEvents and SettingChangeEvents
# rules here, instead of importing the standard ones from utils.

FilterEvents(EventName) := Events if {
    # Many of the events for common controls are structured differently.
    # Instead of having SETTING_NAME as one of the parameters, the event
    # name is set to what would normally be the setting name.
    Events := SettingChangeEvents with data.EventName as EventName
}

FilterEventsOU(EventName, OrgUnit) := FilteredEvents if {
    # Filter the events by both EventName and OrgUnit
    Events := FilterEvents(EventName)
    FilteredEvents := {
        Event | some Event in Events;
        Event.OrgUnit == OrgUnit;
        Event.Group == ""
    }
}

FilterEventsGroup(EventName, Group) := FilteredEvents if {
    # Filter the events by both EventName and Group
    Events := FilterEvents(EventName)
    FilteredEvents := {Event | some Event in Events; Event.Group == Group}
}

SettingChangeEvents contains {
    "Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "NewValue": NewValue,
    "OrgUnit": OrgUnit,
    "Group": Group
}
if {
    some Item in input.commoncontrols_logs.items # For each item...
    some Event in Item.events
    Event.name == data.EventName # Note the data.EventName. This means this
    # rule will only work if called like this:
    # SettingChangeEvents with data.EventName as ExampleEventName

    "NEW_VALUE" in {Parameter.name | some Parameter in Event.parameters}
    NewValue := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "NEW_VALUE"][0]
    OrgUnit := utils.GetEventOu(Event)
    Group := utils.GetEventGroup(Event)
}

SettingChangeEvents contains {
    "Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "NewValue": NewValue,
    "OrgUnit": OrgUnit,
    "Group": Group
}
if {
    some Item in input.commoncontrols_logs.items # For each item...
    some Event in Item.events
    Event.name == data.EventName

    not "NEW_VALUE" in {Parameter.name | some Parameter in Event.parameters}
    # If NEW_VALUE isn't a parameter, then the parameter name will be
    # data.EventName minus the leading CHANGE_ and the trailing S, e.g.,
    # CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS -> ALLOWED_TWO_STEP_VERIFICATION_METHOD
    EventName := trim_suffix(trim_prefix(data.EventName, "CHANGE_"), "S")
    NewValue := [Parameter.value | some Parameter in Event.parameters; Parameter.name == EventName][0]
    OrgUnit := utils.GetEventOu(Event)
    Group := utils.GetEventGroup(Event)
}

LogEvents := utils.GetEvents("commoncontrols_logs")

########################
# GWS.COMMONCONTROLS.1 #
########################

#
# Baseline GWS.COMMONCONTROLS.1.1v0.1
#--

# For 1.1, we need to assert three different things:
# - MFA is allowed
# - MFA is enforced
# - Allowed methods is set to only security key

# Custom NoSuchEvent function needed as we're checking
# three different settings simultaneously. No such event
# if any are missing
NoSuchEvent1_1 := true if {
    Events := FilterEventsOU("ALLOW_STRONG_AUTHENTICATION", utils.TopLevelOU)
    count(Events) == 0
}

NoSuchEvent1_1 := true if {
    Events := FilterEventsOU("ENFORCE_STRONG_AUTHENTICATION", utils.TopLevelOU)
    count(Events) == 0
}

NoSuchEvent1_1 := true if {
    Events := FilterEventsOU("CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS", utils.TopLevelOU)
    count(Events) == 0
}

default NoSuchEvent1_1 := false

GetFriendlyMethods(Value) := "Any" if {
    Value == "ANY"
} else := "Any except verification codes via text, phone call" if {
    Value == "NO_TELEPHONY"
} else := "Only security key and allow security codes without remote access" if {
    Value == "SECURITY_KEY_AND_IP_BOUND_SECURITY_CODE"
} else := "Only security key and allow security codes with remote access" if {
    Value == "SECURITY_KEY_AND_SECURITY_CODE"
} else := Value

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": "Allow users to turn on 2-Step Verification is OFF"
} if {
    some OU in utils.OUsWithEvents
    Events := FilterEventsOU("ALLOW_STRONG_AUTHENTICATION", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
}

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": "2-Step Verification Enforcement is OFF"
} if {
    some OU in utils.OUsWithEvents
    Events := FilterEventsOU("ENFORCE_STRONG_AUTHENTICATION", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
}

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": concat("", ["Allowed methods is set to ", GetFriendlyMethods(LastEvent.NewValue)])
} if {
    some OU in utils.OUsWithEvents
    Events := FilterEventsOU("CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "ONLY_SECURITY_KEY"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

NonCompliantGroups1_1 contains {
    "Name": Group,
    "Value": "Allow users to turn on 2-Step Verification is Off"
} if {
    some Group in utils.GroupsWithEvents
    Events := FilterEventsGroup("ALLOW_STRONG_AUTHENTICATION", Group)
    # Ignore Groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
}

NonCompliantGroups1_1 contains {
    "Name": Group,
    "Value": "2-Step Verification Enforcement is Off"
} if {
    some Group in utils.GroupsWithEvents
    Events := FilterEventsGroup("ENFORCE_STRONG_AUTHENTICATION", Group)
    # Ignore Groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
}

NonCompliantGroups1_1 contains {
    "Name": Group,
    "Value": concat("", ["Allowed methods is set to ", GetFriendlyMethods(LastEvent.NewValue)])
} if {
    some Group in utils.GroupsWithEvents
    Events := FilterEventsGroup("CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS", Group)
    # Ignore Groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "ONLY_SECURITY_KEY"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    NoSuchEvent1_1 == true
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, NonCompliantGroups1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1, "NonCompliantGroups": NonCompliantGroups1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    NoSuchEvent1_1 == false
    Conditions := {count(NonCompliantOUs1_1) == 0, count(NonCompliantGroups1_1) == 0}
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.COMMONCONTROLS.1.2v0.1
#--

NonCompliantOUs1_2 contains {
    "Name": OU,
    "Value": concat("", ["New user enrollment period is set to ", LastEvent.NewValue])
} if {
    some OU in utils.OUsWithEvents
    Events := FilterEventsOU("CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT_PERIOD_DURATION", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "1 week"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

NonCompliantGroups1_2 contains {
    "Name": Group,
    "Value": concat("", ["New user enrollment period is set to ", LastEvent.NewValue])
} if {
    some Group in utils.GroupsWithEvents
    Events := FilterEventsGroup("CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT_PERIOD_DURATION", Group)
    # Ignore groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "1 week"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.1.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEventsOU("CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT_PERIOD_DURATION", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.1.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_2, NonCompliantGroups1_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_2, "NonCompliantGroups": NonCompliantGroups1_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEventsOU("CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT_PERIOD_DURATION", utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs1_2) == 0, count(NonCompliantGroups1_2) == 0}
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.COMMONCONTROLS.1.3v0.1
#--

GetFriendlyValue1_3(Value) := "ON" if {
    Value == "ENABLE_USERS_TO_TRUST_DEVICE"
} else := Value

NonCompliantOUs1_3 contains {
    "Name": OU,
    "Value": concat("", ["Allow user to trust the device is ", GetFriendlyValue1_3(LastEvent.NewValue)])
} if {
    some OU in utils.OUsWithEvents
    Events := FilterEventsOU("CHANGE_TWO_STEP_VERIFICATION_FREQUENCY", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "DISABLE_USERS_TO_TRUST_DEVICE"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

NonCompliantGroups1_3 contains {
    "Name": Group,
    "Value": concat("", ["Allow user to trust the device is ", GetFriendlyValue1_3(LastEvent.NewValue)])
} if {
    some Group in utils.GroupsWithEvents
    Events := FilterEventsGroup("CHANGE_TWO_STEP_VERIFICATION_FREQUENCY", Group)
    # Ignore groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "DISABLE_USERS_TO_TRUST_DEVICE"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.1.3v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEventsOU("CHANGE_TWO_STEP_VERIFICATION_FREQUENCY", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.1.3v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_3, NonCompliantGroups1_3),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_3, "NonCompliantGroups": NonCompliantGroups1_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEventsOU("CHANGE_TWO_STEP_VERIFICATION_FREQUENCY", utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs1_3) == 0, count(NonCompliantGroups1_3) == 0}
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.COMMONCONTROLS.1.4v0.1
#--

NonCompliantOUs1_4 contains {
    "Name": OU,
    "Value": "Allowed methods is set to Any"
} if {
    some OU in utils.OUsWithEvents
    Events := FilterEventsOU("CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "ANY"
}

NonCompliantGroups1_4 contains {
    "Name": Group,
    "Value": "Allowed methods is set to Any"
} if {
    some Group in utils.GroupsWithEvents
    Events := FilterEventsGroup("CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS", Group)
    # Ignore groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "ANY"
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.1.4v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEventsOU("CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.1.4v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_4, NonCompliantGroups1_4),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_4, "NonCompliantGroups": NonCompliantGroups1_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEventsOU("CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS", utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs1_4) == 0, count(NonCompliantGroups1_4) == 0}
    Status := (false in Conditions) == false}

########################
# GWS.COMMONCONTROLS.2 #
########################

#
# Baseline GWS.COMMONCONTROLS.2.1v0.1
#--

# This setting isn't controlled at the OU level, and in this case,
# the logs don't even list an OU for the events. So in this case,
# we just need to ensure the last event is compliant, we don't need
# to check each OU.
tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.2.1v0.1",
    "Criticality": "Should",
    "ReportDetails": concat("", [
        "No relevant event in the current logs. While we are unable ",
        "to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ]), # Custom message instead of utils.NoSuchEventDetails function,
    # as this setting isn't controlled at the OU level
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEvents("TOGGLE_CAA_ENABLEMENT")
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.2.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetailsBoolean(Status),
    "ActualValue": {"TOGGLE_CAA_ENABLEMENT": LastEvent.NewValue},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEvents("TOGGLE_CAA_ENABLEMENT")
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    Status := LastEvent.NewValue == "ENABLED"
}
#--

#
# Baseline GWS.COMMONCONTROLS.2.2v0.1
#--

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.2.2v0.1",
    "Criticality": "May/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}

########################
# GWS.COMMONCONTROLS.3 #
########################

#
# Baseline GWS.COMMONCONTROLS.3.1v0.1
#--

# NOTE: this setting cannot be controlled at the group-level,
# so only a check at the OU-level is implemented here.
NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": "Post-SSO verification is disabled"
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "SsoPolicyProto challenge_selection_behavior", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "PERFORM_CHALLENGE_SELECTION"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.3.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "SsoPolicyProto challenge_selection_behavior", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.3.1v0.1",
    "Criticality": "Shall",
    # Empty list on the next line as this setting can't be set at the group level
    "ReportDetails": utils.ReportDetails(NonCompliantOUs3_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "SsoPolicyProto challenge_selection_behavior", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs3_1) == 0
}
#--

########################
# GWS.COMMONCONTROLS.4 #
########################

#
# Baseline GWS.COMMONCONTROLS.4.1v0.1
#--

# NOTE: this setting cannot be controlled at the group-level,
# so only a check at the OU-level is implemented here.

GoodLimits := {"3600", "14400", "28800", "43200"}

IsGoodLimit(ActualLim) := true if {
    count({GoodLim | some GoodLim in GoodLimits; GoodLim == ActualLim}) > 0
}

IsGoodLimit(ActualLim) := false if {
    count({GoodLim | some GoodLim in GoodLimits; GoodLim == ActualLim}) == 0
}

GetFriendlyValue4_1(Value) := "Session never expires" if {
    Value == "63072000"
} else := "30 days" if {
    Value == "2592000"
} else := "14 days" if {
    Value == "1209600"
} else := "7 days" if {
    Value == "604800"
} else := "24 hours" if {
    Value == "86400"
} else := "20 hours" if {
    Value == "72000"
} else := concat(" ", [Value, "seconds"])

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": concat("", ["Web session duration is set to ", GetFriendlyValue4_1(LastEvent.NewValue)])
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "Session management settings - Session length in seconds", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
    not IsGoodLimit(LastEvent.NewValue)
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Session management settings - Session length in seconds"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs4_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Session management settings - Session length in seconds"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_1) == 0
}
#--

########################
# GWS.COMMONCONTROLS.5 #
########################

# NOTE: these settings cannot be controlled at the group-level,
# so only checks at the OU-level are implemented here.

#
# Baseline GWS.COMMONCONTROLS.5.1v0.1
#--

NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": "Enforce strong password is OFF"
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "Password Management - Enforce strong password", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "on"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.5.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "Password Management - Enforce strong password", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.5.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
} if {
    Events := utils.FilterEventsOU(LogEvents, "Password Management - Enforce strong password", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_1) == 0
}
#--

#
# Baseline GWS.COMMONCONTROLS.5.2v0.1
#--

NonCompliantOUs5_2 contains {
    "Name": OU,
    "Value": concat("", ["Minimum password length is set to ", LastEvent.NewValue])
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "Password Management - Minimum password length", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
    Minimum := to_number(LastEvent.NewValue)
    Minimum < 12
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.5.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "Password Management - Minimum password length", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.5.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "Password Management - Minimum password length", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_2) == 0
}
#--

#
# Baseline GWS.COMMONCONTROLS.5.3v0.1
#--
NonCompliantOUs5_3 contains {
    "Name": OU,
    "Value": "Enforce password policy at next sign-in is OFF"
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "Password Management - Enforce password policy at next login", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "true"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.5.3v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Password Management - Enforce password policy at next login"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.5.3v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_3, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Password Management - Enforce password policy at next login"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_3) == 0
}
#--

#
# Baseline GWS.COMMONCONTROLS.5.4v0.1
#--
NonCompliantOUs5_4 contains {
    "Name": OU,
    "Value": "Allow password reuse is ON"
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "Password Management - Enable password reuse", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.5.4v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "Password Management - Enable password reuse", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.5.4v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_4, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "Password Management - Enable password reuse", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_4) == 0
}
#--

#
# Baseline GWS.COMMONCONTROLS.5.5v0.1
#--
NonCompliantOUs5_5 contains {
    "Name": OU,
    "Value": concat(" ", ["Password reset frequency is", LastEvent.NewValue, "days"])
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "Password Management - Password reset frequency", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "0"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.5.5v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "Password Management - Password reset frequency", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.5.5v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_5, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_5},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "Password Management - Password reset frequency", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs5_5) == 0
}
#--

########################
# GWS.COMMONCONTROLS.6 #
########################

#
# Baseline GWS.COMMONCONTROLS.6.1v0.1
#--
tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.6.1v0.1",
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#
# Baseline GWS.COMMONCONTROLS.6.2v0.1
#--
tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.6.2v0.1",
    "Prerequisites": ["directory/v1/users/list"],
    "Criticality": "Shall",
    "ReportDetails": concat("", [
        concat("", ["The following super admins are configured: ", concat(", ", SuperAdmins)]),
        ". <i>Note: Exceptions are allowed for \"break glass\" super admin accounts, ",
        "though we are not able to account for this automatically.</i>"
    ]),
    "ActualValue": SuperAdmins,
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SuperAdmins := {Admin.primaryEmail | some Admin in input.super_admins}
    Conditions := {count(SuperAdmins) >= 2, count(SuperAdmins) <= 4}
    Status := (false in Conditions) == false
}
#--

########################
# GWS.COMMONCONTROLS.7 #
########################

#
# Baseline GWS.COMMONCONTROLS.7.1v0.1
#--
tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.7.1v0.1",
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

########################
# GWS.COMMONCONTROLS.8 #
########################

#
# Baseline GWS.COMMONCONTROLS.8.1v0.1
#--
NonCompliantOUs8_1 contains {
    "Name": OU,
    "Value": "Allow super admins to recover their account is ON"
} if {
    some OU in utils.OUsWithEvents
    SettingName := "AdminAccountRecoverySettingsProto Enable admin account recovery"
    Events := utils.FilterEventsOU(LogEvents, SettingName, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantGroups8_1 contains {
    "Name": Group,
    "Value": "Allow super admins to recover their account is ON"
} if {
    some Group in utils.GroupsWithEvents
    SettingName := "AdminAccountRecoverySettingsProto Enable admin account recovery"
    Events := utils.FilterEventsGroup(LogEvents, SettingName, Group)
    # Ignore groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.8.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "AdminAccountRecoverySettingsProto Enable admin account recovery"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.8.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs8_1, NonCompliantGroups8_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs8_1, "NonCompliantGroups": NonCompliantGroups8_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
} if {
    SettingName := "AdminAccountRecoverySettingsProto Enable admin account recovery"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs8_1) == 0, count(NonCompliantGroups8_1) == 0}
    Status := (false in Conditions) == false
}
#--

########################
# GWS.COMMONCONTROLS.9 #
########################

#
# Baseline GWS.COMMONCONTROLS.9.1v0.1
#--
tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.9.1v0.1",
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#
# Baseline GWS.COMMONCONTROLS.9.2v0.1
#--
tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.9.2v0.1",
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#########################
# GWS.COMMONCONTROLS.10 #
#########################

#
# Baseline GWS.COMMONCONTROLS.10.1v0.1
#--
tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.10.1v0.1",
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#
# Baseline GWS.COMMONCONTROLS.10.2v0.1
#--

# NOTE: App access cannot be controlled at the group/OU level

# Step 1: Get the set of services that have either an API access allow or API access block event
APIAccessEvents contains {
    "Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "EventName": Event.name,
    "OrgUnit": OrgUnit,
    "ServiceName": ServiceName
}
if {
    some Item in input.commoncontrols_logs.items
    some Event in Item.events
    # Filter for events where event name is either ALLOW_SERVICE_FOR_OAUTH2_ACCESS or DISALLOW...
    true in {
        Event.name == "ALLOW_SERVICE_FOR_OAUTH2_ACCESS",
        Event.name == "DISALLOW_SERVICE_FOR_OAUTH2_ACCESS"
    }
    OrgUnit := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "ORG_UNIT_NAME"][0]
    ServiceName := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "OAUTH2_SERVICE_NAME"][0]
}

# Step 2: Identify services whose most recent event is an allow event
HighRiskBlocked contains Service if {
    # Iterate through all services
    some Service in {Event.ServiceName | some Event in APIAccessEvents}
    # Only look at services that end with _HIGH_RISK. It's confusing
    # how these events appear in the logs. If a user selects "Restricted"
    # and doesn't check "allow not high risk" a pair of events will appear:
    # 1 with the service name (e.g., DRIVE) with ALLOW_SERVICE_FOR_OAUTH2_ACCESS
    # and a second with the DRIVE_HIGH_RISK set to DISALLOW_SERVICE_FOR_OAUTH2_ACCESS.
    # If user user instead selects "Restricted" but doesn't check "allow not high risk",
    # again, a pair of events will appear:
    # 1 with the service name (e.g., DRIVE) with DISALLOW_SERVICE_FOR_OAUTH2_ACCESS
    # and a second with the DRIVE_HIGH_RISK set to ALLOW_SERVICE_FOR_OAUTH2_ACCESS.
    # Really confusing. But, in short, to identify services that are set to "resticted but
    # allow not high risk", we just need to look for events ending with _HIGH_RISK.
    endswith(Service, "_HIGH_RISK")
    # Filter for just that service
    FilteredEvents := {Event | some Event in APIAccessEvents; Event.ServiceName == Service}
    # Get the most recent change
    Event := utils.GetLastEvent(FilteredEvents)
    # If the most recent change is ALLOW, this service is unrestricted
    Event.EventName == "DISALLOW_SERVICE_FOR_OAUTH2_ACCESS"
}

# Step 3: Identify services whose most recent event is an allow event and where
# the high-risk context isn't blocked
UnrestrictedServices10_2 contains Service if {
    # Iterate through all services
    some Service in {Event.ServiceName | some Event in APIAccessEvents}
    # Ignore services that end risk _HIGH_RISK. Those are handled later
    not endswith(Service, "_HIGH_RISK")
    # Filter for just that service
    FilteredEvents := {Event | some Event in APIAccessEvents; Event.ServiceName == Service}
    # Get the most recent change
    Event := utils.GetLastEvent(FilteredEvents)
    # If the most recent change is ALLOW... and the _HIGH_RISK
    # version of the service is not blocked, then the app is unrestricted
    Event.EventName == "ALLOW_SERVICE_FOR_OAUTH2_ACCESS"
    not concat("", [Service, "_HIGH_RISK"]) in HighRiskBlocked
}

ReportDetails10_2(true) := "Requirement met."

ReportDetails10_2(false) := concat("", [
    "The following services allow access: ",
    concat(", ", UnrestrictedServices10_2), "."
])

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.10.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": concat("", [
        "No API Access Allowed/Blocked events in the current logs. ",
        "While we are unable to determine the state from the logs, ",
        "the default setting is non-compliant; manual check recommended."
    ]),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := APIAccessEvents
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.10.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetails10_2(Status),
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := APIAccessEvents
    count(Events) > 0
    Status := count(UnrestrictedServices10_2) == 0
}

# Note that the above logic doesn't filter for OU. As the logic for this setting
# is already fairly complex and GWS doesn't currently allow you to modify this
# setting at the OU level, leaving that as out of scope for now.
#--

#
# Baseline GWS.COMMONCONTROLS.10.3v0.1
#--
# Identify services whose most recent event is an allow event
UnrestrictedServices10_3 contains Service if {
    # Iterate through all services
    some Service in {Event.ServiceName | some Event in APIAccessEvents}
    # Ignore services that end risk _HIGH_RISK. Those are handled later
    not endswith(Service, "_HIGH_RISK")
    # Filter for just that service
    FilteredEvents := {Event | some Event in APIAccessEvents; Event.ServiceName == Service}
    # Get the most recent change
    Event := utils.GetLastEvent(FilteredEvents)
    # If the most recent change is ALLOW..., even if the _HIGH_RISK
    # version of the service is blocked, then the app is unrestricted
    # for the purposes of 11.3, so we don't need to check the high
    # risk part for this one.
    Event.EventName == "ALLOW_SERVICE_FOR_OAUTH2_ACCESS"
}

ReportDetails10_3(true) := "Requirement met."

ReportDetails10_3(false) := concat("", [
    "The following services allow access: ",
    concat(", ", UnrestrictedServices10_3), "."
])

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.10.3v0.1",
    "Criticality": "SHALL",
    "ReportDetails": concat("", [
        "No API Access Allowed/Blocked events in the current logs. ",
        "While we are unable to determine the state from the logs, ",
        "the default setting is non-compliant; manual check recommended."
    ]),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := APIAccessEvents
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.10.3v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetails10_3(Status),
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := APIAccessEvents
    count(Events) > 0
    Status := count(UnrestrictedServices10_3) == 0
}
#--

#
# Baseline GWS.COMMONCONTROLS.10.4v0.1
#--

# NOTE: this setting cannot be set at the group level.

DomainOwnedAppAccessEvents contains {
    "Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "EventName": Event.name,
    "OrgUnit": OrgUnit
}
if {
    some Item in input.commoncontrols_logs.items
    some Event in Item.events
    # Filter for events where event name is either TRUST_DOMAIN_OWNED_OAUTH2_APPS or UNTRUST...
    true in {
        Event.name == "UNTRUST_DOMAIN_OWNED_OAUTH2_APPS",
        Event.name == "TRUST_DOMAIN_OWNED_OAUTH2_APPS"
    }
    OrgUnit := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "ORG_UNIT_NAME"][0]
}

NonCompliantOUs10_4 contains {
    "Name": OU,
    "Value": "Trust internal apps is ON"
} if {
    some OU in utils.OUsWithEvents
    Events := {Event | some Event in DomainOwnedAppAccessEvents; Event.OrgUnit == OU}
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.EventName != "UNTRUST_DOMAIN_OWNED_OAUTH2_APPS"
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.10.4v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := {Event | some Event in DomainOwnedAppAccessEvents; Event.OrgUnit == utils.TopLevelOU}
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.10.4v0.1",
        "Criticality": "Shall",
        "ReportDetails": utils.ReportDetails(NonCompliantOUs10_4, []),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs10_4},
        "RequirementMet": Status,
        "NoSuchEvent": false
}
if {
    Events := {Event | some Event in DomainOwnedAppAccessEvents; Event.OrgUnit == utils.TopLevelOU}
    count(Events) > 0
    Status := count(NonCompliantOUs10_4) == 0
}
#--

#
# Baseline GWS.COMMONCONTROLS.10.5v0.1
#--

# NOTE: this setting cannot be set at the group level.

UnconfiguredAppAccessEvents contains {
    "Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "EventName": Event.name,
    "OrgUnit": OrgUnit
}
if {
    some Item in input.commoncontrols_logs.items
    some Event in Item.events
    # Filter for events where event name is either BLOCK_ALL... or UNBLOCK... or SIGN_IN...
    true in {
        Event.name == "BLOCK_ALL_THIRD_PARTY_API_ACCESS",
        Event.name == "UNBLOCK_ALL_THIRD_PARTY_API_ACCESS",
        Event.name == "SIGN_IN_ONLY_THIRD_PARTY_API_ACCESS"
    }
    OrgUnit := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "ORG_UNIT_NAME"][0]
}

GetFriendlyValue10_5(Value) := "Allow users to access any third-party apps" if {
    Value == "UNBLOCK_ALL_THIRD_PARTY_API_ACCESS"
} else := "Allow users to access third-party apps that only request basic info needed for Sign in with Google." if {
    Value == "SIGN_IN_ONLY_THIRD_PARTY_API_ACCESS"
} else := concat(" ", [Value, "seconds"])

NonCompliantOUs10_5 contains {
    "Name": OU,
    "Value": concat("", ["Unconfigured third-party app access is set to ", GetFriendlyValue10_5(LastEvent.EventName)])
} if {
    some OU in utils.OUsWithEvents
    Events := {Event | some Event in UnconfiguredAppAccessEvents; Event.OrgUnit == OU}
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.EventName != "BLOCK_ALL_THIRD_PARTY_API_ACCESS"
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.10.5v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := {Event | some Event in UnconfiguredAppAccessEvents; Event.OrgUnit == utils.TopLevelOU}
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.10.5v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs10_5, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs10_5},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := {Event | some Event in UnconfiguredAppAccessEvents; Event.OrgUnit == utils.TopLevelOU}
    count(Events) > 0
    Status := count(NonCompliantOUs10_5) == 0
}
#--

#########################
# GWS.COMMONCONTROLS.11 #
#########################

#
# Baseline GWS.COMMONCONTROLS.11.1v0.1
#--

# For 11.1, we need to assert two different things:
# - Users can only allow whitelisted apps
# - Exceptions aren't allowed for internal apps

# Custom NoSuchEvent function needed as we're checking
# two different settings simultaneously.
NoSuchEvent11_1 := true if {
    Events := utils.FilterEventsOU(LogEvents, "Apps Access Setting Allowlist access", utils.TopLevelOU)
    count(Events) == 0
}

NoSuchEvent11_1 := true if {
    Events := utils.FilterEventsOU(LogEvents, "Apps Access Setting allow_all_internal_apps", utils.TopLevelOU)
    count(Events) == 0
}

default NoSuchEvent11_1 := false

NonCompliantOUs11_1 contains {
    "Name": OU,
    "Value": "Users can install and run any app from the Marketplace"
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "Apps Access Setting Allowlist access", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "ALLOW_SPECIFIED"
    LastEvent.NewValue != "ALLOW_NONE"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantGroups11_1 contains {
    "Name": Group,
    "Value": "Users can install and run any app from the Marketplace"
} if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, "Apps Access Setting Allowlist access", Group)
    # Ignore groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "ALLOW_SPECIFIED"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs11_1 contains {
    "Name": OU,
    "Value": "Users can install and run any internal app, even if it's not allowlisted"
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "Apps Access Setting allow_all_internal_apps", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantGroups11_1 contains {
    "Name": Group,
    "Value": "Users can install and run any internal app, even if it's not allowlisted"
} if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, "Apps Access Setting allow_all_internal_apps", Group)
    # Ignore groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.11.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    NoSuchEvent11_1 == true
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.11.1v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs11_1, NonCompliantGroups11_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs11_1, "NonCompliantGroups": NonCompliantGroups11_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    NoSuchEvent11_1 == false
    Conditions := {count(NonCompliantOUs11_1) == 0, count(NonCompliantGroups11_1) == 0}
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.COMMONCONTROLS.11.2v0.1
#--
NonCompliantOUs11_2 contains {
    "Name": OU,
    "Value": "Allow users to manage their access to less secure apps is ON"
} if {
    some OU in utils.OUsWithEvents
    Events := FilterEventsOU("WEAK_PROGRAMMATIC_LOGIN_SETTINGS_CHANGED", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "DENIED"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}
# NOTE: When WEAK_PROGRAMMATIC_LOGIN_SETTINGS_CHANGED for a child OU
# is set to inherit from parent, apparently NO EVENT IS PRODUCED IN
# THE ADMIN LOGS. When you later override the setting, it shows
# "INHERIT_FROM_PARENT" as the "OLD_VALUE", so I'm putting that above
# for completeness, but this appears to be a case where we won't be
# able to detect setting inheritance, as least for now.

NonCompliantGroups11_2 contains {
    "Name": Group,
    "Value": "Allow users to manage their access to less secure apps is ON"
} if {
    some Group in utils.GroupsWithEvents
    Events := FilterEventsGroup("WEAK_PROGRAMMATIC_LOGIN_SETTINGS_CHANGED", Group)
    # Ignore groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "DENIED"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.11.2v0.1",
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEventsOU("WEAK_PROGRAMMATIC_LOGIN_SETTINGS_CHANGED", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.11.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs11_2, NonCompliantGroups11_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs11_2, "NonCompliantGroups": NonCompliantGroups11_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEventsOU("WEAK_PROGRAMMATIC_LOGIN_SETTINGS_CHANGED", utils.TopLevelOU)
    count(Events) > 0
    Conditions := {count(NonCompliantOUs11_2) == 0, count(NonCompliantGroups11_2) == 0}
    Status := (false in Conditions) == false
}
#--

#########################
# GWS.COMMONCONTROLS.12 #
#########################

#### Part 1: detecting service toggle events for OUs/groups *without* an individual admin control
TakeoutServiceEnableEvents contains {
    "Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "NewValue": NewValue,
    "OrgUnit": OrgUnit,
    "Group": Group
}
if {
    some Item in input.commoncontrols_logs.items
    some Event in Item.events
    Event.name == "TOGGLE_SERVICE_ENABLED"

    "SERVICE_NAME" in {Parameter.name | some Parameter in Event.parameters}
    "NEW_VALUE" in {Parameter.name | some Parameter in Event.parameters}

    ServiceName := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "SERVICE_NAME"][0]
    NewValue := [Parameter.value | some Parameter in Event.parameters; Parameter.name == "NEW_VALUE"][0]
    OrgUnit := utils.GetEventOu(Event)
    Group := utils.GetEventGroup(Event)

    ServiceName == "Google Takeout"
}

NonCompliantOUs12_1 contains {
    "Name": OU,
    "Value": "Takeout is enabled for services without an individual admin control"
} if {
    some OU in utils.OUsWithEvents
    Events := {
        Event | some Event in TakeoutServiceEnableEvents;
        Event.OrgUnit == OU;
        Event.Group == ""
    }
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent = utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

NonCompliantGroups12_1 contains {
    "Name": Group,
    "Value": "Takeout is enabled for services without an individual admin control"
} if {
    some Group in utils.GroupsWithEvents
    Events := {
        Event | some Event in TakeoutServiceEnableEvents;
        Event.Group == Group
    }
    # Ignore groups without any events.
    count(Events) > 0
    LastEvent = utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

#### Part 2: detecting services *with* an individual admin control
Apps := {"Blogger", "Google Books", "Google Maps", "Google Pay", "Google Photos", "Google Play",
    "Google Play Console", "Timeline - Location History", "YouTube"}

AppsAllowingTakoutOU contains App if {
    Events := utils.FilterEventsNoOU(LogEvents, "UserTakeoutSettingsProto User Takeout ")
    some App in Apps
    Filtered := {Event | some Event in Events; Event.AppName == App; Event.OrgUnit == data.OrgUnit}
    # Note the data.OrgUnit. This means this
    # rule will only work if called like this:
    # AppsAllowingTakoutOU with data.OrgUnit as ExampleOrgUnit
    LastEvent := utils.GetLastEvent(Filtered)
    LastEvent.NewValue != "Disabled"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

AppsAllowingTakoutGroup contains App if {
    Events := utils.FilterEventsNoOU(LogEvents, "UserTakeoutSettingsProto User Takeout ")
    some App in Apps
    Filtered := {Event | some Event in Events; Event.AppName == App; Event.Group == data.Group}
    # Note the data.Group. This means this
    # rule will only work if called like this:
    # AppsAllowingTakoutGroup with data.Group as ExampleGroup
    LastEvent := utils.GetLastEvent(Filtered)
    LastEvent.NewValue != "Disabled"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs12_1 contains {
    "Name": OU,
    "Value": concat("", [
        "The following apps with individual admin control have Takeout enabled: ",
        concat(", ", EnabledApps)
    ])
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "UserTakeoutSettingsProto User Takeout ", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    EnabledApps := AppsAllowingTakoutOU with data.OrgUnit as OU
    count(EnabledApps) > 0
}

NonCompliantGroups12_1 contains {
    "Name": Group,
    "Value": concat("", [
        "The following apps with individual admin control have Takeout enabled: ",
        concat(", ", EnabledApps)
    ])
} if {
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, "UserTakeoutSettingsProto User Takeout ", Group)
    # Ignore groups without any events.
    count(Events) > 0
    EnabledApps := AppsAllowingTakoutGroup with data.Group as Group
    count(EnabledApps) > 0
}

#
# Baseline GWS.COMMONCONTROLS.12.1v0.1
#--

NoSuchEvent12_1 := true if {
    Events := utils.FilterEventsOU(LogEvents, "UserTakeoutSettingsProto User Takeout ", utils.TopLevelOU)
    count(Events) == 0
}

NoSuchEvent12_1 := true if {
    Events := {Event | some Event in TakeoutServiceEnableEvents; Event.OrgUnit == utils.TopLevelOU}
    count(Events) == 0
}

default NoSuchEvent12_1 := false

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.12.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    NoSuchEvent12_1 == true
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.12.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs12_1, NonCompliantGroups12_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs12_1, "NonCompliantGroups": NonCompliantGroups12_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    NoSuchEvent12_1 == false
    Conditions := {count(NonCompliantOUs12_1) == 0, count(NonCompliantGroups12_1) == 0}
    Status := (false in Conditions) == false
}
#--

#########################
# GWS.COMMONCONTROLS.13 #
#########################

#
# Baseline GWS.COMMONCONTROLS.13.1v0.1
#--
tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.13.1v0.1",
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": concat("", [
        "Results for GWS.COMMONCONTROLS.13 are listed in the ",
        "<a href='../IndividualReports/RulesReport.html'>Rules Report</a>."
    ]),
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#########################
# GWS.COMMONCONTROLS.14 #
#########################

#
# Baseline GWS.COMMONCONTROLS.14.1v0.1
#--
tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.14.1v0.1",
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#
# Baseline GWS.COMMONCONTROLS.14.2v0.1
#--
tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.14.2v0.1",
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#########################
# GWS.COMMONCONTROLS.15 #
#########################

#
# Baseline GWS.COMMONCONTROLS.15.1v0.1
#--
tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.15.1v0.1",
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#
# Baseline GWS.COMMONCONTROLS.15.2v0.1
#--

# NOTE: This setting cannot be controlled at the group level

NonCompliantOUs15_2 contains {
    "Name": OU,
    "Value": "Supplemental data storage is set to Russian Federation"
} if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "CHANGE_DATA_LOCALIZATION_FOR_RUSSIA", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.15.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := utils.FilterEventsOU(LogEvents, "CHANGE_DATA_LOCALIZATION_FOR_RUSSIA", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.COMMONCONTROLS.15.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs15_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs15_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "CHANGE_DATA_LOCALIZATION_FOR_RUSSIA", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs15_2) == 0
}
#--
