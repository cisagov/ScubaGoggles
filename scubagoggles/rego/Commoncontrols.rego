package commoncontrols

import future.keywords
import data.utils
import data.utils.PolicyApiInUse

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

ToggleServiceEvents contains {
    "Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "ServiceName": ServiceName,
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
}

LogEvents := utils.GetEvents("commoncontrols_logs")

########################
# GWS.COMMONCONTROLS.1 #
########################

#
# Baseline GWS.COMMONCONTROLS.1.1
#--

CommonControlsId1_1 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.1.1")

# For 1.1, we need to assert three different things:
# - MFA is allowed
# - MFA is enforced
# - Allowed methods is set to only security key

# Custom NoSuchEvent function needed as we're checking
# three different settings simultaneously. No such event
# if any are missing
default NoSuchEvent1_1 := false

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

Check1_1_OK if {
    not PolicyApiInUse
    not NoSuchEvent1_1
}

Check1_1_OK if {PolicyApiInUse}

GetFriendlyMethods(Value) := "Any" if {
    Value in {"ALL", "ANY"}
} else := "Any except verification codes via text, phone call" if {
    Value == "NO_TELEPHONY"
} else := "Only security key and allow security codes without remote access" if {
    Value in {"PASSKEY_PLUS_IP_BOUND_SECURITY_CODE", "SECURITY_KEY_AND_IP_BOUND_SECURITY_CODE"}
} else := "Only security key and allow security codes with remote access" if {
    Value in {"PASSKEY_PLUS_SECURITY_CODE", "SECURITY_KEY_AND_SECURITY_CODE"}
} else := Value

NonComplianceMessage1_1a := "Users cannot enable 2-step verification (2SV)."

NonComplianceMessage1_1b(value) := sprintf("Allowed methods is set to %s",
                                          [value])

NonComplianceMessage1_1c := "2-step verification (2SV) is not enforced."

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": "Allow users to turn on 2-Step Verification is OFF"
}
if {
    not PolicyApiInUse
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
}
if {
    not PolicyApiInUse
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
    "Value": NonComplianceMessage1_1b(GetFriendlyMethods(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
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
}
if {
    not PolicyApiInUse
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
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := FilterEventsGroup("ENFORCE_STRONG_AUTHENTICATION", Group)
    # Ignore Groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
}

NonCompliantGroups1_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage1_1b(GetFriendlyMethods(LastEvent.NewValue))
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := FilterEventsGroup("CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS", Group)
    # Ignore Groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "ONLY_SECURITY_KEY"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

# There are 3 items to check for this baseline.  First, users must be allowed to
# enroll in 2SV.  If they have been enrolled, then the passkey (aka security
# key) is the only allowed 2SV method.  If the method is also OK, 2SV
# enforcement must be enabled, and this is determined by ensuring the date
# of enforcement is in the past (before today).

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1a
}
if {
    some OU, settings in input.policies
    enable2SV := settings.security_two_step_verification_enrollment.allowEnrollment
    not enable2SV
}

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1b(GetFriendlyMethods(enforceMethod))
}
if {
    some OU, settings in input.policies
    enable2SV := settings.security_two_step_verification_enrollment.allowEnrollment
    enable2SV
    enforceMethod := settings.security_two_step_verification_enforcement_factor.allowedSignInFactorSet
    enforceMethod != "PASSKEY_ONLY"
}

NonCompliantOUs1_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_1c
}
if {
    today := time.now_ns()
    RFC3339 := "2006-01-02T15:04:05Z07:00"
    some OU, settings in input.policies
    enable2SV := settings.security_two_step_verification_enrollment.allowEnrollment
    enable2SV
    enforceMethod := settings.security_two_step_verification_enforcement_factor.allowedSignInFactorSet
    enforceMethod == "PASSKEY_ONLY"
    enforce2SV := settings.security_two_step_verification_enforcement.enforcedFrom
    enforceValue := time.parse_ns(RFC3339, enforce2SV)
    enforceValue > today
}

tests contains {
    "PolicyId": CommonControlsId1_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check1_1_OK
}

tests contains {
    "PolicyId": CommonControlsId1_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_1, NonCompliantGroups1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1, "NonCompliantGroups": NonCompliantGroups1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check1_1_OK
    Conditions := {count(NonCompliantOUs1_1) == 0, count(NonCompliantGroups1_1) == 0}
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.COMMONCONTROLS.1.2
#--

CommonControlsId1_2 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.1.2")

LogMessage1_2 := "CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT_PERIOD_DURATION"

Check1_2_OK if {
    not PolicyApiInUse
    events := FilterEventsOU(LogMessage1_2, utils.TopLevelOU)
    count(events) > 0
}

Check1_2_OK if {PolicyApiInUse}

NonComplianceMessage1_2(value, expected) := sprintf("New user enrollment period (%s) %s (%s)",
                                                    [utils.GetFriendlyDuration(value),
                                                    "doesn't match expected",
                                                    utils.GetFriendlyDuration(expected)])

NonCompliantOUs1_2 contains {
    "Name": OU,
    "Value": concat("", ["New user enrollment period is set to ", LastEvent.NewValue])
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := FilterEventsOU(LogMessage1_2, OU)
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
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := FilterEventsGroup(LogMessage1_2, Group)
    # Ignore groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "1 week"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

NonCompliantOUs1_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_2(enrollSeconds, expectedPeriod)
}
if {
    expectedPeriod := utils.DurationToSeconds("7d")
    some OU, settings in input.policies
    enrollPeriod := settings.security_two_step_verification_grace_period.enrollmentGracePeriod
    enrollSeconds := utils.DurationToSeconds(enrollPeriod)
    enrollSeconds != expectedPeriod
}

tests contains {
    "PolicyId": CommonControlsId1_2,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check1_2_OK
}

tests contains {
    "PolicyId": CommonControlsId1_2,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_2, NonCompliantGroups1_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_2, "NonCompliantGroups": NonCompliantGroups1_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check1_2_OK
    Conditions := {count(NonCompliantOUs1_2) == 0, count(NonCompliantGroups1_2) == 0}
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.COMMONCONTROLS.1.3
#--

CommonControlsId1_3 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.1.3")

LogMessage1_3 := "CHANGE_TWO_STEP_VERIFICATION_FREQUENCY"

Check1_3_OK if {
    not PolicyApiInUse
    events := FilterEventsOU(LogMessage1_3, utils.TopLevelOU)
    count(events) > 0
}

Check1_3_OK if {PolicyApiInUse}

NonComplianceMessage1_3 := "User is allowed to trust device."

GetFriendlyValue1_3(Value) := "ON" if {
    Value == "ENABLE_USERS_TO_TRUST_DEVICE"
} else := Value

NonCompliantOUs1_3 contains {
    "Name": OU,
    "Value": concat("", ["Allow user to trust the device is ", GetFriendlyValue1_3(LastEvent.NewValue)])
}
if {
    not PolicyApiInUse
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
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := FilterEventsGroup(LogMessage1_3, Group)
    # Ignore groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "DISABLE_USERS_TO_TRUST_DEVICE"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

NonCompliantOUs1_3 contains {
    "Name": OU,
    "Value": NonComplianceMessage1_3
}
if {
    some OU, settings in input.policies
    trustDevice := settings.security_two_step_verification_device_trust.allowTrustingDevice
    trustDevice
}

tests contains {
    "PolicyId": CommonControlsId1_3,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check1_3_OK
}

tests contains {
    "PolicyId": CommonControlsId1_3,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs1_3, NonCompliantGroups1_3),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_3, "NonCompliantGroups": NonCompliantGroups1_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check1_3_OK
    Conditions := {count(NonCompliantOUs1_3) == 0, count(NonCompliantGroups1_3) == 0}
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.COMMONCONTROLS.1.4
#--

CommonControlsId1_4 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.1.4")

NonCompliantOUs1_4 contains {
    "Name": OU,
    "Value": "Allowed methods is set to Any"
}
if {
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
}
if {
    some Group in utils.GroupsWithEvents
    Events := FilterEventsGroup("CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS", Group)
    # Ignore groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "ANY"
}

tests contains {
    "PolicyId": CommonControlsId1_4,
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
    "PolicyId": CommonControlsId1_4,
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
# Baseline GWS.COMMONCONTROLS.2.1
#--

CommonControlsId2_1 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.2.1")

# This setting isn't controlled at the OU level, and in this case,
# the logs don't even list an OU for the events. So in this case,
# we just need to ensure the last event is compliant, we don't need
# to check each OU.
tests contains {
    "PolicyId": CommonControlsId2_1,
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
    "PolicyId": CommonControlsId2_1,
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

########################
# GWS.COMMONCONTROLS.3 #
########################

#
# Baseline GWS.COMMONCONTROLS.3.1
#--

CommonControlsId3_1 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.3.1")

LogMessage3_1 := "SsoPolicyProto challenge_selection_behavior"

Check3_1_OK if {
    events := utils.FilterEventsOU(LogEvents, LogMessage3_1, utils.TopLevelOU)
    count(events) > 0
}

NonComplianceMessage3_1 := "Post Single Sign-on (SSO) verification is disabled."

# NOTE: this setting cannot be controlled at the group-level,
# so only a check at the OU-level is implemented here.
NonCompliantOUs3_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage3_1
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage3_1, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "PERFORM_CHALLENGE_SELECTION"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": CommonControlsId3_1,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    not Check3_1_OK
}

tests contains {
    "PolicyId": CommonControlsId3_1,
    "Criticality": "Should",
    # Empty list on the next line as this setting can't be set at the group level
    "ReportDetails": utils.ReportDetails(NonCompliantOUs3_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check3_1_OK
    Status := count(NonCompliantOUs3_1) == 0
}
#--

#
# Baseline GWS.COMMONCONTROLS.3.2
#--

CommonControlsId3_2 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.3.2")

# TODO replace the following placeholder with actual implementation
# SsoPolicyProto sso_profile_challenge_selection_behavior appears to the appropriate log event
tests contains {
    "PolicyId": CommonControlsId3_2,
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

########################
# GWS.COMMONCONTROLS.4 #
########################

#
# Baseline GWS.COMMONCONTROLS.4.1
#--

CommonControlsId4_1 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.4.1")

# NOTE: this setting cannot be controlled at the group-level,
# so only a check at the OU-level is implemented here.

GoodLimits := {"3600", "14400", "28800", "43200"}

LogMessage4_1 := "Session management settings - Session length in seconds"

Check4_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage4_1, utils.TopLevelOU)
    count(events) > 0
}

Check4_1_OK if {PolicyApiInUse}

IsGoodLimit(ActualLim) := true if {
    count({GoodLim | some GoodLim in GoodLimits; GoodLim == ActualLim}) > 0
}

IsGoodLimit(ActualLim) := false if {
    count({GoodLim | some GoodLim in GoodLimits; GoodLim == ActualLim}) == 0
}

NonComplianceMessage4_1(Value) := sprintf("Web session duration: %s",
                                          [Value])

GetFriendlyValue4_1(Value) := "Session never expires" if {
    Value == 63072000
} else := utils.GetFriendlyDuration(Value)

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage4_1(GetFriendlyValue4_1(to_number(LastEvent.NewValue)))
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage4_1, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
    not IsGoodLimit(LastEvent.NewValue)
}

NonCompliantOUs4_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage4_1(GetFriendlyValue4_1(durationSeconds))
}
if {
    # This is the requirement limit for session duration:
    webSessionMax := utils.DurationToSeconds("12h")
    some OU, settings in input.policies
    duration := settings.security_session_controls.webSessionDuration
    durationSeconds := utils.DurationToSeconds(duration)
    durationSeconds > webSessionMax
}

tests contains {
    "PolicyId": CommonControlsId4_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check4_1_OK
}

tests contains {
    "PolicyId": CommonControlsId4_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs4_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check4_1_OK
    Status := count(NonCompliantOUs4_1) == 0
}
#--

########################
# GWS.COMMONCONTROLS.5 #
########################

# NOTE: these settings cannot be controlled at the group-level,
# so only checks at the OU-level are implemented here.

#
# Baseline GWS.COMMONCONTROLS.5.1
#--

CommonControlsId5_1 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.5.1")
LogMessage5_1 := "Password Management - Enforce strong password"
PasswordStrength := "STRONG"

Check5_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage5_1, utils.TopLevelOU)
    count(events) > 0
}

Check5_1_OK if {PolicyApiInUse}

NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": "Enforce strong password is OFF"
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage5_1, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "on"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs5_1 contains {
    "Name": OU,
    "Value": sprintf("Password strength is %s, not %s",
                     [CurrentStrength, PasswordStrength])
}
if {
    some OU, settings in input.policies
    CurrentStrength := upper(settings.security_password.allowedStrength)
    CurrentStrength != PasswordStrength
}

tests contains {
    "PolicyId": CommonControlsId5_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check5_1_OK
}

tests contains {
    "PolicyId": CommonControlsId5_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check5_1_OK
    Status := count(NonCompliantOUs5_1) == 0
}
#--

#
# Baseline GWS.COMMONCONTROLS.5.2
#--

CommonControlsId5_2 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.5.2")

LogMessageMinPassword := "Password Management - Minimum password length"

MinimumPasswordLength := 12

Check5_2_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessageMinPassword, utils.TopLevelOU)
    count(events) > 0
}

Check5_2_OK if {PolicyApiInUse}

FormatMessage5_2 := "Minimum password length: %d, less than %d"
NonComplianceMessage5_2(Value) := sprintf(FormatMessage5_2,
                                          [Value, MinimumPasswordLength])

NonCompliantOUs5_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_2(Minimum)
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessageMinPassword, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
    Minimum := to_number(LastEvent.NewValue)
    Minimum < MinimumPasswordLength
}

NonCompliantOUs5_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_2(CurrentLength)
}
if {
    some OU, settings in input.policies
    CurrentLength := settings.security_password.minimumLength
    CurrentLength < MinimumPasswordLength
}

tests contains {
    "PolicyId": CommonControlsId5_2,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check5_2_OK
}

tests contains {
    "PolicyId": CommonControlsId5_2,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_2, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check5_2_OK
    Status := count(NonCompliantOUs5_2) == 0
}
#--

#
# Baseline GWS.COMMONCONTROLS.5.3
#--

CommonControlsId5_3 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.5.3")

SuggestedPasswordLength := 15

Check5_3_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessageMinPassword, utils.TopLevelOU)
    count(events) > 0
}

Check5_3_OK if {PolicyApiInUse}

FormatMessage5_3 := "Minimum password length: %d, recommended is at least %d"
NonComplianceMessage5_3(Value) := sprintf(FormatMessage5_3,
                                          [Value, SuggestedPasswordLength])

NonCompliantOUs5_3 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_3(Minimum)
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessageMinPassword, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
    Minimum := to_number(LastEvent.NewValue)
    Minimum < SuggestedPasswordLength
}

NonCompliantOUs5_3 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_3(CurrentLength)
}
if {
    some OU, settings in input.policies
    CurrentLength := settings.security_password.minimumLength
    CurrentLength < SuggestedPasswordLength
}

tests contains {
    "PolicyId": CommonControlsId5_3,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check5_3_OK
}

tests contains {
    "PolicyId": CommonControlsId5_3,
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_3, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check5_3_OK
    Status := count(NonCompliantOUs5_3) == 0
}
#--

#
# Baseline GWS.COMMONCONTROLS.5.4
#--

CommonControlsId5_4 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.5.4")
LogMessage5_4 := "Password Management - Enforce password policy at next login"
NonComplianceMessage5_4 := "Enforce password policy at next sign-in is OFF"

Check5_4_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage5_4, utils.TopLevelOU)
    count(events) > 0
}

Check5_4_OK if {PolicyApiInUse}

NonCompliantOUs5_4 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_4
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage5_4, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "true"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs5_4 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_4
}
if {
    some OU, settings in input.policies
    settings.security_password.enforceRequirementsAtLogin != true
}

tests contains {
    "PolicyId": CommonControlsId5_4,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check5_4_OK
}

tests contains {
    "PolicyId": CommonControlsId5_4,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_4, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check5_4_OK
    Status := count(NonCompliantOUs5_4) == 0
}
#--

#
# Baseline GWS.COMMONCONTROLS.5.5
#--

CommonControlsId5_5 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.5.5")
LogMessage5_5 := "Password Management - Enable password reuse"
NonComplianceMessage5_5 := "Allow password reuse is ON"

Check5_5_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage5_5, utils.TopLevelOU)
    count(events) > 0
}

Check5_5_OK if {PolicyApiInUse}

NonCompliantOUs5_5 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_5
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage5_5, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs5_5 contains {
    "Name": OU,
    "Value": NonComplianceMessage5_5
}
if {
    some OU, settings in input.policies
    settings.security_password.allowReuse == true
}

tests contains {
    "PolicyId": CommonControlsId5_5,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check5_5_OK
}

tests contains {
    "PolicyId": CommonControlsId5_5,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_5, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_5},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check5_5_OK
    Status := count(NonCompliantOUs5_5) == 0
}
#--

#
# Baseline GWS.COMMONCONTROLS.5.6
#--

CommonControlsId5_6 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.5.6")
LogMessage5_6 := "Password Management - Password reset frequency"

Check5_6_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage5_6, utils.TopLevelOU)
    count(events) > 0
}

Check5_6_OK if {PolicyApiInUse}

NonCompliantOUs5_6 contains {
    "Name": OU,
    "Value": concat(" ", ["Password reset frequency is", LastEvent.NewValue, "days"])
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage5_6, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "0"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs5_6 contains {
    "Name": OU,
    "Value": sprintf("Password reset frequency is %s", [passwordExpiration])
}
if {
    some OU, settings in input.policies
    passwordExpiration := settings.security_password.expirationDuration
    expirationValue := utils.DurationToSeconds(passwordExpiration)
    expirationValue != 0
}

tests contains {
    "PolicyId": CommonControlsId5_6,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check5_6_OK
}

tests contains {
    "PolicyId": CommonControlsId5_6,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs5_6, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs5_6},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check5_6_OK
    Status := count(NonCompliantOUs5_6) == 0
}
#--

########################
# GWS.COMMONCONTROLS.6 #
########################

#
# Baseline GWS.COMMONCONTROLS.6.1
#--

CommonControlsId6_1 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.6.1")

tests contains {
    "PolicyId": CommonControlsId6_1,
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#
# Baseline GWS.COMMONCONTROLS.6.2
#--

CommonControlsId6_2 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.6.2")

tests contains {
    "PolicyId": CommonControlsId6_2,
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
    Conditions := {count(SuperAdmins) >= 2, count(SuperAdmins) <= 8}
    Status := (false in Conditions) == false
}
#--

########################
# GWS.COMMONCONTROLS.7 #
########################

#
# Baseline GWS.COMMONCONTROLS.7.1
#--

CommonControlsId7_1 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.7.1")

tests contains {
    "PolicyId": CommonControlsId7_1,
    "Criticality": "Should/Not-Implemented",
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
# Baseline GWS.COMMONCONTROLS.8.1
#--

CommonControlsId8_1 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.8.1")
LogMessage8_1 := "AdminAccountRecoverySettingsProto Enable admin account recovery"
NonComplianceMessage8_1 := "Allow super admins to recover their account is ON"

Check8_1_OK if {
    not PolicyApiInUse
    events := utils.FilterEventsOU(LogEvents, LogMessage8_1, utils.TopLevelOU)
    count(events) > 0
}

Check8_1_OK if {PolicyApiInUse}

NonCompliantOUs8_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage8_1
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    SettingName := LogMessage8_1
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
    "Value": NonComplianceMessage8_1
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    SettingName := LogMessage8_1
    Events := utils.FilterEventsGroup(LogEvents, SettingName, Group)
    # Ignore groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs8_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage8_1
}
if {
    some OU, settings in input.policies
    settings.security_super_admin_account_recovery.enableAccountRecovery == true
}

tests contains {
    "PolicyId": CommonControlsId8_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check8_1_OK
}

tests contains {
    "PolicyId": CommonControlsId8_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs8_1, NonCompliantGroups8_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs8_1, "NonCompliantGroups": NonCompliantGroups8_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check8_1_OK
    Conditions := {count(NonCompliantOUs8_1) == 0, count(NonCompliantGroups8_1) == 0}
    Status := (false in Conditions) == false
}
#--

########################
# GWS.COMMONCONTROLS.9 #
########################

#
# Baseline GWS.COMMONCONTROLS.9.1
#--

CommonControlsId9_1 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.9.1")

tests contains {
    "PolicyId": CommonControlsId9_1,
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#
# Baseline GWS.COMMONCONTROLS.9.2
#--

CommonControlsId9_2 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.9.2")

tests contains {
    "PolicyId": CommonControlsId9_2,
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
# Baseline GWS.COMMONCONTROLS.10.1
#--

CommonControlsId10_1 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.10.1")

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
UnrestrictedServices10_1 contains Service if {
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

ReportDetails10_1(true) := "Requirement met."

ReportDetails10_1(false) := concat("", [
    "The following services allow access: ",
    concat(", ", UnrestrictedServices10_1), "."
])

tests contains {
    "PolicyId": CommonControlsId10_1,
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
    "PolicyId": CommonControlsId10_1,
    "Criticality": "Shall",
    "ReportDetails": ReportDetails10_1(Status),
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := APIAccessEvents
    count(Events) > 0
    Status := count(UnrestrictedServices10_1) == 0
}

# Note that the above logic doesn't filter for OU. As the logic for this setting
# is already fairly complex and GWS doesn't currently allow you to modify this
# setting at the OU level, leaving that as out of scope for now.
#--

#
# Baseline GWS.COMMONCONTROLS.10.2
#--

CommonControlsId10_2 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.10.2")

# Identify services whose most recent event is an allow event
UnrestrictedServices10_2 contains Service if {
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

ReportDetails10_2(true) := "Requirement met."

ReportDetails10_2(false) := concat("", [
    "The following services allow access: ",
    concat(", ", UnrestrictedServices10_2), "."
])

tests contains {
    "PolicyId": CommonControlsId10_2,
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
    "PolicyId": CommonControlsId10_2,
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
#--

#
# Baseline GWS.COMMONCONTROLS.10.3
#--

CommonControlsId10_3 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.10.3")

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

NonCompliantOUs10_3 contains {
    "Name": OU,
    "Value": "Trust internal apps is ON"
}
if {
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
    "PolicyId": CommonControlsId10_3,
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
    "PolicyId": CommonControlsId10_3,
        "Criticality": "Shall",
        "ReportDetails": utils.ReportDetails(NonCompliantOUs10_3, []),
        "ActualValue": {"NonCompliantOUs": NonCompliantOUs10_3},
        "RequirementMet": Status,
        "NoSuchEvent": false
}
if {
    Events := {Event | some Event in DomainOwnedAppAccessEvents; Event.OrgUnit == utils.TopLevelOU}
    count(Events) > 0
    Status := count(NonCompliantOUs10_3) == 0
}
#--

#
# Baseline GWS.COMMONCONTROLS.10.4
#--

CommonControlsId10_4 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.10.4")

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

GetFriendlyValue10_4(Value) := "Allow users to access any third-party apps" if {
    Value == "UNBLOCK_ALL_THIRD_PARTY_API_ACCESS"
} else := "Allow users to access third-party apps that only request basic info needed for Sign in with Google." if {
    Value == "SIGN_IN_ONLY_THIRD_PARTY_API_ACCESS"
} else := concat(" ", [Value, "seconds"])

NonCompliantOUs10_4 contains {
    "Name": OU,
    "Value": concat("", ["Unconfigured third-party app access is set to ", GetFriendlyValue10_4(LastEvent.EventName)])
}
if {
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
    "PolicyId": CommonControlsId10_4,
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
    "PolicyId": CommonControlsId10_4,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs10_4, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs10_4},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := {Event | some Event in UnconfiguredAppAccessEvents; Event.OrgUnit == utils.TopLevelOU}
    count(Events) > 0
    Status := count(NonCompliantOUs10_4) == 0
}
#--

#
# Baseline GWS.COMMONCONTROLS.10.5
#--

CommonControlsId10_5 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.10.5")

EventName10_5 := "WEAK_PROGRAMMATIC_LOGIN_SETTINGS_CHANGED"

Check10_5_OK if {
    not PolicyApiInUse
    events := FilterEventsOU(EventName10_5, utils.TopLevelOU)
    count(events) > 0
}

Check10_5_OK if {PolicyApiInUse}

NonComplianceMessage10_5 := "Users are allowed to manage access to less secure apps."

NonCompliantOUs10_5 contains {
    "Name": OU,
    "Value": NonComplianceMessage10_5
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := FilterEventsOU(EventName10_5, OU)
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

NonCompliantGroups10_5 contains {
    "Name": Group,
    "Value": NonComplianceMessage10_5
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := FilterEventsGroup(EventName10_5, Group)
    # Ignore groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "DENIED"
    LastEvent.NewValue != "INHERIT_FROM_PARENT"
}

NonCompliantOUs10_5 contains {
    "Name": OU,
    "Value": NonComplianceMessage10_5
}
if {
    some OU, settings in input.policies
    lessSecure := settings.security_less_secure_apps.allowLessSecureApps
    lessSecure != false
}

tests contains {
    "PolicyId": CommonControlsId10_5,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := true
    not Check10_5_OK
}

tests contains {
    "PolicyId": CommonControlsId10_5,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs10_5, NonCompliantGroups10_5),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs10_5, "NonCompliantGroups": NonCompliantGroups10_5},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check10_5_OK
    Conditions := {count(NonCompliantOUs10_5) == 0, count(NonCompliantGroups10_5) == 0}
    Status := (false in Conditions) == false
}
#--

#########################
# GWS.COMMONCONTROLS.11 #
#########################

#
# Baseline GWS.COMMONCONTROLS.11.1
#--

CommonControlsId11_1 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.11.1")

LogMessage11_1_A := "Apps Access Setting Allowlist access"
LogMessage11_1_B := "Apps Access Setting allow_all_internal_apps"

NonCompliancePrefix11_1 := "Users can install and run any"
NonComplianceMessage11_1(anyApp) := sprintf("%s app from the Marketplace.",
                                            [NonCompliancePrefix11_1]) if {
    anyApp
} else := sprintf("%s internal app, even if it's not allowlisted.",
                  [NonCompliancePrefix11_1])

# For 11.1, we need to assert two different things:
# - Users can only allow whitelisted apps
# - Exceptions aren't allowed for internal apps

# Custom NoSuchEvent function needed as we're checking
# two different settings simultaneously.

default NoSuchEvent11_1 := false

NoSuchEvent11_1 := true if {
    Events := utils.FilterEventsOU(LogEvents, LogMessage11_1_A, utils.TopLevelOU)
    count(Events) == 0
}

NoSuchEvent11_1 := true if {
    Events := utils.FilterEventsOU(LogEvents, LogMessage11_1_B, utils.TopLevelOU)
    count(Events) == 0
}

Check11_1_OK if {
    not PolicyApiInUse
    not NoSuchEvent11_1
}

Check11_1_OK if {PolicyApiInUse}

NonCompliantOUs11_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage11_1(true)
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage11_1_A, OU)
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
    "Value": NonComplianceMessage11_1(true)
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage11_1_A, Group)
    # Ignore groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "ALLOW_SPECIFIED"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs11_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage11_1(false)
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage11_1_B, OU)
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
    "Value": NonComplianceMessage11_1(false)
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage11_1_B, Group)
    # Ignore groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantOUs11_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage11_1(true)
}
if {
    some OU, settings in input.policies
    access := settings.workspace_marketplace_apps_access_options.accessLevel
    not access in {"ALLOW_LISTED_APPS", "ALLOW_NONE"}
}

NonCompliantOUs11_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage11_1(false)
}
if {
    some OU, settings in input.policies
    access := settings.workspace_marketplace_apps_access_options.accessLevel
    allowInternal := settings.workspace_marketplace_apps_access_options.allowAllInternalApps
    access == "ALLOW_LISTED_APPS"
    allowInternal != false
}

tests contains {
    "PolicyId": CommonControlsId11_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check11_1_OK
}

tests contains {
    "PolicyId": CommonControlsId11_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs11_1, NonCompliantGroups11_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs11_1, "NonCompliantGroups": NonCompliantGroups11_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check11_1_OK
    Conditions := {count(NonCompliantOUs11_1) == 0, count(NonCompliantGroups11_1) == 0}
    Status := (false in Conditions) == false
}
#--

#########################
# GWS.COMMONCONTROLS.12 #
#########################

LogMessage12_1 := "UserTakeoutSettingsProto User Takeout "

Msg12_1 := "The following apps with individual admin control have Takeout enabled: %s"
NonComplianceMessage12_1(EnabledApps) := sprintf(Msg12_1,
                                                 [concat(", ", sort(EnabledApps))])

#### Part 1: detecting service toggle events for OUs/groups *without* an individual admin control
TakeoutServiceEnableEvents contains {
    "Timestamp": time.parse_rfc3339_ns(Item.id.time),
    "TimestampStr": Item.id.time,
    "NewValue": NewValue,
    "OrgUnit": OrgUnit,
    "Group": Group
}
if {
    not PolicyApiInUse
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

NonComplianceMessage12_1a := "Takeout is enabled for services without an individual admin control."

NonCompliantOUs12_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage12_1a
}
if {
    not PolicyApiInUse
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
    "Value": NonComplianceMessage12_1a
}
if {
    not PolicyApiInUse
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
    not PolicyApiInUse
    Events := utils.FilterEventsNoOU(LogEvents, LogMessage12_1)
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
    not PolicyApiInUse
    Events := utils.FilterEventsNoOU(LogEvents, LogMessage12_1)
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
    "Value": NonComplianceMessage12_1(EnabledApps)
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, LogMessage12_1, OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    EnabledApps := AppsAllowingTakoutOU with data.OrgUnit as OU
    count(EnabledApps) > 0
}

NonCompliantGroups12_1 contains {
    "Name": Group,
    "Value": NonComplianceMessage12_1(EnabledApps)

}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    Events := utils.FilterEventsGroup(LogEvents, LogMessage12_1, Group)
    # Ignore groups without any events.
    count(Events) > 0
    EnabledApps := AppsAllowingTakoutGroup with data.Group as Group
    count(EnabledApps) > 0
}

#
# Baseline GWS.COMMONCONTROLS.12.1
#--

default NoSuchEvent12_1 := false

NoSuchEvent12_1 := true if {
    Events := utils.FilterEventsOU(LogEvents, LogMessage12_1, utils.TopLevelOU)
    count(Events) == 0
}

NoSuchEvent12_1 := true if {
    Events := {Event | some Event in TakeoutServiceEnableEvents; Event.OrgUnit == utils.TopLevelOU}
    count(Events) == 0
}

CommonControlsId12_1 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.12.1")

Check12_1_OK if {
    not PolicyApiInUse
    not NoSuchEvent12_1
}

Check12_1_OK if {PolicyApiInUse}

Takeout := {"blogger": "Blogger",
            "books": "Google Books",
            "location_history": "Timeline - Location History",
            "maps": "Google Maps",
            "pay": "Google Pay",
            "photos": "Google Photos",
            "play": "Google Play",
            "play_console": "Google Play Console",
            "youtube": "YouTube"}

NonCompliantOUs12_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage12_1(EnabledApps)

}
if {
    some OU, settings in input.policies
    utils.AppEnabled(input.policies, "takeout", OU)
    EnabledApps :=[value
		           | some key, value in Takeout
                     section := sprintf("%s_user_takeout", [key])
                     section in object.keys(settings)
                     state := settings[section].takeoutStatus
                     state != "DISABLED"]
    count(EnabledApps) > 0
}

tests contains {
    "PolicyId": CommonControlsId12_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check12_1_OK
}

tests contains {
    "PolicyId": CommonControlsId12_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs12_1, NonCompliantGroups12_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs12_1, "NonCompliantGroups": NonCompliantGroups12_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check12_1_OK
    Conditions := {count(NonCompliantOUs12_1) == 0, count(NonCompliantGroups12_1) == 0}
    Status := (false in Conditions) == false
}
#--

#########################
# GWS.COMMONCONTROLS.13 #
#########################

#
# Baseline GWS.COMMONCONTROLS.13.1
#--

CommonControlsId13_1 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.13.1")

tests contains {
    "PolicyId": CommonControlsId13_1,
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
# Baseline GWS.COMMONCONTROLS.14.1
#--

CommonControlsId14_1 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.14.1")

tests contains {
    "PolicyId": CommonControlsId14_1,
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#
# Baseline GWS.COMMONCONTROLS.14.2
#--

CommonControlsId14_2 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.14.2")

tests contains {
    "PolicyId": CommonControlsId14_2,
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
# Baseline GWS.COMMONCONTROLS.15.1
#--

CommonControlsId15_1 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.15.1")

tests contains {
    "PolicyId": CommonControlsId15_1,
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#
# Baseline GWS.COMMONCONTROLS.15.2
#--
CommonControlsId15_2 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.15.2")

NonCompliantOUs15_2 contains {
    "Name": OU,
    "Value": "Data processing in the region selected for data at rest is set to OFF"
} if {
    some OU in utils.OUsWithEvents
    SettingName := "DataProcessingRequirementsProto limit_to_storage_location"
    Events := utils.FilterEventsOU(LogEvents, SettingName, OU)
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "true"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

NonCompliantGroups15_2 contains {
    "Name": Group,
    "Value": "Data processing in the region selected for data at rest is set to OFF"
} if {
    some Group in utils.GroupsWithEvents
    SettingName := "DataProcessingRequirementsProto limit_to_storage_location"
    Events := utils.FilterEventsGroup(LogEvents, SettingName, Group)
    # Ignore groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue != "true"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": CommonControlsId15_2,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "DataProcessingRequirementsProto limit_to_storage_location"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": CommonControlsId15_2,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs15_2, NonCompliantGroups15_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs15_2, "NonCompliantGroups": NonCompliantGroups15_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "DataProcessingRequirementsProto limit_to_storage_location"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0

    Conditions := {
        count(NonCompliantOUs15_2) == 0,
        count(NonCompliantGroups15_2) == 0
    }
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.COMMONCONTROLS.15.3
#--

CommonControlsId15_3 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.15.3")

# NOTE: This setting cannot be controlled at the group level

NonCompliantOUs15_3 contains {
    "Name": OU,
    "Value": "Supplemental data storage is set to Russian Federation"
}
if {
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
    "PolicyId": CommonControlsId15_3,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    Events := utils.FilterEventsOU(LogEvents, "CHANGE_DATA_LOCALIZATION_FOR_RUSSIA", utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": CommonControlsId15_3,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs15_3, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs15_3},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := utils.FilterEventsOU(LogEvents, "CHANGE_DATA_LOCALIZATION_FOR_RUSSIA", utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs15_3) == 0
}
#--

#
# Baseline GWS.COMMONCONTROLS.16.1
#--

CommonControlsId16_1 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.16.1")

NonComplianceMessage16_1 := "Access to additional services without individual control is turned on"

# NOTE: This setting cannot be controlled at the group level

NonCompliantOUs16_1 contains {
    "Name": OU,
    "Value": NonComplianceMessage16_1
}
if {
    some OU in utils.OUsWithEvents
    # Note that this setting requires the custom ToggleServiceEvents rule.
    # Filter based on the service name of the event, otherwise all events are returned.
    Events := {
        Event | some Event in ToggleServiceEvents;
        Event.OrgUnit == OU;
        Event.ServiceName == "DISABLE_UNLISTED_SERVICES"
    }
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "false"
}

tests contains {
    "PolicyId": CommonControlsId16_1,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    # Filter based on the service name of the event, otherwise all events are returned.
    Events := {
        Event | some Event in ToggleServiceEvents;
        Event.OrgUnit == utils.TopLevelOU;
        Event.ServiceName == "DISABLE_UNLISTED_SERVICES"
    }
    count(Events) == 0
}

tests contains {
    "PolicyId": CommonControlsId16_1,
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs16_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs16_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    # Filter based on the service name of the event, otherwise all events are returned.
    Events := {
        Event | some Event in ToggleServiceEvents;
        Event.OrgUnit == utils.TopLevelOU;
        Event.ServiceName == "DISABLE_UNLISTED_SERVICES"
    }
    count(Events) > 0
    Status := count(NonCompliantOUs16_1) == 0
}
#--

#
# Baseline GWS.COMMONCONTROLS.16.2
#--

CommonControlsId16_2 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.16.2")

NonComplianceMessage16_2 := "Early access apps are ENABLED"

Check16_2_OK if {
    not PolicyApiInUse
    Events := {
        Event | some Event in ToggleServiceEvents;
        Event.OrgUnit == utils.TopLevelOU;
        Event.ServiceName == "Early Access Apps"
    }
    count(Events) > 0
}

Check16_2_OK if {PolicyApiInUse}

NonCompliantOUs16_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage16_2
}
if {
    not PolicyApiInUse
    some OU in utils.OUsWithEvents
    # Note that this setting requires the custom ToggleServiceEvents rule.
    # Filter based on the service name of the event, otherwise all events are returned.
    Events := {
        Event | some Event in ToggleServiceEvents;
        Event.OrgUnit == OU;
        Event.ServiceName == "Early Access Apps"
    }
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    # For the Early Access Apps service:
    # If service status is set to "ON for everyone", then "NewValue" == true (non-compliant state)
    # else, "NewValue" == false (compliant state)
    LastEvent.NewValue == "true"
}

NonCompliantGroups16_2 contains {
    "Name": Group,
    "Value": NonComplianceMessage16_2
}
if {
    not PolicyApiInUse
    some Group in utils.GroupsWithEvents
    # Note that this setting requires the custom ToggleServiceEvents rule.
    Events := {
        Event | some Event in ToggleServiceEvents;
        Event.Group == Group;
        Event.ServiceName == "Early Access Apps"
    }
    # Ignore groups without any events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "true"
}

NonCompliantOUs16_2 contains {
    "Name": OU,
    "Value": NonComplianceMessage16_2
}
if {
    some OU, settings in input.policies
    appState := utils.AppExplicitStatus(input.policies, "early_access_apps", OU)
    appState == "ENABLED"
}

tests contains {
    "PolicyId": CommonControlsId16_2,
    "Criticality": "Should",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    not PolicyApiInUse
    DefaultSafe := false
    not Check16_2_OK
}

tests contains {
    "PolicyId": CommonControlsId16_2,
    "Criticality": "Should",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs16_2, NonCompliantGroups16_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs16_2, "NonCompliantGroups": NonCompliantGroups16_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Check16_2_OK
    Conditions := {
        count(NonCompliantOUs16_2) == 0,
        count(NonCompliantGroups16_2) == 0
    }
    Status := (false in Conditions) == false
}
#--

#
# Baseline GWS.COMMONCONTROLS.17.1
#--

CommonControlsId17_1 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.17.1")

# NOTE: This setting cannot be controlled at the group level

NonCompliantOUs17_1 contains {
    "Name": OU,
    "Value": "Require multi party approval for sensitive admin actions is DISABLED"
}
if {
    some OU in utils.OUsWithEvents
    Events := utils.FilterEventsOU(LogEvents, "Multi Party Approval (MPA) Control Multi Party Approval Control", OU)
    # Ignore OUs without any events. We're already asserting that the
    # top-level OU has at least one event; for all other OUs we assume
    # they inherit from a parent OU if they have no events.
    count(Events) > 0
    LastEvent := utils.GetLastEvent(Events)
    LastEvent.NewValue == "disabled"
}

tests contains {
    "PolicyId": CommonControlsId17_1,
    "Criticality": "Shall",
    "ReportDetails": utils.NoSuchEventDetails(DefaultSafe, utils.TopLevelOU),
    "ActualValue": "No relevant event for the top-level OU in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    SettingName := "Multi Party Approval (MPA) Control Multi Party Approval Control"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": CommonControlsId17_1,
    "Criticality": "Shall",
    "ReportDetails": utils.ReportDetails(NonCompliantOUs17_1, []),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs17_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    SettingName := "Multi Party Approval (MPA) Control Multi Party Approval Control"
    Events := utils.FilterEventsOU(LogEvents, SettingName, utils.TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs17_1) == 0
}
#--

#########################
# GWS.COMMONCONTROLS.18 #
#########################

# TODO access actual API capabilities for DLP, the following checks are placeholders.

#
# Baseline GWS.COMMONCONTROLS.18.1
#--

CommonControlsId18_1 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.18.1")

tests contains {
    "PolicyId": CommonControlsId18_1,
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#
# Baseline GWS.COMMONCONTROLS.18.2
#--

CommonControlsId18_2 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.18.2")

tests contains {
    "PolicyId": CommonControlsId18_2,
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#
# Baseline GWS.COMMONCONTROLS.18.3
#--

CommonControlsId18_3 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.18.3")

tests contains {
    "PolicyId": CommonControlsId18_3,
    "Criticality": "Shall/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--

#
# Baseline GWS.COMMONCONTROLS.18.4
#--

CommonControlsId18_4 := utils.PolicyIdWithSuffix("GWS.COMMONCONTROLS.18.4")

tests contains {
    "PolicyId": CommonControlsId18_4,
    "Criticality": "Should/Not-Implemented",
    "ReportDetails": "Currently not able to be tested automatically; please manually check.",
    "ActualValue": "",
    "RequirementMet": false,
    "NoSuchEvent": true
}
#--
