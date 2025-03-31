package utils
import future.keywords

# This is for use in versioning the baseline policy identifiers.  The versions
# are kept out of the Rego files to minimize updates.  The baseline Markdown
# files are the source of the policy version suffixes.  Both the default
# "baseline_suffix" and policy to version mapping ("baseline_versions") are
# included by the Orchestrator in the input data for normal policy evaluation.
# For testing, the version suffix is not required in the input data, as the
# default will be used and the results are only processed by OPA (and not the
# Reporter, which WILL look for matches between policy IDs in the Markdown and
# OPA results).

default BaseVersionSuffix := "vM"

BaseVersionSuffix := input.baseline_suffix if {
    "baseline_suffix" in object.keys(input)}

PolicyIdSuffix(PolicyIdPrefix) := policyVersionSuffix if {
    "baseline_versions" in object.keys(input)
    PolicyIdPrefix in object.keys(input.baseline_versions)
    policyVersionSuffix := input.baseline_versions[PolicyIdPrefix]
} else := BaseVersionSuffix

PolicyIdWithSuffix(PolicyIdPrefix) := sprintf("%s%s",
                                              [PolicyIdPrefix,
                                               PolicyIdSuffix(PolicyIdPrefix)])

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

EnumOUSettings(NonCompOUs) := NonCompliantMessage("OUs", NonCompOUs)

EnumGroupSettings(NonCompGroups) := NonCompliantMessage("groups", NonCompGroups)

# Create a html formatted list detailing the settings for each OU/group
# - Listing: a set of dicts, each with a "Name" and "Value" fields
NonCompliantMessage(GroupsOrOU, Listing) := message if {
    items := [concat("", ["<li>", item.Name, ": ", item.Value, "</li>"])
              | some item in Listing]
    message := sprintf("The following %s are non-compliant:<ul>%s</ul>",
                       [GroupsOrOU, concat("", items)])
}

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

RequirementsMetMessage := "Requirement met in all OUs and groups."

ReportDetails(NonCompOUs, NonCompGroups) := Description if {
    count(NonCompOUs) == 0
    count(NonCompGroups) == 0
    Description := RequirementsMetMessage
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

# Use GetApiSettingValue() when you need to determine for a "sub" orgunit
# (not the top-level orgunit) the current setting value.  It may be set
# explicitly in the orgunit, but it may be inherited from the top-level
# orgunit.  This function handles both cases.  The ApiSettingExists() is
# a helper function that indicates whether a setting is present in the given
# orgunit.  All settings MUST be present in the top-level orgunit.

ApiSettingExists(Section, Setting, OU) := true if {
    OUSettings := input.policies[OU]
    Section in object.keys(OUSettings)
    Setting in object.keys(OUSettings[Section])
} else := false

GetApiSettingValue(Section, Setting, OU) := Value if {
    not ApiSettingExists(Section, Setting, OU)
    topOUSettings := input.policies[TopLevelOU]
    Value := topOUSettings[Section][Setting]
}

GetApiSettingValue(Section, Setting, OU) := Value if {
    OUSettings := input.policies[OU]
    Value := OUSettings[Section][Setting]
}

# The following functions are intended for use in testing the Scubagoggles
# Rego modules.

PassTestResult(PolicyId, Output) := TestResult(PolicyId,
                                               Output,
                                               RequirementsMetMessage,
                                               true)

PassTestResultWithMessage(PolicyId, Output, Message) := TestResult(PolicyId,
                                                                   Output,
                                                                   Message,
                                                                   true)

FailTestResult(PolicyId, Output, FailMessage) := TestResult(PolicyId,
                                                            Output,
                                                            FailMessage,
                                                            false)

FailTestNoEvent(PolicyId, Output, TopOU, defaultOK) := true if {
    RuleOutput := FindTestOutput(PolicyId, Output)
    RuleOutput.RequirementMet == defaultOK
    RuleOutput.NoSuchEvent
    RuleOutput.ReportDetails == NoSuchEventDetails(defaultOK, TopOU)
} else := false

FailTestGroupNonCompliant(PolicyId, Output, Listing) if {
    RuleOutput := FindTestOutput(PolicyId, Output)
    not RuleOutput.RequirementMet
    not RuleOutput.NoSuchEvent
    RuleOutput.ReportDetails == EnumGroupSettings(Listing)
} else := false

FailTestOUNonCompliant(PolicyId, Output, Listing) if {
    RuleOutput := FindTestOutput(PolicyId, Output)
    not RuleOutput.RequirementMet
    not RuleOutput.NoSuchEvent
    RuleOutput.ReportDetails == EnumOUSettings(Listing)
} else := false

FailTestNonCompliant(PolicyId, Output, Message) if {
    RuleOutput := FindTestOutput(PolicyId, Output)
    not RuleOutput.RequirementMet
    not RuleOutput.NoSuchEvent
    RuleOutput.ReportDetails == Message
} else := false

FailTestBothNonCompliant(PolicyId, Output, OUListing, GroupListing) if {
    RuleOutput := FindTestOutput(PolicyId, Output)
    not RuleOutput.RequirementMet
    not RuleOutput.NoSuchEvent
    RuleOutput.ReportDetails == sprintf("%s<br>%s",
                                        [EnumOUSettings(OUListing),
                                         EnumGroupSettings(GroupListing)])
} else := false

ManualCheckMessage := "Currently not able to be tested automatically; please manually check."

NotImplementedTestResult(PolicyId, Output) if {
    RuleOutput := FindTestOutput(PolicyId, Output)
    RuleOutput.RequirementMet == false
    RuleOutput.NoSuchEvent
    RuleOutput.ReportDetails == ManualCheckMessage
} else := false

TestResult(PolicyId, Output, ReportDetailString, RequirementMet) := true if {
    RuleOutput := FindTestOutput(PolicyId, Output)
    RuleOutput.RequirementMet == RequirementMet
    EventsOK(RuleOutput)
    RuleOutput.ReportDetails == ReportDetailString
} else := false

FindTestOutput(PolicyId, Output) := RuleOutput if {
    RulesOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RulesOutput) == 1
    RuleOutput := RulesOutput[0]
}

EventsOK(RuleOutput) if {
    PolicyApiInUse
} else if {
    not RuleOutput.NoSuchEvent
} else := false

default PolicyApiInUse := false

PolicyApiInUse if {"policies" in object.keys(input)}

# The function you should use to determine the enabled state is AppEnabled().
# AppDisabled() only checks whether the orgunit has an explicit disabled
# state - if it doesn't have an explicit state setting, it'll inherit
# the setting from the top orgunit.  Use AppEnabled() and NOT AppDisabled()!
# Use it like this, for example (with Chat):
#
#   ChatEnabled(orgunit) := utils.AppEnabled(input.policies, "chat", orgunit)
#
# (you have to make sure the service status name is "chat_service_status" in
# the policies input data).

AppDisabled(policies, serviceStatusName, orgunit) if {
    appState := policies[orgunit][serviceStatusName].serviceState
    upper(appState) == "DISABLED"
}

default AppEnabled(_, _, _) := false

AppServiceStatusName(appName) := sprintf("%s_service_status", [appName])

AppEnabled(policies, appName, orgunit) if {
    serviceStatusName := AppServiceStatusName(appName)
    appState := policies[orgunit][serviceStatusName].serviceState
    upper(appState) == "ENABLED"
}

AppEnabled(policies, appName, orgunit) if {
    serviceStatusName := AppServiceStatusName(appName)
    not AppDisabled(policies, serviceStatusName, orgunit)
    appState := policies[TopLevelOU][serviceStatusName].serviceState
    upper(appState) == "ENABLED"
}

# Use the following function if you need to know if the app enable state has
# been explicitly set in the given orgunit or group.  The above functions will
# tell you whether the app is enabled, but its state may be due to inheriting
# the state from the top-level orgunit.  In some cases, you need to know
# whether the state has been explicitly set (not inherited).  This function
# returns "ENABLED", "DISABLED" if explicitly set; it's undefined otherwise.

AppExplicitStatus(policies, appName, orgunit) := appState if {
    serviceStatusName := AppServiceStatusName(appName)
    appState := upper(policies[orgunit][serviceStatusName].serviceState)
}

# There are a lot of policies that have enabled/disabled states.  The states
# (values) in the log events are strings ("true", "false), while the states
# in the Policy API are booleans (true, false).  This is a common function
# to translate the states to "enabled"/"disabled".

GetFriendlyEnabledValue(Value) := "enabled" if {
    Value in {true, "true"}
} else := "disabled" if {
    Value in {false, "false"}
} else := Value

# This function will convert a "duration string" (e.g., "18m" for 18 minutes)
# to an integer representing the time in seconds.  This may be used for
# comparing string durations.  Typically, Google's Policy API returns duration
# values in seconds.  See CC 1.2 & CC 4.1 for examples of usage.

DurationToSeconds(duration) := durationSeconds if {
    multipliers := {"s": 1, "m": 60, "h": 3600, "d": 86400}
    result := regex.find_all_string_submatch_n(`(?i)^(\d+)([dhms])$`,
                                            duration,
                                            1)
    firstMatch := result[0]
    value := to_number(firstMatch[1])
    unit := firstMatch[2]
    multiplier := multipliers[lower(unit)]
    durationSeconds := value * multiplier
}

# Google will often return durations in seconds, but the values correspond to
# a "common" duration (that is usually a choice in the UI).  This function
# will convert the given seconds to a duration other than seconds that will
# (hopefully) make more sense to the user.

GetFriendlyDuration(Seconds) := "180 days" if {
    Seconds == 15552000
} else := "90 days" if {
    Seconds == 7776000
} else := "30 days" if {
    Seconds == 2592000
} else := "14 days" if {
    Seconds == 1209600
} else := "7 days" if {
    Seconds == 604800
} else := "24 hours" if {
    Seconds == 86400
} else := "20 hours" if {
    Seconds == 72000
} else := sprintf("%d seconds", [Seconds])
