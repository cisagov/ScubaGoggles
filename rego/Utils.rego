package utils
import future.keywords

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

OUsWithEvents contains OrgUnit if {
    some Log in input
    some Item in Log.items
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
    count(OUsWithEvents) == 1
    some OU in OUsWithEvents
}

TopLevelOU := Name if {
    # Extreme edge case: input.tenant_info.topLevelOU is empty
    # because no custom OUs currently exist, but multiple OUs
    # are present in the events, likely due to an custom OU
    # that was deleted. In this case, we have no way of determining
    # which of OUs is the current OU.
    input.tenant_info.topLevelOU == ""
    count(OUsWithEvents) > 1
    Name := ""
}

TopLevelOU := Name if {
    # Extreme edge case: no custom OUs have been made
    # and the logs are empty. In this case, we really
    # have no way of determining the top-level OU name.
    input.tenant_info.topLevelOU == ""
    count(OUsWithEvents) == 0
    Name := ""
}