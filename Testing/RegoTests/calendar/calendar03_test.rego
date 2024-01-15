package calendar
import future.keywords

#
# Policy 1
#--
test_ExtSharingSecondaryCal_Correct_V1 if {
 # Test external sharing for secondary calendars when there's only one event
    PolicyId := "GWS.CALENDAR.3.1v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "<span class=setting>Only free busy/information for secondary calendars </span>",
        " is shared outside Test Top-Level Domain"
    ])
}

test_ExtSharingSecondaryCal_Correct_V2 if {
    # Test external sharing for secondary calendars when there's multiple events and the most most recent is correct
    PolicyId := "GWS.CALENDAR.3.1v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "<span class=setting>Only free busy/information for secondary calendars </span> ",
        "is shared outside Test Top-Level Domain"
    ])
}

test_ExtSharingSecondaryCal_Incorrect_V1 if {
    # Test external sharing for secondary calendars when there are no relevant events
    PolicyId := "GWS.CALENDAR.3.1v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

test_ExtSharingSecondaryCal_Incorrect_V2 if {
    # Test external sharing for secondary calendars when there's only one event and it's wrong
    PolicyId := "GWS.CALENDAR.3.1v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "<span class=setting>All information for secondary calendars </span>",
        " is shared outside Test Top-Level Domain but outsiders cannot change calendars."
    ])
}

test_ExtSharingSecondaryCal_Incorrect_V3 if {
    # Test external sharing for secondary calendars when there are multiple events and the most recent is wrong
    PolicyId := "GWS.CALENDAR.3.1v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"},
                        {"name": "NEW_VALUE", "value": "READ_WRITE_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "<span class=setting>All information for secondary calendars </span>",
        " is shared outside Test Top-Level Domain but outsiders cannot change calendars."
    ])
}

#
# GWS.CALENDAR.3.2v0.1
#--

test_ExternalSharingOptions_Secondary__Correct_V1 if {
    # Not-Implemented
    PolicyId := "GWS.CALENDAR.3.2v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Currently not able to be tested automatically; please manually check."
}
#--