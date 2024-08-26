package commoncontrols
import future.keywords

#
# GWS.COMMONCONTROLS.12.1v0.3
#--
test_Takeout_Correct_V1 if {
    # Test basic correct
    PolicyId := "GWS.COMMONCONTROLS.12.1v0.3"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Disabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Blogger"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Google Takeout"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_Takeout_Incorrect_V1 if {
    # Test specifc apps allowed, ou
    PolicyId := "GWS.COMMONCONTROLS.12.1v0.3"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Enabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Blogger"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Enabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Google Maps"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Google Takeout"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul>",
        "<li>Test Top-Level OU: The following apps with individual admin control have Takeout enabled: ",
        "Blogger, Google Maps</li>",
        "</ul>"
    ])
}

test_Takeout_Incorrect_V2 if {
    # Test nonspecific apps allowed, ou
    PolicyId := "GWS.COMMONCONTROLS.12.1v0.3"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Disabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Blogger"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Google Takeout"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul>",
        "<li>Test Top-Level OU: Takeout is enabled for services without an individual admin control</li>",
        "</ul>"
    ])
}

test_Takeout_Incorrect_V3 if {
    # Test nonspecific apps and specific apps allowed, ou
    PolicyId := "GWS.COMMONCONTROLS.12.1v0.3"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Enabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Blogger"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Google Takeout"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul>",
        "<li>Test Top-Level OU: Takeout is enabled for services without an individual admin control</li>",
        "<li>Test Top-Level OU: The following apps with individual admin control have Takeout enabled: Blogger</li>",
        "</ul>"
    ])
}

test_Takeout_Incorrect_V4 if {
    # Test nonspecific apps allowed, group
    PolicyId := "GWS.COMMONCONTROLS.12.1v0.3"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "Disabled"},
                        {"name": "SETTING_NAME", "value": "UserTakeoutSettingsProto User Takeout "},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Blogger"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Google Takeout"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Google Takeout"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "GROUP_EMAIL", "value": "test@test"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following groups are non-compliant:<ul>",
        "<li>test@test: Takeout is enabled for services without an individual admin control</li>",
        "</ul>"
    ])
}
#--