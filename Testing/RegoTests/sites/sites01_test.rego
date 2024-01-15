package sites
import future.keywords

#
# Baseline GWS.SITES.1.1v0.1
#--

test_Sites_Disabled_Correct_V1 if {
    # Test ensure Sites is disabled
    PolicyId := "GWS.SITES.1.1v0.1"
    Output := tests with input as {
        "sites_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Sites"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
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
    RuleOutput[0].ReportDetails == "Requirement met in all OUs."
}

test_Sites_Disabled_Correct_V2 if {
    # Test ensure sites is disabled when there's multiple events and the most recent is correct
    PolicyId := "GWS.SITES.1.1v0.1"
    Output := tests with input as {
        "sites_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Sites"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Sites"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
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
    RuleOutput[0].ReportDetails == "Requirement met in all OUs."
}

test_Sites_Disabled_Correct_V3 if {
    # Test ensure sites is disabled when there are multiple OU's
    PolicyId := "GWS.SITES.1.1v0.1"
    Output := tests with input as {
        "sites_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Sites"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Sites"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
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
    RuleOutput[0].ReportDetails == "Requirement met in all OUs."
}

test_Sites_Disabled_Correct_V4 if {
    # Test sites is disabled when there are multiple OU's and an older event is non-complaint
    PolicyId := "GWS.SITES.1.1v0.1"
    Output := tests with input as {
        "sites_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Sites"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Sites"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Sites"},
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
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs."
}

#--------TO FIX
test_Sites_Disabled_Correct_V5 if {
    # Test Sites inheritance
    PolicyId := "GWS.SITES.1.1v0.1"
    Output := tests with input as {
        "sites_logs": {"items": [
            {
                "id": {"time": "2022-12-10T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Sites"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:29.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Sites"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Second OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Sites"},
                        {"name": "NEW_VALUE", "value": "INHERIT_FROM_PARENT"},
                        {"name": "ORG_UNIT_NAME", "value": "Second OU"},
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
    RuleOutput[0].ReportDetails == "Requirement met in all OUs."
}

test_Sites_Disabled_Incorrect_V1 if {
    # Test sites is disabled when there is an event for a different service
    PolicyId := "GWS.SITES.1.1v0.1"
    Output := tests with input as {
        "sites_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Sites"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
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
    RuleOutput[0].ReportDetails == "Requirement failed in Test Top-Level OU."
}

test_Sites_Disabled_Incorrect_V2 if {
    # Test Sites is disabled when there's only one event and it's wrong
    PolicyId := "GWS.SITES.1.1v0.1"
    Output := tests with input as {
        "sites_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Sites"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
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
    RuleOutput[0].ReportDetails == "Requirement failed in Test Top-Level OU."
}

test_Sites_Disabled_Incorrect_V3 if {
    # Test sites is disabled when there are multiple events and the most recent is wrong
    PolicyId := "GWS.SITES.1.1v0.1"
    Output := tests with input as {
        "sites_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Sites"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Sites"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
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
    RuleOutput[0].ReportDetails == "Requirement failed in Test Top-Level OU."
}

test_Sites_Disabled_Incorrect_V4 if {
    # Test sites is disabled when the Top-level OU is compliant but a secondary OU is non-compliant
    PolicyId := "GWS.SITES.1.1v0.1"
    Output := tests with input as {
        "sites_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Sites"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Sites"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement failed in Secondary OU."
}

test_Sites_Disabled_Incorrect_V5 if {
    # Test sites is disabled when there's only one event and it's wrong
    PolicyId := "GWS.SITES.1.1v0.1"
    Output := tests with input as {
        "sites_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Sites"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
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
    RuleOutput[0].ReportDetails == "Requirement failed in Test Top-Level OU."
}

test_Sites_Disabled_Incorrect_V6 if {
    # Test sites is disabled when there are no relevant events
    PolicyId := "GWS.SITES.1.1v0.1"
    Output := tests with input as {
        "sites_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
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
#--