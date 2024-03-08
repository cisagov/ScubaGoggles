package meet
import future.keywords


#
# Baseline 2 - Policy 1
#--
test_JoinExternalPers_Correct_V1 if {
    # Test meeting access when there's only one event
    PolicyId := "GWS.MEET.2.1v0.1"
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "WORKSPACE_DOMAINS"},
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
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_JoinExternalPers_Correct_V2 if {
    # Test meeting access when there's multiple events and the most most recent is correct
    PolicyId := "GWS.MEET.2.1v0.1"
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "WORKSPACE_DOMAINS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "ALL"},
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
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_JoinExternalPers_Correct_V3 if {
    # Test meeting access when there's multiple events and the most most recent is correct
    PolicyId := "GWS.MEET.2.1v0.1"
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "WORKSPACE_DOMAINS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "WORKSPACE_DOMAINS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
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

test_History_Correct_V4 if {
    # Test history setting when set to inherit from parent
    PolicyId := "GWS.MEET.2.1v0.1"
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2020-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "WORKSPACE_DOMAINS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "ALL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
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

test_JoinExternalPers_Correct_V5 if {
    # Test meeting access when there's only one event
    PolicyId := "GWS.MEET.2.1v0.1"
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
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
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_JoinExternalPers_Correct_V6 if {
    # Test meeting access when there's multiple events and the most most recent is correct
    PolicyId := "GWS.MEET.2.1v0.1"
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "ALL"},
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
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_JoinExternalPers_Correct_V7 if {
    # Test meeting access when there's multiple events and the most most recent is correct
    PolicyId := "GWS.MEET.2.1v0.1"
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
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

test_History_Correct_V8 if {
    # Test history setting when set to inherit from parent
    PolicyId := "GWS.MEET.2.1v0.1"
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2020-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "ALL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
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

test_JoinExternalPers_Incorrect_V1 if {
    # Test meeting access when there are no relevant events
    PolicyId := "GWS.MEET.2.1v0.1"
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "ALL"},
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

test_JoinExternalPers_Incorrect_V2 if {
    # Test meeting access when there's only one event and it's wrong
    PolicyId := "GWS.MEET.2.1v0.1"
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "ALL"},
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
    RuleOutput[0].Criticality == "Shall"
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
    "What meetings can org users join is set to any meetings, ",
    "including meetings created with personal accounts</li></ul>"])
}

test_JoinExternalPers_Incorrect_V3 if {
    # Test meeting access when there are multiple events and the most recent is wrong
    PolicyId := "GWS.MEET.2.1v0.1"
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "ALL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "WORKSPACE_DOMAINS"},
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
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
    "What meetings can org users join is set to any meetings, ",
    "including meetings created with personal accounts</li></ul>"])
}

test_JoinExternalPers_Incorrect_V4 if {
    # Test allow user to change history setting when there are multiple OU and a secondary OU is wrong
    PolicyId := "GWS.MEET.2.1v0.1"
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "ALL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
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
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Test Secondary OU: ",
    "What meetings can org users join is set to any meetings, ",
    "including meetings created with personal accounts</li></ul>"])
}
#--

test_JoinExternalPers_Incorrect_V5 if {
    # Test allow user to change history setting when the primary OU is missing but a different one is present
    PolicyId := "GWS.MEET.2.1v0.1"
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
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
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

test_JoinExternalPers_Incorrect_V6 if {
    # Test meeting access when there's only one event and it's wrong
    PolicyId := "GWS.MEET.2.1v0.1"
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "ALL"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
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
    RuleOutput[0].Criticality == "Shall"
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Secondary OU: ",
    "What meetings can org users join is set to any meetings, ",
    "including meetings created with personal accounts</li></ul>"])
}

test_JoinExternalPers_Incorrect_V7 if {
    # Test meeting access when there are multiple events and the most recent is wrong
    PolicyId := "GWS.MEET.2.1v0.1"
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "ALL"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SafetyAccessLockProto meetings_allowed_to_join"},
                        {"name": "NEW_VALUE", "value": "WORKSPACE_DOMAINS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
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
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Secondary OU: ",
    "What meetings can org users join is set to any meetings, ",
    "including meetings created with personal accounts</li></ul>"])
}
