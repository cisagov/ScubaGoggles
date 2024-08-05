package classroom
import future.keywords


# GWS.CLASSROOM.2.1v0.2
#--

test_APIAccess_Correct_V1 if {
    # Test API Access is disabled when there's only one event
    PolicyId := "GWS.CLASSROOM.2.1v0.2"
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "ApiDataAccessSettingProto api_access_enabled"},
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

test_APIAccess_Correct_V2 if {
    # Test enforcing API Access is disabled when there's multiple events, with the chronological latest
    # correct but not last in json list
    PolicyId := "GWS.CLASSROOM.2.1v0.2"
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "ApiDataAccessSettingProto api_access_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "ApiDataAccessSettingProto api_access_enabled"},
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
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_APIAccess_Correct_V3 if {
    # Test enforcing API Access is disabled is correct when there are events in multiple OUs
    PolicyId := "GWS.CLASSROOM.2.1v0.2"
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ApiDataAccessSettingProto api_access_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ApiDataAccessSettingProto api_access_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
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
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_APIAccess_Correct_V4 if {
    # Test API Access is disabled when set to inherit from parent
    PolicyId := "GWS.CLASSROOM.2.1v0.2"
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2020-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ApiDataAccessSettingProto api_access_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ApiDataAccessSettingProto api_access_enabled"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ApiDataAccessSettingProto api_access_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
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

test_APIAccess_Incorrect_V1 if {
    # Test API Access is disabled when there's only one event and it's wrong
    PolicyId := "GWS.CLASSROOM.2.1v0.2"
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "ApiDataAccessSettingProto api_access_enabled"},
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
        "The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "Data access is set to ON</li></ul>"
    ])
}

test_APIAccess_Incorrect_V2 if {
    # Test API Access is disabled when there's multiple events, with the chronological latest
    # incorrect but not last in json list
    PolicyId := "GWS.CLASSROOM.2.1v0.2"
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "ApiDataAccessSettingProto api_access_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "ApiDataAccessSettingProto api_access_enabled"},
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
        "The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "Data access is set to ON</li></ul>"
    ])
}


test_APIAccess_Incorrect_V3 if {
    # Test API Access is disabled when there no applicable event
    PolicyId := "GWS.CLASSROOM.2.1v0.2"
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "something else"},
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
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}
test_APIAccess_Incorrect_V4 if {
    # Test allow API Access is disabled when there are multiple OU and a secondary OU is wrong
    PolicyId := "GWS.CLASSROOM.2.1v0.2"
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ApiDataAccessSettingProto api_access_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ApiDataAccessSettingProto api_access_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
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
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul><li>Test Secondary OU: ",
        "Data access is set to ON</li></ul>"
    ])
}
#--

test_APIAccess_Incorrect_V5 if {
    # Test API Access is disabled when the primary OU is missing but a different one is present
    PolicyId := "GWS.CLASSROOM.2.1v0.2"
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ApiDataAccessSettingProto api_access_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
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

test_APIAccess_Incorrect_V6 if {
    # Test API Access is disabled access when there's only one event and it's wrong
    PolicyId := "GWS.CLASSROOM.2.1v0.2"
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ApiDataAccessSettingProto api_access_enabled"},
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
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "Data access is set to SAME_DOMAIN</li></ul>"
    ])
}

test_APIAccess_Incorrect_V7 if {
    # Test API Access is disabled when there are multiple events and the most recent is wrong
    PolicyId := "GWS.CLASSROOM.2.1v0.2"
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ApiDataAccessSettingProto api_access_enabled"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ApiDataAccessSettingProto api_access_enabled"},
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
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "Data access is set to SAME_DOMAIN</li></ul>"
    ])
}

test_APIAccess_Incorrect_V8 if {
    # Test API Access is disabled when there are multiple OU and a secondary OU is wrong
    PolicyId := "GWS.CLASSROOM.2.1v0.2"
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ApiDataAccessSettingProto api_access_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ApiDataAccessSettingProto api_access_enabled"},
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
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul><li>Test Secondary OU: ",
        "Data access is set to SAME_DOMAIN</li></ul>"
    ])
}
#--

test_APIAccess_Incorrect_V9 if {
    # Test API Access is disabled when the primary OU is missing but a different one is present
    PolicyId := "GWS.CLASSROOM.2.1v0.2"
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ApiDataAccessSettingProto api_access_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
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
#--
