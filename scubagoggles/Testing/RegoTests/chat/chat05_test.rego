package chat
import future.keywords

#
# GWS.CHAT.5.1
#--
test_Enable_Correct_V1 if {
    # Test correct 1 OU
    PolicyId := ChatId5_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto one_on_one_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto group_chat_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_restrictions"},
                        {"name": "NEW_VALUE", "value": "SPACE_RESTRICTIONS_NO_RESTRICTIONS"},
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
    RuleOutput[0].ReportDetails == concat("<br>", ["Requirement met in all OUs and groups.", Chat5Warning])
}

test_Enable_Correct_V2 if {
    # Test correct 2 OUs, child OU overrides top-level settings
    PolicyId := ChatId5_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto one_on_one_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto group_chat_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_restrictions"},
                        {"name": "NEW_VALUE", "value": "SPACE_RESTRICTIONS_NO_RESTRICTIONS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto one_on_one_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Other OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto group_chat_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Other OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Other OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_restrictions"},
                        {"name": "NEW_VALUE", "value": "SPACE_RESTRICTIONS_NO_RESTRICTIONS"},
                        {"name": "ORG_UNIT_NAME", "value": "Other OU"},
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
    RuleOutput[0].ReportDetails == concat("<br>", ["Requirement met in all OUs and groups.", Chat5Warning])
}

test_Enable_Correct_V3 if {
    # Test correct 2 OUs, child OU inherits
    PolicyId := ChatId5_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto one_on_one_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto group_chat_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_restrictions"},
                        {"name": "NEW_VALUE", "value": "SPACE_RESTRICTIONS_NO_RESTRICTIONS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto one_on_one_reporting"},
                        {"name": "ORG_UNIT_NAME", "value": "Other OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto group_chat_reporting"},
                        {"name": "ORG_UNIT_NAME", "value": "Other OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_reporting"},
                        {"name": "ORG_UNIT_NAME", "value": "Other OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_restrictions"},
                        {"name": "ORG_UNIT_NAME", "value": "Other OU"},
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
    RuleOutput[0].ReportDetails == concat("<br>", ["Requirement met in all OUs and groups.", Chat5Warning])
}

test_Enable_Incorrect_V1 if {
    # Test incorrect 1 OU, one conversation type is disabled
    PolicyId := ChatId5_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto one_on_one_reporting"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto group_chat_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_restrictions"},
                        {"name": "NEW_VALUE", "value": "SPACE_RESTRICTIONS_NO_RESTRICTIONS"},
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
        "The following OUs are non-compliant:<ul>",
        "<li>Test Top-Level OU: Content reporting for 1:1 direct messages is disabled.</li></ul>",
        "<br>",
        Chat5Warning
    ])
}

test_Enable_Incorrect_V2 if {
    # Test incorrect 1 OU, spaces restricted
    PolicyId := ChatId5_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto one_on_one_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto group_chat_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_restrictions"},
                        {"name": "NEW_VALUE", "value": "SPACE_RESTRICTIONS_DISCOVERABLE_SPACES_ONLY"},
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
        "The following OUs are non-compliant:<ul>",
        "<li>Test Top-Level OU: Content reporting for spaces is restricted to discoverable spaces only.</li></ul>",
        "<br>",
        Chat5Warning
    ])
}

test_Enable_Incorrect_V3 if {
    # Test correct 2 OUs, child OU overrides top-level settings
    PolicyId := ChatId5_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto one_on_one_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto group_chat_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_restrictions"},
                        {"name": "NEW_VALUE", "value": "SPACE_RESTRICTIONS_NO_RESTRICTIONS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto one_on_one_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Other OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto group_chat_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Other OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_DISABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Other OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_restrictions"},
                        {"name": "NEW_VALUE", "value": "SPACE_RESTRICTIONS_NO_RESTRICTIONS"},
                        {"name": "ORG_UNIT_NAME", "value": "Other OU"},
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
        "<li>Other OU: Content reporting for spaces is disabled.</li></ul>",
        "<br>",
        Chat5Warning
    ])
}

test_Enable_Incorrect_V4 if {
    # Test incorrect 1 OU, one setting is missing
    PolicyId := ChatId5_1
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto group_chat_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_reporting"},
                        {"name": "NEW_VALUE", "value": "CONTENT_REPORTING_STATE_ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto room_restrictions"},
                        {"name": "NEW_VALUE", "value": "SPACE_RESTRICTIONS_NO_RESTRICTIONS"},
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

#
# GWS.CHAT.5.2
#--
test_Categories_Correct_V1 if {
    # Test correct 1 OU
    PolicyId := ChatId5_2
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto report_types"},
                        {
                            "name": "NEW_VALUE",
                            "value": concat("", [
                                "[system_violation: HARASSMENT\n, system_violation: DISCRIMINATION\n, ",
                                "system_violation: EXPLICIT_CONTENT\n, system_violation: SPAM\n, ",
                                "system_violation: CONFIDENTIAL_INFORMATION\n, system_violation: ",
                                "SENSITIVE_INFORMATION\n, system_violation: OTHER\n]"
                            ])
                        },
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

test_Categories_Correct_V2 if {
    # Test correct, 2 OUs, child OU overrides
    PolicyId := ChatId5_2
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto report_types"},
                        {
                            "name": "NEW_VALUE",
                            "value": concat("", [
                                "[system_violation: HARASSMENT\n, system_violation: DISCRIMINATION\n, ",
                                "system_violation: EXPLICIT_CONTENT\n, system_violation: SPAM\n, ",
                                "system_violation: CONFIDENTIAL_INFORMATION\n, system_violation: ",
                                "SENSITIVE_INFORMATION\n, system_violation: OTHER\n]"
                            ])
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto report_types"},
                        {
                            "name": "NEW_VALUE",
                            "value": concat("", [
                                "[system_violation: HARASSMENT\n, system_violation: DISCRIMINATION\n, ",
                                "system_violation: EXPLICIT_CONTENT\n, system_violation: SPAM\n, ",
                                "system_violation: CONFIDENTIAL_INFORMATION\n, system_violation: ",
                                "SENSITIVE_INFORMATION\n, system_violation: OTHER\n]"
                            ])
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Other OU"},
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

test_Categories_Correct_V3 if {
    # Test correct, 2 OUs, child OU inherits
    PolicyId := ChatId5_2
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto report_types"},
                        {
                            "name": "NEW_VALUE",
                            "value": concat("", [
                                "[system_violation: HARASSMENT\n, system_violation: DISCRIMINATION\n, ",
                                "system_violation: EXPLICIT_CONTENT\n, system_violation: SPAM\n, ",
                                "system_violation: CONFIDENTIAL_INFORMATION\n, system_violation: ",
                                "SENSITIVE_INFORMATION\n, system_violation: OTHER\n]"
                            ])
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto report_types"},
                        {"name": "ORG_UNIT_NAME", "value": "Other OU"},
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

test_Categories_Incorrect_V1 if {
    # Test incorrect 1 OU
    PolicyId := ChatId5_2
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto report_types"},
                        {
                            "name": "NEW_VALUE",
                            "value": concat("", [
                                "[system_violation: HARASSMENT\n, system_violation: DISCRIMINATION\n, ",
                                "system_violation: EXPLICIT_CONTENT\n, system_violation: SPAM\n, ",
                                "system_violation: CONFIDENTIAL_INFORMATION\n, system_violation: ",
                                "SENSITIVE_INFORMATION\n]"
                            ])
                        },
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
        "The following OUs are non-compliant:<ul>",
        "<li>Test Top-Level OU: The following reporting types are disabled: other</li></ul>"
    ])
}

test_Categories_Incorrect_V2 if {
    # Test incorrect 2 OUs
    PolicyId := ChatId5_2
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto report_types"},
                        {
                            "name": "NEW_VALUE",
                            "value": concat("", [
                                "[system_violation: HARASSMENT\n, system_violation: DISCRIMINATION\n, ",
                                "system_violation: EXPLICIT_CONTENT\n, system_violation: SPAM\n, ",
                                "system_violation: CONFIDENTIAL_INFORMATION\n, system_violation: ",
                                "SENSITIVE_INFORMATION\n, system_violation: OTHER\n]"
                            ])
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.662Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "ContentReportingProto report_types"},
                        {
                            "name": "NEW_VALUE",
                            "value": concat("", [
                                "[system_violation: DISCRIMINATION\n, ",
                                "system_violation: EXPLICIT_CONTENT\n, system_violation: SPAM\n, ",
                                "system_violation: CONFIDENTIAL_INFORMATION\n, system_violation: ",
                                "SENSITIVE_INFORMATION\n, system_violation: OTHER\n]"
                            ])
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Other OU"},
                    ]
                }]
            },
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
        "<li>Other OU: The following reporting types are disabled: harassment</li></ul>"
    ])
}

test_Categories_Incorrect_V3 if {
    # Test incorrect no events
    PolicyId := ChatId5_2
    Output := tests with input as {
        "chat_logs": {"items": [

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
