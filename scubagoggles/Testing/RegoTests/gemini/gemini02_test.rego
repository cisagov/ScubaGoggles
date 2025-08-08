package gemini
import future.keywords

#
# GWS.GEMINI.2.1
#--
test_2_1_Correct_V1 if {
    PolicyId := GeminiId2_1
    Output := tests with input as {
        "gemini_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GenAiAlphaSettingsProto alpha_enabled"
                        },
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"},
                    ]
                }]
            }
        ]},
        "policies": {
            "topOU": {
                "gemini_app_service_status": {"serviceState": "ENABLED"}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_2_1_Correct_V2 if {
    # Alpha Gemini features enabled but Gemini disabled for OU
    PolicyId := GeminiId2_1
    Output := tests with input as {
        "gemini_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GenAiAlphaSettingsProto alpha_enabled"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"},
                    ]
                }]
            }
        ]},
        "policies": {
            "topOU": {
                "gemini_app_service_status": {"serviceState": "DISABLED"}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_2_1_Correct_V3 if {
    # Setting inheritance
    PolicyId := GeminiId2_1
    Output := tests with input as {
        "gemini_logs": {"items": [
            {
                "id": {"time": "2020-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GenAiAlphaSettingsProto alpha_enabled"
                        },
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GenAiAlphaSettingsProto alpha_enabled"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GenAiAlphaSettingsProto alpha_enabled"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "topOU"},
                    ]
                }]
            }
        ]},
        "policies": {
            "topOU": {
                "gemini_app_service_status": {"serviceState": "ENABLED"}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}


test_2_1_Incorrect_V1 if {
    # Alpha Gemini features enabled
    PolicyId := GeminiId2_1
    Output := tests with input as {
        "gemini_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GenAiAlphaSettingsProto alpha_enabled"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"},
                    ]
                }]
            }
        ]},
        "policies": {
            "topOU": {
                "gemini_app_service_status": {"serviceState": "ENABLED"}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul>",
        "<li>topOU: Alpha Gemini features are enabled.</li></ul>"
    ])
}

test_2_1_Incorrect_V2 if {
    # Any license allowed in group
    PolicyId := GeminiId2_1
    Output := tests with input as {
        "gemini_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GenAiAlphaSettingsProto alpha_enabled"
                        },
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GenAiAlphaSettingsProto alpha_enabled"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "GROUP_EMAIL", "value": "group1"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"}
                    ]
                }]
            }
        ]},
        "policies": {
            "topOU": {
                "gemini_app_service_status": {"serviceState": "ENABLED"}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following groups are non-compliant:<ul>",
        "<li>group1: Alpha Gemini features are enabled.</li></ul>"
    ])
}
#--
