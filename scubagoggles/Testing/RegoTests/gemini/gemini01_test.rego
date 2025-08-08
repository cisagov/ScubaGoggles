package gemini
import future.keywords

#
# GWS.GEMINI.1.1
#--
test_1_1_Correct_V1 if {
    PolicyId := GeminiId1_1
    Output := tests with input as {
        "gemini_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "BardNonDuetEnablementProto enable_bard_non_duet_access"
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

test_1_1_Correct_V2 if {
    # Any license allowed but Gemini disabled for OU
    PolicyId := GeminiId1_1
    Output := tests with input as {
        "gemini_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "BardNonDuetEnablementProto enable_bard_non_duet_access"
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

test_1_1_Correct_V3 if {
    # Any inheritance
    PolicyId := GeminiId1_1
    Output := tests with input as {
        "gemini_logs": {"items": [
            {
                "id": {"time": "2020-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "BardNonDuetEnablementProto enable_bard_non_duet_access"
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
                            "value": "BardNonDuetEnablementProto enable_bard_non_duet_access"
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
                            "value": "BardNonDuetEnablementProto enable_bard_non_duet_access"
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


test_1_1_Incorrect_V1 if {
    # Any license allowed
    PolicyId := GeminiId1_1
    Output := tests with input as {
        "gemini_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "BardNonDuetEnablementProto enable_bard_non_duet_access"
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
        "<li>topOU: Gemini access regardless of license is enabled.</li></ul>"
    ])
}

test_1_1_Incorrect_V2 if {
    # Any license allowed in group
    PolicyId := GeminiId1_1
    Output := tests with input as {
        "gemini_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "BardNonDuetEnablementProto enable_bard_non_duet_access"
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
                            "value": "BardNonDuetEnablementProto enable_bard_non_duet_access"
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
        "<li>group1: Gemini access regardless of license is enabled.</li></ul>"
    ])
}
#--
