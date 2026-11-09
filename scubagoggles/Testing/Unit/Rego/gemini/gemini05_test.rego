package gemini
import future.keywords

import data.utils.FailTestGroupNonCompliant
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant

#
# GWS.GEMINI.5.1
#--
test_5_1_Correct_V1 if {
    # Personal avatars disabled for the top-level OU
    PolicyId := GeminiId5_1
    Output := tests with input as {
        "gemini_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "VidsLikeness enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_5_1_Correct_V2 if {
    # Most recent event disables personal avatars
    PolicyId := GeminiId5_1
    Output := tests with input as {
        "gemini_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "VidsLikeness enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "VidsLikeness enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_5_1_Correct_V3 if {
    # Deleted sub-OU setting inherits the compliant top-level OU value
    PolicyId := GeminiId5_1
    Output := tests with input as {
        "gemini_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "VidsLikeness enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "VidsLikeness enabled"},
                        {"name": "ORG_UNIT_NAME", "value": "subOU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_5_1_Incorrect_V1 if {
    # Personal avatars enabled for the top-level OU
    PolicyId := GeminiId5_1
    Output := tests with input as {
        "gemini_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "VidsLikeness enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    failedOU := [{"Name": "topOU",
                  "Value": "Personal avatars in Google Vids are enabled."}]

    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_5_1_Incorrect_V2 if {
    # No events; personal avatars are on by default
    PolicyId := GeminiId5_1
    Output := tests with input as {
        "gemini_logs": {"items": []},
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    FailTestNoEvent(PolicyId, Output, "topOU", false)
}

test_5_1_Incorrect_V3 if {
    # Disabled for the top-level OU but enabled for a sub-OU
    PolicyId := GeminiId5_1
    Output := tests with input as {
        "gemini_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "VidsLikeness enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "VidsLikeness enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "subOU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    failedOU := [{"Name": "subOU",
                  "Value": "Personal avatars in Google Vids are enabled."}]

    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_5_1_Incorrect_V4 if {
    # Enabled for a group
    PolicyId := GeminiId5_1
    Output := tests with input as {
        "gemini_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "VidsLikeness enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "VidsLikeness enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "GROUP_EMAIL", "value": "group1"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    failedGroup := [{"Name": "group1",
                     "Value": "Personal avatars in Google Vids are enabled."}]

    FailTestGroupNonCompliant(PolicyId, Output, failedGroup)
}

test_5_1_Incorrect_V5 if {
    # Deleting the top-level OU setting reverts to the default (enabled)
    PolicyId := GeminiId5_1
    Output := tests with input as {
        "gemini_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "VidsLikeness enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "VidsLikeness enabled"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    failedOU := [{"Name": "topOU",
                  "Value": "Personal avatars in Google Vids are enabled."}]

    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_5_1_Incorrect_V6 if {
    # Event sequence captured from a live tenant: set OFF, then back ON
    PolicyId := GeminiId5_1
    Output := tests with input as {
        "gemini_logs": {"items": [
            {
                "id": {"time": "2026-10-28T17:02:39.572Z"},
                "events": [{
                    "name": "CREATE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "APPLICATION_NAME", "value": "Drive and Editors GenAI"},
                        {"name": "SETTING_NAME", "value": "VidsLikeness enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"},
                    ]
                }]
            },
            {
                "id": {"time": "2026-10-28T17:02:48.294Z"},
                "events": [{
                    "name": "CHANGE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "APPLICATION_NAME", "value": "Drive and Editors GenAI"},
                        {"name": "SETTING_NAME", "value": "VidsLikeness enabled"},
                        {"name": "OLD_VALUE", "value": "false"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "topOU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    failedOU := [{"Name": "topOU",
                  "Value": "Personal avatars in Google Vids are enabled."}]

    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--
