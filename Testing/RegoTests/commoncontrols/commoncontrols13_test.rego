package commoncontrols
import future.keywords

#
# GWS.COMMONCONTROLS.13.1v0.1
#--

test_Access_Correct_V1 if {
    # Test 1 event
    PolicyId := "GWS.COMMONCONTROLS.13.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "WEAK_PROGRAMMATIC_LOGIN_SETTINGS_CHANGED",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "DENIED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"}
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

test_Access_Correct_V2 if {
    # Test multiple events
    PolicyId := "GWS.COMMONCONTROLS.13.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "WEAK_PROGRAMMATIC_LOGIN_SETTINGS_CHANGED",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "DENIED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "WEAK_PROGRAMMATIC_LOGIN_SETTINGS_CHANGED",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"}
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

test_Access_Incorrect_V1 if {
    # Test 1 event
    PolicyId := "GWS.COMMONCONTROLS.13.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "WEAK_PROGRAMMATIC_LOGIN_SETTINGS_CHANGED",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"}
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
    RuleOutput[0].ReportDetails == "Requirement failed in Test Top-Level OU."
}

test_Access_Incorrect_V2 if {
    # Test multiple events
    PolicyId := "GWS.COMMONCONTROLS.13.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "WEAK_PROGRAMMATIC_LOGIN_SETTINGS_CHANGED",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "WEAK_PROGRAMMATIC_LOGIN_SETTINGS_CHANGED",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "DENIED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"}
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
    RuleOutput[0].ReportDetails == "Requirement failed in Test Top-Level OU."
}

test_Access_Incorrect_V3 if {
    # Test no relevant events
    PolicyId := "GWS.COMMONCONTROLS.13.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [

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
        "No relevant event in the current logs for the top-level OU, ",
        "Test Top-Level OU. While we are unable ",
        "to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])}

test_Access_Incorrect_V4 if {
    # Test no relevant events in top-level OU
    PolicyId := "GWS.COMMONCONTROLS.13.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "WEAK_PROGRAMMATIC_LOGIN_SETTINGS_CHANGED",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "DENIED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"}
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
        "No relevant event in the current logs for the top-level OU, ",
        "Test Top-Level OU. While we are unable ",
        "to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])}

test_Access_Incorrect_V5 if {
    # Test multiple OUs
    PolicyId := "GWS.COMMONCONTROLS.13.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "WEAK_PROGRAMMATIC_LOGIN_SETTINGS_CHANGED",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "WEAK_PROGRAMMATIC_LOGIN_SETTINGS_CHANGED",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "DENIED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"}
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
    RuleOutput[0].ReportDetails == "Requirement failed in Test Second-Level OU."
}
#--