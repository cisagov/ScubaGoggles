package commoncontrols
import future.keywords

#
# GWS.COMMONCONTROLS.2.1
#--

test_CAA_Correct_V1 if {
    # Test 1 event
    PolicyId := CommonControlsId2_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_CAA_ENABLEMENT",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ENABLED"},
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
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_CAA_Correct_V2 if {
    # Test multiple events
    PolicyId := CommonControlsId2_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_CAA_ENABLEMENT",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ENABLED"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_CAA_ENABLEMENT",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "DISABLED"},
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
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_CAA_Incorrect_V1 if {
    # Test 1 event
    PolicyId := CommonControlsId2_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_CAA_ENABLEMENT",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "DISABLED"},
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
    RuleOutput[0].ReportDetails == "Requirement not met."
}

test_CAA_Incorrect_V2 if {
    # Test multiple events
    PolicyId := CommonControlsId2_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_CAA_ENABLEMENT",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "DISABLED"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_CAA_ENABLEMENT",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ENABLED"},
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
    RuleOutput[0].ReportDetails == "Requirement not met."
}

test_CAA_Incorrect_V3 if {
    # Test no relevant events
    PolicyId := CommonControlsId2_1
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
        "No relevant event in the current logs. While we are unable ",
        "to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}
#--
