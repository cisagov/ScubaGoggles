package commoncontrols
import future.keywords

#
# GWS.COMMONCONTROLS.16.1v0.2
#--

test_Unlisted_Correct_V1 if {
    # Test 1 event
    PolicyId := "GWS.COMMONCONTROLS.16.1v0.2"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "DISABLE_UNLISTED_SERVICES"},
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

test_Unlisted_Correct_V2 if {
    # Test inheritance
    PolicyId := "GWS.COMMONCONTROLS.16.1v0.2"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "DISABLE_UNLISTED_SERVICES"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "DISABLE_UNLISTED_SERVICES"},
                        {"name": "NEW_VALUE", "value": "INHERIT_FROM_PARENT"},
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

test_Unlisted_Incorrect_V1 if {
    PolicyId := "GWS.COMMONCONTROLS.16.1v0.2"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TOGGLE_SERVICE_ENABLED",
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "DISABLE_UNLISTED_SERVICES"},
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
        "<li>Test Top-Level OU: Access to additional services without individual control is turned on</li>",
        "</ul>"
    ])
}

test_Unlisted_Incorrect_V2 if {
    # Test no events
    PolicyId := "GWS.COMMONCONTROLS.16.1v0.2"
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
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. While we are unable ",
        "to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}
#--