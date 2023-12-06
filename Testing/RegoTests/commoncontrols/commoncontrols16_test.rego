package commoncontrols
import future.keywords

#
# GWS.COMMONCONTROLS.16.1v0.1
#--
test_Logs_Correct_V1 if {
    # Test 1 event
    PolicyId := "GWS.COMMONCONTROLS.16.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ENABLED"},
                        {
                            "name": "SETTING_NAME",
                            "value": "Data Sharing Settings between GCP and Google Workspace \"Sharing Options\""
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
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

test_Logs_Correct_V2 if {
    # Test multiple events
    PolicyId := "GWS.COMMONCONTROLS.16.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ENABLED"},
                        {
                            "name": "SETTING_NAME",
                            "value": "Data Sharing Settings between GCP and Google Workspace \"Sharing Options\""
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "DISABLED"},
                        {
                            "name": "SETTING_NAME",
                            "value": "Data Sharing Settings between GCP and Google Workspace \"Sharing Options\""
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
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

test_Logs_Incorrect_V1 if {
    # Test 1 event
    PolicyId := "GWS.COMMONCONTROLS.16.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "DISABLED"},
                        {
                            "name": "SETTING_NAME",
                            "value": "Data Sharing Settings between GCP and Google Workspace \"Sharing Options\""
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
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

test_Logs_Incorrect_V2 if {
    # Test multiple events
    PolicyId := "GWS.COMMONCONTROLS.16.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "DISABLED"},
                        {
                            "name": "SETTING_NAME",
                            "value": "Data Sharing Settings between GCP and Google Workspace \"Sharing Options\""
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ENABLED"},
                        {
                            "name": "SETTING_NAME",
                            "value": "Data Sharing Settings between GCP and Google Workspace \"Sharing Options\""
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
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

test_Logs_Incorrect_V3 if {
    # Test no relevent events
    PolicyId := "GWS.COMMONCONTROLS.16.1v0.1"
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
    ])
}
#--

#
# GWS.COMMONCONTROLS.16.2v0.1
#--
test_AccessControl_Correct_V1 if {
    # Test not implemented
    PolicyId := "GWS.COMMONCONTROLS.16.2v0.1"
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
    RuleOutput[0].ReportDetails == "Currently not able to be tested automatically; please manually check."
}
#--
