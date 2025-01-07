package commoncontrols
import future.keywords

#
# GWS.COMMONCONTROLS.1.4
#--

test_NotPhone_Correct_V1 if {
    # Test enforcing MFA when there's only one event set to only key
    PolicyId := CommonControlsId1_4
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS",
                    "parameters": [
                        {"name": "ALLOWED_TWO_STEP_VERIFICATION_METHOD", "value": "ONLY_SECURITY_KEY"},
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

test_NotPhone_Correct_V2 if {
    # Test enforcing MFA when there's only one event set to any except phone
    PolicyId := CommonControlsId1_4
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS",
                    "parameters": [
                        {"name": "ALLOWED_TWO_STEP_VERIFICATION_METHOD", "value": "NO_TELEPHONY"},
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

test_NotPhone_Correct_V3 if {
    # Test enforcing MFA when there are multiple events
    PolicyId := CommonControlsId1_4
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS",
                    "parameters": [
                        {"name": "ALLOWED_TWO_STEP_VERIFICATION_METHOD", "value": "NO_TELEPHONY"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS",
                    "parameters": [
                        {"name": "ALLOWED_TWO_STEP_VERIFICATION_METHOD", "value": "ANY"},
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

test_NotPhone_Incorrect_V1 if {
    # Test enforcing MFA when there's only one event set to any
    PolicyId := CommonControlsId1_4
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS",
                    "parameters": [
                        {"name": "ALLOWED_TWO_STEP_VERIFICATION_METHOD", "value": "ANY"},
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
        "<li>Test Top-Level OU: Allowed methods is set to Any</li>",
        "</ul>"
    ])
}

test_NotPhone_Incorrect_V2 if {
    # Test enforcing MFA when there's multiple events
    PolicyId := CommonControlsId1_4
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS",
                    "parameters": [
                        {"name": "ALLOWED_TWO_STEP_VERIFICATION_METHOD", "value": "ONLY_SECURITY_KEY"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS",
                    "parameters": [
                        {"name": "ALLOWED_TWO_STEP_VERIFICATION_METHOD", "value": "ANY"},
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
        "<li>Test Top-Level OU: Allowed methods is set to Any</li>",
        "</ul>"
    ])
}

test_NotPhone_Incorrect_V3 if {
    # Test enforcing MFA when there are no relevant events
    PolicyId := CommonControlsId1_4
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
#--

test_NotPhone_Incorrect_V4 if {
    # Test enforcing MFA when there are no relevant events for the top-level OU
    PolicyId := CommonControlsId1_4
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS",
                    "parameters": [
                        {"name": "ALLOWED_TWO_STEP_VERIFICATION_METHOD", "value": "ONLY_SECURITY_KEY"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
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
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, ",
        "Test Top-Level OU. While we are unable ",
        "to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])}

test_NotPhone_Correct_V5 if {
    # Test enforcing MFA when there are multiple OUs
    PolicyId := CommonControlsId1_4
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS",
                    "parameters": [
                        {"name": "ALLOWED_TWO_STEP_VERIFICATION_METHOD", "value": "NO_TELEPHONY"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS",
                    "parameters": [
                        {"name": "ALLOWED_TWO_STEP_VERIFICATION_METHOD", "value": "ANY"},
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
        "<li>Test Top-Level OU: Allowed methods is set to Any</li>",
        "</ul>"
    ])
}
#--
