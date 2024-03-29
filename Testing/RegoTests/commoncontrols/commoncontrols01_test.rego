package commoncontrols
import future.keywords

#
# GWS.COMMONCONTROLS.1.1v0.1
#--
test_EnforceMFA_Correct_V1 if {
    # Test enforcing MFA when there's only one event
    PolicyId := "GWS.COMMONCONTROLS.1.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ALLOW_STRONG_AUTHENTICATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ENFORCE_STRONG_AUTHENTICATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
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

test_EnforceMFA_Correct_V2 if {
    # Test enforcing MFA when there's multiple events, with the chronological latest
    # correct but not last in json list
    PolicyId := "GWS.COMMONCONTROLS.1.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ENFORCE_STRONG_AUTHENTICATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ALLOW_STRONG_AUTHENTICATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ENFORCE_STRONG_AUTHENTICATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
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

test_EnforceMFA_Incorrect_V1 if {
    # Test enforcing MFA when there's only one event and it's wrong
    PolicyId := "GWS.COMMONCONTROLS.1.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ENFORCE_STRONG_AUTHENTICATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ALLOW_STRONG_AUTHENTICATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
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
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul>",
        "<li>Test Top-Level OU: 2-Step Verification Enforcement is OFF</li>",
        "</ul>"
    ])
}

test_EnforceMFA_Incorrect_V2 if {
    # Test enforcing MFA when there's multiple events, with the chronological latest
    # incorrect but not last in json list
    PolicyId := "GWS.COMMONCONTROLS.1.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ENFORCE_STRONG_AUTHENTICATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ENFORCE_STRONG_AUTHENTICATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ALLOW_STRONG_AUTHENTICATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
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
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul>",
        "<li>Test Top-Level OU: 2-Step Verification Enforcement is OFF</li>",
        "</ul>"
    ])
}


test_EnforceMFA_Incorrect_V3 if {
    # Test enforcing MFA when there's no enforce mfa event
    PolicyId := "GWS.COMMONCONTROLS.1.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS",
                    "parameters": [
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
        "No relevant event in the current logs for the top-level OU, ",
        "Test Top-Level OU. While we are unable ",
        "to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])}

test_EnforceMFA_Incorrect_V4 if {
    # Test enforcing MFA when there's no change methods event
    PolicyId := "GWS.COMMONCONTROLS.1.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ENFORCE_STRONG_AUTHENTICATION",
                    "parameters": [
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
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, ",
        "Test Top-Level OU. While we are unable ",
        "to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

test_EnforceMFA_Incorrect_V5 if {
    # Test, mfa not allowed
    PolicyId := "GWS.COMMONCONTROLS.1.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ENFORCE_STRONG_AUTHENTICATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ALLOW_STRONG_AUTHENTICATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
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
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul>",
        "<li>Test Top-Level OU: Allow users to turn on 2-Step Verification is OFF</li>",
        "</ul>"
    ])
}

test_EnforceMFA_Incorrect_V6 if {
    # Test, mfa not phishing resistant
    PolicyId := "GWS.COMMONCONTROLS.1.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ENFORCE_STRONG_AUTHENTICATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ALLOW_STRONG_AUTHENTICATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS",
                    "parameters": [
                        {
                            "name": "ALLOWED_TWO_STEP_VERIFICATION_METHOD",
                            "value": "NO_TELEPHONY"
                        },
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
        "<li>Test Top-Level OU: Allowed methods is set to Any except verification codes via text, phone call</li>",
        "</ul>"
    ])
}

test_EnforceMFA_Incorrect_V7 if {
    # Test, mfa not phishing resistant
    PolicyId := "GWS.COMMONCONTROLS.1.1v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ENFORCE_STRONG_AUTHENTICATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ALLOW_STRONG_AUTHENTICATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS",
                    "parameters": [
                        {
                            "name": "ALLOWED_TWO_STEP_VERIFICATION_METHOD",
                            "value": "NO_TELEPHONY"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS",
                    "parameters": [
                        {
                            "name": "ALLOWED_TWO_STEP_VERIFICATION_METHOD",
                            "value": "NO_TELEPHONY"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "GROUP_EMAIL", "value": "test@test.com"}
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
        "<li>Test Top-Level OU: Allowed methods is set to Any except verification codes via text, phone call</li>",
        "</ul>",
        "<br>",
        "The following groups are non-compliant:<ul>",
        "<li>test@test.com: Allowed methods is set to Any except verification codes via text, phone call</li>",
        "</ul>",     
    ])
}
#--

#
# GWS.COMMONCONTROLS.1.2v0.1
#--
test_Enforcement_Correct_V1 if {
    # Test enforcing MFA when there's only one event
    PolicyId := "GWS.COMMONCONTROLS.1.2v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT_PERIOD_DURATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "1 week"},
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

test_Enforcement_Correct_V2 if {
    # Test enforcing MFA when there's multiple events, with the chronological latest
    # correct but not last in json list
    PolicyId := "GWS.COMMONCONTROLS.1.2v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT_PERIOD_DURATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "1 week"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ENFORCE_STRONG_AUTHENTICATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "1 day"},
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

test_Enforcement_Correct_V3 if {
    # Test enforcing MFA inheritance
    PolicyId := "GWS.COMMONCONTROLS.1.2v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT_PERIOD_DURATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "1 week"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT_PERIOD_DURATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "2 weeks"},
                        {"name": "ORG_UNIT_NAME", "value": "Second OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2023-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT_PERIOD_DURATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "INHERIT_FROM_PARENT"},
                        {"name": "ORG_UNIT_NAME", "value": "Second OU"},
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

test_Enforcement_Incorrect_V1 if {
    # Test enforcing MFA when there's only one event and it's wrong
    PolicyId := "GWS.COMMONCONTROLS.1.2v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT_PERIOD_DURATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "2 weeks"},
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
        "<li>Test Top-Level OU: New user enrollment period is set to 2 weeks</li>",
        "</ul>"
    ])
}

test_Enforcement_Incorrect_V2 if {
    # Test enforcing MFA when there's multiple events, with the chronological latest
    # incorrect but not last in json list
    PolicyId := "GWS.COMMONCONTROLS.1.2v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT_PERIOD_DURATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "2 weeks"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT_PERIOD_DURATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "1 week"},
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
        "<li>Test Top-Level OU: New user enrollment period is set to 2 weeks</li>",
        "</ul>"
    ])
}


test_Enforcement_Incorrect_V3 if {
    # Test enforcing MFA when there no applicable event
    PolicyId := "GWS.COMMONCONTROLS.1.2v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "SOMETHING_ELSE",
                    "parameters": [
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
        "No relevant event in the current logs for the top-level OU, ",
        "Test Top-Level OU. While we are unable ",
        "to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

#
# GWS.COMMONCONTROLS.1.4v0.1
#--
test_Disable_Trusted_Device_Correct_V1 if {
    # Test disable trusted device when there's only one event
    PolicyId := "GWS.COMMONCONTROLS.1.3v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_TWO_STEP_VERIFICATION_FREQUENCY",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "DISABLE_USERS_TO_TRUST_DEVICE"},
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

test_Disable_Trusted_Device_Correct_V2 if {
    # Test disabled trusted device when there's multiple events, with the chronological latest
    # correct but not last in json list
    PolicyId := "GWS.COMMONCONTROLS.1.3v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_TWO_STEP_VERIFICATION_FREQUENCY",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "DISABLE_USERS_TO_TRUST_DEVICE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT_PERIOD_DURATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ENABLE_USERS_TO_TRUST_DEVICE"},
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

test_Disable_Trusted_Device_Incorrect_V1 if {
    # Test disable trusted device when there's only one event and it's wrong
    PolicyId := "GWS.COMMONCONTROLS.1.3v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_TWO_STEP_VERIFICATION_FREQUENCY",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ENABLE_USERS_TO_TRUST_DEVICE"},
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
        "<li>Test Top-Level OU: Allow user to trust the device is ON</li>",
        "</ul>"
    ])
}

test_Disable_Trusted_Device_Incorrect_V2 if {
    # Test disabled trusted device when there's multiple events, with the chronological latest
    # incorrect but not last in json list
    PolicyId := "GWS.COMMONCONTROLS.1.3v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_TWO_STEP_VERIFICATION_FREQUENCY",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ENABLE_USERS_TO_TRUST_DEVICE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT_PERIOD_DURATION",
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "DISABLE_USERS_TO_TRUST_DEVICE"},
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
        "<li>Test Top-Level OU: Allow user to trust the device is ON</li>",
        "</ul>"
    ])
}


test_Disable_Trusted_Device_Incorrect_V3 if {
    # Test disabled trusted device when there no applicable event
    PolicyId := "GWS.COMMONCONTROLS.1.3v0.1"
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "SOMETHING_ELSE",
                    "parameters": [
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
        "No relevant event in the current logs for the top-level OU, ",
        "Test Top-Level OU. While we are unable ",
        "to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}
#--

#
# GWS.COMMONCONTROLS.1.4v0.1
#--

test_NotPhone_Correct_V1 if {
    # Test enforcing MFA when there's only one event set to only key
    PolicyId := "GWS.COMMONCONTROLS.1.4v0.1"
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
    PolicyId := "GWS.COMMONCONTROLS.1.4v0.1"
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
    PolicyId := "GWS.COMMONCONTROLS.1.4v0.1"
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
    PolicyId := "GWS.COMMONCONTROLS.1.4v0.1"
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
    PolicyId := "GWS.COMMONCONTROLS.1.4v0.1"
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
    PolicyId := "GWS.COMMONCONTROLS.1.4v0.1"
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
    PolicyId := "GWS.COMMONCONTROLS.1.4v0.1"
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
    PolicyId := "GWS.COMMONCONTROLS.1.4v0.1"
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