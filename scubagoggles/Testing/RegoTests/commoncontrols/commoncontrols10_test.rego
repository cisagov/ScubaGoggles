package commoncontrols

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.COMMONCONTROLS.10.1
#--

test_AccessControl_Correct_V1 if {
    # Test not implemented
    PolicyId := CommonControlsId10_1
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

#
# GWS.COMMONCONTROLS.10.2
#--
test_Consent_Correct_V1 if {
    # Test disallow with no high risk version
    PolicyId := CommonControlsId10_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DISALLOW_SERVICE_FOR_OAUTH2_ACCESS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "OAUTH2_SERVICE_NAME", "value": "CLASSROOM"}
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
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_Consent_Correct_V2 if {
    # Test disallow with high risk version
    PolicyId := CommonControlsId10_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DISALLOW_SERVICE_FOR_OAUTH2_ACCESS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "OAUTH2_SERVICE_NAME", "value": "DRIVE"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ALLOW_SERVICE_FOR_OAUTH2_ACCESS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "OAUTH2_SERVICE_NAME", "value": "DRIVE_HIGH_RISK"}
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
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_Consent_Incorrect_V1 if {
    # Test allow with no high risk version
    PolicyId := CommonControlsId10_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ALLOW_SERVICE_FOR_OAUTH2_ACCESS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "OAUTH2_SERVICE_NAME", "value": "CLASSROOM"}
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
    RuleOutput[0].ReportDetails == "The following services allow access: CLASSROOM."
}

test_Consent_Incorrect_V2 if {
    # Test allow with high risk version allowed
    PolicyId := CommonControlsId10_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ALLOW_SERVICE_FOR_OAUTH2_ACCESS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "OAUTH2_SERVICE_NAME", "value": "DRIVE"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ALLOW_SERVICE_FOR_OAUTH2_ACCESS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "OAUTH2_SERVICE_NAME", "value": "DRIVE_HIGH_RISK"}
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
    RuleOutput[0].ReportDetails == "The following services allow access: DRIVE."
}

test_Consent_Incorrect_V3 if {
    # Test allow with high risk version blocked
    PolicyId := CommonControlsId10_2
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ALLOW_SERVICE_FOR_OAUTH2_ACCESS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "OAUTH2_SERVICE_NAME", "value": "DRIVE"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DISALLOW_SERVICE_FOR_OAUTH2_ACCESS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "OAUTH2_SERVICE_NAME", "value": "DRIVE_HIGH_RISK"}
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
    RuleOutput[0].ReportDetails == "The following services allow access: DRIVE."
}

test_Consent_Incorrect_V4 if {
    # Test no events
    PolicyId := CommonControlsId10_2
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
        "No API Access Allowed/Blocked events in the current logs. ",
        "While we are unable ",
        "to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])}
#--

#
# GWS.COMMONCONTROLS.10.3
#--
test_Internal_Correct_V1 if {
    # Test basic
    PolicyId := CommonControlsId10_3
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "UNTRUST_DOMAIN_OWNED_OAUTH2_APPS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_Internal_Correct_V2 if {
    # Test multiple events
    PolicyId := CommonControlsId10_3
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "UNTRUST_DOMAIN_OWNED_OAUTH2_APPS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TRUST_DOMAIN_OWNED_OAUTH2_APPS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_Internal_Incorrect_V1 if {
    # Test basic
    PolicyId := CommonControlsId10_3
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TRUST_DOMAIN_OWNED_OAUTH2_APPS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                  "Value": "Trust internal apps is ON"}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Internal_Incorrect_V2 if {
    # Test multiple events
    PolicyId := CommonControlsId10_3
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "TRUST_DOMAIN_OWNED_OAUTH2_APPS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "UNTRUST_DOMAIN_OWNED_OAUTH2_APPS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                  "Value": "Trust internal apps is ON"}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Internal_Incorrect_V3 if {
    # Test no events
    PolicyId := CommonControlsId10_3
    Output := tests with input as {
        "commoncontrols_logs": {"items": [

        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}
#--

#
# GWS.COMMONCONTROLS.10.4
#--
test_Unconfigured_Correct_V1 if {
    # Test basic
    PolicyId := CommonControlsId10_4
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "BLOCK_ALL_THIRD_PARTY_API_ACCESS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_Unconfigured_Correct_V2 if {
    # Test basic multiple events
    PolicyId := CommonControlsId10_4
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "BLOCK_ALL_THIRD_PARTY_API_ACCESS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "UNBLOCK_ALL_THIRD_PARTY_API_ACCESS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_Unconfigured_Incorrect_V1 if {
    # Test unblock
    PolicyId := CommonControlsId10_4
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "UNBLOCK_ALL_THIRD_PARTY_API_ACCESS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    msg := sprintf("Unconfigured third-party app access is set to %s",
                   ["Allow users to access any third-party apps"])
    failedOU := [{"Name": "Test Top-Level OU",
                  "Value": msg}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Unconfigured_Incorrect_V2 if {
    # Test signin only
    PolicyId := CommonControlsId10_4
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "SIGN_IN_ONLY_THIRD_PARTY_API_ACCESS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    msg := sprintf("Unconfigured third-party app access is set to %s %s",
                   ["Allow users to access third-party apps that only",
                    "request basic info needed for Sign in with Google."])
    failedOU := [{"Name": "Test Top-Level OU",
                  "Value": msg}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Unconfigured_Incorrect_V3 if {
    # Test no events
    PolicyId := CommonControlsId10_4
    Output := tests with input as {
        "commoncontrols_logs": {"items": [

        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}
#--
