package commoncontrols
import future.keywords

#
# GWS.COMMONCONTROLS.11.1v0.1
#--

test_AllowList_Correct_V1 if {
    # Test not implemented
    PolicyId := "GWS.COMMONCONTROLS.11.1v0.1"
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
# GWS.COMMONCONTROLS.11.2v0.1
#--

test_AccessControl_Correct_V1 if {
    # Test restricted when there is no _HIGH_RISK event present
    # (not all services have a risk version, just Drive and Gmail)
    PolicyId := "GWS.COMMONCONTROLS.11.2v0.1"
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

test_AccessControl_Correct_V2 if {
    # Test allowed with not high risk allowed
    PolicyId := "GWS.COMMONCONTROLS.11.2v0.1"
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
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_AccessControl_Correct_V3 if {
    # Test restricted with not high risk disallowed
    PolicyId := "GWS.COMMONCONTROLS.11.2v0.1"
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

test_AccessControl_Correct_V4 if {
    # Test multiple services
    PolicyId := "GWS.COMMONCONTROLS.11.2v0.1"
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
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DISALLOW_SERVICE_FOR_OAUTH2_ACCESS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "OAUTH2_SERVICE_NAME", "value": "CLASSROOM"}
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
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_AccessControl_Correct_V5 if {
    # Test multiple services, multiple events
    PolicyId := "GWS.COMMONCONTROLS.11.2v0.1"
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
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
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
                        {"name": "OAUTH2_SERVICE_NAME", "value": "CLASSROOM"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "ALLOW_SERVICE_FOR_OAUTH2_ACCESS",
                    "parameters": [
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "OAUTH2_SERVICE_NAME", "value": "CLASSROOM"}
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
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_AccessControl_Incorrect_V1 if {
    # Test unrestricted when there is no _HIGH_RISK event present
    # (not all services have a risk version, just Drive and Gmail)
    PolicyId := "GWS.COMMONCONTROLS.11.2v0.1"
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

test_AccessControl_Incorrect_V2 if {
    # Test unrestricted with not high risk disallowed
    PolicyId := "GWS.COMMONCONTROLS.11.2v0.1"
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

test_AccessControl_Incorrect_V3 if {
    # Test unrestricted with no high risk version
    PolicyId := "GWS.COMMONCONTROLS.11.2v0.1"
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

test_AccessControl_Incorrect_V4 if {
    # Test no events
    PolicyId := "GWS.COMMONCONTROLS.11.2v0.1"
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
# GWS.COMMONCONTROLS.11.3v0.1
#--

test_Consent_Correct_V1 if {
    # Test disallow with no high risk version
    PolicyId := "GWS.COMMONCONTROLS.11.3v0.1"
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
    PolicyId := "GWS.COMMONCONTROLS.11.3v0.1"
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
    PolicyId := "GWS.COMMONCONTROLS.11.3v0.1"
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
    PolicyId := "GWS.COMMONCONTROLS.11.3v0.1"
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
    PolicyId := "GWS.COMMONCONTROLS.11.3v0.1"
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
    PolicyId := "GWS.COMMONCONTROLS.11.3v0.1"
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
# GWS.COMMONCONTROLS.11.4v0.1
#--
test_Internal_Correct_V1 if {
    # Test basic
    PolicyId := "GWS.COMMONCONTROLS.11.4v0.1"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs."
}

test_Internal_Correct_V2 if {
    # Test multiple events
    PolicyId := "GWS.COMMONCONTROLS.11.4v0.1"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs."
}

test_Internal_Incorrect_V1 if {
    # Test basic
    PolicyId := "GWS.COMMONCONTROLS.11.4v0.1"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement failed in Test Top-Level OU."
}

test_Internal_Incorrect_V2 if {
    # Test multiple events
    PolicyId := "GWS.COMMONCONTROLS.11.4v0.1"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement failed in Test Top-Level OU."
}

test_Internal_Incorrect_V3 if {
    # Test no events
    PolicyId := "GWS.COMMONCONTROLS.11.4v0.1"
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

#
# GWS.COMMONCONTROLS.11.5v0.1
#--

test_Unconfigured_Correct_V1 if {
    # Test basic
    PolicyId := "GWS.COMMONCONTROLS.11.5v0.1"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs."
}

test_Unconfigured_Correct_V2 if {
    # Test basic multiple events
    PolicyId := "GWS.COMMONCONTROLS.11.5v0.1"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs."
}

test_Unconfigured_Incorrect_V1 if {
    # Test unblock
    PolicyId := "GWS.COMMONCONTROLS.11.5v0.1"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement failed in Test Top-Level OU."
}

test_Unconfigured_Incorrect_V2 if {
    # Test signin only
    PolicyId := "GWS.COMMONCONTROLS.11.5v0.1"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement failed in Test Top-Level OU."
}

test_Unconfigured_Incorrect_V3 if {
    # Test no events
    PolicyId := "GWS.COMMONCONTROLS.11.5v0.1"
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