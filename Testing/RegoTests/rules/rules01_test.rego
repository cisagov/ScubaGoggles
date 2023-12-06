package rules
import future.keywords

test_Alert_Correct_V1 if {
    # 1 event
    PolicyId := "GWS.COMMONCONTROLS.15.1v0.1"
    Requirement := "Government-backed attacks"
    Output := tests with input as {
        "rules_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "SYSTEM_DEFINED_RULE_NAME",
                                "value": "Government-backed attacks"
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                                "value": "Status changed from OFF to ON."
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                                "value": "Email notification status unchanged, receivers unchanged."
                            }
                        ]
                    }
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId; Result.Requirement == Requirement]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Warnings about potential government-backed attacks."
}

test_Alert_Correct_V2 if {
    # Just a status unchanged event, but rule is default-on
    PolicyId := "GWS.COMMONCONTROLS.15.1v0.1"
    Requirement := "User-reported phishing"
    Output := tests with input as {
        "rules_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "SYSTEM_DEFINED_RULE_NAME",
                                "value": "User-reported phishing"
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                                "value": "Status unchanged."
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                                "value": concat("", [
                                    "Email notification status unchanged, receivers ",
                                    "changed from NULL to Super Admins."
                                ])
                            }
                        ]
                    }
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId; Result.Requirement == Requirement]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "A sender has sent messages to your domain that users have classified as phishings."
}

test_Alert_Correct_V3 if {
    # Multiple events, but one is a "Status unchanged." event
    PolicyId := "GWS.COMMONCONTROLS.15.1v0.1"
    Requirement := "Government-backed attacks"
    Output := tests with input as {
        "rules_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "SYSTEM_DEFINED_RULE_NAME",
                                "value": "Government-backed attacks"
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                                "value": "Status unchanged."
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                                "value": "Email notification status changed from ON to OFF."
                            }
                        ]
                    }
                ]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "SYSTEM_DEFINED_RULE_NAME",
                                "value": "Government-backed attacks"
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                                "value": "Status changed from OFF to ON."
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                                "value": "Email notification status unchanged, receivers unchanged."
                            }
                        ]
                    }
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId; Result.Requirement == Requirement]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Warnings about potential government-backed attacks."
}

test_Alert_Correct_V4 if {
    # Multiple events
    PolicyId := "GWS.COMMONCONTROLS.15.1v0.1"
    Requirement := "Government-backed attacks"
    Output := tests with input as {
        "rules_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "SYSTEM_DEFINED_RULE_NAME",
                                "value": "Government-backed attacks"
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                                "value": "Status changed from OFF to ON."
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                                "value": "Email notification status changed from ON to OFF."
                            }
                        ]
                    }
                ]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "SYSTEM_DEFINED_RULE_NAME",
                                "value": "Government-backed attacks"
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                                "value": "Status changed from ON to OFF."
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                                "value": "Email notification status unchanged, receivers unchanged."
                            }
                        ]
                    }
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId; Result.Requirement == Requirement]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Warnings about potential government-backed attacks."
}

test_Alert_Correct_V5 if {
    # no events, but default on
    PolicyId := "GWS.COMMONCONTROLS.15.1v0.1"
    Requirement := "User-reported phishing"
    Output := tests with input as {
        "rules_logs": {"items": [

        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId; Result.Requirement == Requirement]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "A sender has sent messages to your domain that users have classified as phishings."
}

test_Alert_Incorrect_V1 if {
    # 1 event
    PolicyId := "GWS.COMMONCONTROLS.15.1v0.1"
    Requirement := "Government-backed attacks"
    Output := tests with input as {
        "rules_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "SYSTEM_DEFINED_RULE_NAME",
                                "value": "Government-backed attacks"
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                                "value": "Status changed from ON to OFF."
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                                "value": "Email notification status unchanged, receivers unchanged."
                            }
                        ]
                    }
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId; Result.Requirement == Requirement]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Warnings about potential government-backed attacks."
}

test_Alert_Incorrect_V2 if {
    # 1 status unchanged event, default is off
    PolicyId := "GWS.COMMONCONTROLS.15.1v0.1"
    Requirement := "Government-backed attacks"
    Output := tests with input as {
        "rules_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "SYSTEM_DEFINED_RULE_NAME",
                                "value": "Government-backed attacks"
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                                "value": "Status unchanged."
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                                "value": "Email notification status changed from OFF to ON."
                            }
                        ]
                    }
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId; Result.Requirement == Requirement]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Warnings about potential government-backed attacks."
}

test_Alert_Incorrect_V3 if {
    # No events, default is off
    PolicyId := "GWS.COMMONCONTROLS.15.1v0.1"
    Requirement := "Government-backed attacks"
    Output := tests with input as {
        "rules_logs": {"items": [

        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId; Result.Requirement == Requirement]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Warnings about potential government-backed attacks."
}

test_Email_Correct_V1 if {
    # 1 event
    PolicyId := "GWS.COMMONCONTROLS.15.1v0.1"
    Requirement := "TLS failure"
    Output := tests with input as {
        "rules_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "SYSTEM_DEFINED_RULE_NAME",
                                "value": "TLS failure"
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                                "value": "Status unchanged."
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                                "value": "Email notification status changed from OFF to ON, receivers unchanged."
                            }
                        ]
                    }
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId; Result.Requirement == Requirement]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Messages requiring Transport Layer Security (TLS) can't be delivered."
}

test_Email_Correct_V2 if {
    # Multiple events, but one is a "Status unchanged." event
    PolicyId := "GWS.COMMONCONTROLS.15.1v0.1"
    Requirement := "TLS failure"
    Output := tests with input as {
        "rules_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "SYSTEM_DEFINED_RULE_NAME",
                                "value": "TLS failure"
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                                "value": "Status unchanged."
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                                "value": "Email notification status unchanged, receivers unchanged."
                            }
                        ]
                    }
                ]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "SYSTEM_DEFINED_RULE_NAME",
                                "value": "TLS failure"
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                                "value": "Status changed from OFF to ON."
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                                "value": "Email notification status changed from OFF to ON, receivers unchanged."
                            }
                        ]
                    }
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId; Result.Requirement == Requirement]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Messages requiring Transport Layer Security (TLS) can't be delivered."
}

test_Email_Correct_V3 if {
    # Multiple events
    PolicyId := "GWS.COMMONCONTROLS.15.1v0.1"
    Requirement := "TLS failure"
    Output := tests with input as {
        "rules_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "SYSTEM_DEFINED_RULE_NAME",
                                "value": "TLS failure"
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                                "value": "Status changed from OFF to ON."
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                                "value": "Email notification status changed from OFF to ON."
                            }
                        ]
                    }
                ]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "SYSTEM_DEFINED_RULE_NAME",
                                "value": "TLS failure"
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                                "value": "Status changed from ON to OFF."
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                                "value": "Email notification status changed from ON to OFF."
                            }
                        ]
                    }
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId; Result.Requirement == Requirement]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Messages requiring Transport Layer Security (TLS) can't be delivered."
}

test_Email_Correct_V4 if {
    # 1 event, receiver changed
    PolicyId := "GWS.COMMONCONTROLS.15.1v0.1"
    Requirement := "TLS failure"
    Output := tests with input as {
        "rules_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "SYSTEM_DEFINED_RULE_NAME",
                                "value": "TLS failure"
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                                "value": "Status unchanged."
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                                "value": concat("", [
                                    "Email notification status unchanged, receivers ",
                                    "changed from NULL to Super Admins."
                                ])
                            }
                        ]
                    }
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId; Result.Requirement == Requirement]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Messages requiring Transport Layer Security (TLS) can't be delivered."
}

test_Email_Incorrect_V1 if {
    # 1 event
    PolicyId := "GWS.COMMONCONTROLS.15.1v0.1"
    Requirement := "TLS failure"
    Output := tests with input as {
        "rules_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "SYSTEM_DEFINED_RULE_NAME",
                                "value": "TLS failure"
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                                "value": "Status changed from ON to OFF."
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                                "value": "Email notification status changed from ON to OFF"
                            }
                        ]
                    }
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId; Result.Requirement == Requirement]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Messages requiring Transport Layer Security (TLS) can't be delivered."
}

test_Email_Incorrect_V2 if {
    # 1 status unchanged event, default is off
    PolicyId := "GWS.COMMONCONTROLS.15.1v0.1"
    Requirement := "TLS failure"
    Output := tests with input as {
        "rules_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "SYSTEM_DEFINED_RULE_NAME",
                                "value": "TLS failure"
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE",
                                "value": "Status unchanged."
                            },
                            {
                                "name": "SYSTEM_DEFINED_RULE_ACTION_RECEIVERS_CHANGE",
                                "value": "Email notification status unchanged, receivers unchanged."
                            }
                        ]
                    }
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId; Result.Requirement == Requirement]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Messages requiring Transport Layer Security (TLS) can't be delivered."
}

test_Email_Incorrect_V3 if {
    # No events, default is off
    PolicyId := "GWS.COMMONCONTROLS.15.1v0.1"
    Requirement := "TLS failure"
    Output := tests with input as {
        "rules_logs": {"items": [

        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId; Result.Requirement == Requirement]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Messages requiring Transport Layer Security (TLS) can't be delivered."
}

