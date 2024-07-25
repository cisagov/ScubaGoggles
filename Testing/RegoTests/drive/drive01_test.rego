package drive
import future.keywords

#
# GWS.DRIVEDOCS.1.1v0.2
#--
test_Sharing_Correct_V1 if {
    # Test sharing setting when there's only one event
    PolicyId := "GWS.DRIVEDOCS.1.1v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_Sharing_Correct_V2 if {
    # Test sharing setting when there's multiple events and the most most recent is correct
    PolicyId := "GWS.DRIVEDOCS.1.1v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_Sharing_Correct_V3 if {
    # Test sharing setting when there's multiple OUs
    PolicyId := "GWS.DRIVEDOCS.1.1v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
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

test_Sharing_Incorrect_V1 if {
    # Test sharing setting when there are no relevant events
    PolicyId := "GWS.DRIVEDOCS.1.1v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

test_Sharing_Incorrect_V2 if {
    # Test sharing setting when there's only one event and it's wrong
    PolicyId := "GWS.DRIVEDOCS.1.1v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Top-Level OU: ",
    "Files owned by users or shared drives can ",
    "be shared outside of the organization</li></ul>"])
}

test_Sharing_Incorrect_V3 if {
    # Test sharing setting when there are multiple events and the most recent is wrong
    PolicyId := "GWS.DRIVEDOCS.1.1v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Top-Level OU: ",
    "Files owned by users or shared drives can ",
    "be shared outside of the organization</li></ul>"])
}

test_Sharing_Incorrect_V4 if {
    # Test sharing setting when there are multiple OUs and secondary is wrong
    PolicyId := "GWS.DRIVEDOCS.1.1v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Secondary OU: ",
    "Files owned by users or shared drives can ",
    "be shared outside of the organization</li></ul>"])
}

test_Sharing_Incorrect_V5 if {
    # Test sharing setting when the top OU is not present but there is another
    PolicyId := "GWS.DRIVEDOCS.1.1v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}
#--

#
# GWS.DRIVEDOCS.1.2v0.2
#--
test_Receiving_Correct_V1 if {
    # Test sharing setting when there's only one event
    PolicyId := "GWS.DRIVEDOCS.1.2v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_Receiving_Correct_V2 if {
    # Test sharing setting when there's multiple events and the most most recent is correct
    PolicyId := "GWS.DRIVEDOCS.1.2v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_Receiving_Correct_V3 if {
    # Test sharing setting when there's multiple OUs
    PolicyId := "GWS.DRIVEDOCS.1.2v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
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

test_Receiving_Incorrect_V1 if {
    # Test sharing setting when there are no relevant events
    PolicyId := "GWS.DRIVEDOCS.1.2v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

test_Receiving_Incorrect_V2 if {
    # Test sharing setting when there's only one event and it's wrong
    PolicyId := "GWS.DRIVEDOCS.1.2v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Top-Level OU: Users can recieve files outside the domain</li></ul>"])
}

test_Receiving_Incorrect_V3 if {
    # Test sharing setting when there are multiple events and the most recent is wrong
    PolicyId := "GWS.DRIVEDOCS.1.2v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Top-Level OU: Users can recieve files outside the domain</li></ul>"])

}

test_Receiving_Incorrect_V4 if {
    # Test sharing setting when there are multiple OUs, top OU is compliant but secondary isn't
    PolicyId := "GWS.DRIVEDOCS.1.2v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Secondary OU: Users can recieve files outside the domain</li></ul>"])
}

test_Receiving_Incorrect_V5 if {
    # Test sharing setting when top level OU is not present
    PolicyId := "GWS.DRIVEDOCS.1.2v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

#
# GWS.DRIVEDOCS.1.3v0.2
#--
test_Warnings_Correct_V1 if {
    # Test sharing setting when there's only one event
    PolicyId := "GWS.DRIVEDOCS.1.3v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_Warnings_Correct_V2 if {
    # Test sharing setting when there's multiple events and the most most recent is correct
    PolicyId := "GWS.DRIVEDOCS.1.3v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_Warnings_Correct_V3 if {
    # Test sharing setting when there's multiple OUs
    PolicyId := "GWS.DRIVEDOCS.1.3v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
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

test_Warnings_Incorrect_V1 if {
    # Test sharing setting when there are no relevant events
    PolicyId := "GWS.DRIVEDOCS.1.3v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

test_Warnings_Incorrect_V2 if {
    # Test sharing setting when there's only one event and it's wrong
    PolicyId := "GWS.DRIVEDOCS.1.3v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Top-Level OU: External Sharing Warning is Disabled</li></ul>"])
}

test_Warningsr_Incorrect_V3 if {
    # Test sharing setting when there are multiple events and the most recent is wrong
    PolicyId := "GWS.DRIVEDOCS.1.3v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Top-Level OU: External Sharing Warning is Disabled</li></ul>"])
}

test_Warnings_Incorrect_V4 if {
    # Test sharing setting when Top OU is correct but not secondary OU
    PolicyId := "GWS.DRIVEDOCS.1.3v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Secondary OU: External Sharing Warning is Disabled</li></ul>"])
}

test_Warnings_Incorrect_V5 if {
    # Test sharing setting when Top OU is not present
    PolicyId := "GWS.DRIVEDOCS.1.3v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2021-27-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

#
# GWS.DRIVEDOCS.1.4v0.2
#--
test_NonGoogle_Correct_V1 if {
    # Test sharing setting when there's only one event
    PolicyId := "GWS.DRIVEDOCS.1.4v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_NonGoogle_Correct_V2 if {
    # Test sharing setting when there's multiple events and the most most recent is correct
    PolicyId := "GWS.DRIVEDOCS.1.4v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_NonGoogle_Correct_V3 if {
    # Test sharing setting when there's multiple OUs
    PolicyId := "GWS.DRIVEDOCS.1.4v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
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
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_NonGoogle_Incorrect_V1 if {
    # Test sharing setting when there are no relevant events
    PolicyId := "GWS.DRIVEDOCS.1.4v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

test_NonGoogle_Incorrect_V2 if {
    # Test sharing setting when there's only one event and it's wrong
    PolicyId := "GWS.DRIVEDOCS.1.4v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "ANONYMOUS_PREVIEW"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Top-Level OU: ",
    "External sharing is enabled and ",
    "items can be shared to non-google accounts</li></ul>"])
}

test_NonGoogle_Incorrect_V3 if {
    # Test sharing setting when there are multiple events and the most recent is wrong
    PolicyId := "GWS.DRIVEDOCS.1.4v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "ANONYMOUS_PREVIEW"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-13-23T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-14-24T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Top-Level OU: ",
    "External sharing is enabled and ",
    "items can be shared to non-google accounts</li></ul>"])
}

test_NonGoogle_Incorrect_V4 if {
    # Test sharing setting when Top OU is correct but not secondary OU
    PolicyId := "GWS.DRIVEDOCS.1.4v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-24T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHARING_NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Secondary OU: ",
    "External sharing is enabled and ",
    "items can be shared to non-google accounts</li></ul>"])
}

test_NonGoogle_Incorrect_V5 if {
    # Test sharing setting when Top OU is not present
    PolicyId := "GWS.DRIVEDOCS.1.4v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_INVITES_TO_NON_GOOGLE_ACCOUNTS"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

#
# GWS.DRIVEDOCS.1.5v0.2
#--
test_Link_Correct_V1 if {
    # Test sharing setting when there's only one event
    PolicyId := "GWS.DRIVEDOCS.1.5v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_Link_Correct_V2 if {
    # Test sharing setting when there's multiple events and the most most recent is correct
    PolicyId := "GWS.DRIVEDOCS.1.5v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_Link_Correct_V3 if {
    # Test sharing setting when there's multiple OUs
    PolicyId := "GWS.DRIVEDOCS.1.5v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
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

test_Link_Incorrect_V1 if {
    # Test sharing setting when there are no relevant events
    PolicyId := "GWS.DRIVEDOCS.1.5v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

test_Link_Incorrect_V2 if {
    # Test sharing setting when there's only one event and it's wrong
    PolicyId := "GWS.DRIVEDOCS.1.5v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Top-Level OU: Published web content can be made visible to anyone with a link</li></ul>"])
}
test_Link_Incorrect_V3 if {
    # Test sharing setting when there are multiple events and the most recent is wrong
    PolicyId := "GWS.DRIVEDOCS.1.5v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Top-Level OU: Published web content can be made visible to anyone with a link</li></ul>"])
}

test_Link_Incorrect_V4 if {
    # Test sharing setting when Top OU is correct but not secondary OU
    PolicyId := "GWS.DRIVEDOCS.1.5v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Secondary OU: Published web content can be made visible to anyone with a link</li></ul>"])
}

test_Link_Incorrect_V5 if {
    # Test sharing setting when Top OU is not present
    PolicyId := "GWS.DRIVEDOCS.1.5v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "PUBLISHING_TO_WEB"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}
#--

#
# GWS.DRIVEDOCS.1.6v0.2
#--
test_SharingChecker_Correct_V1 if {
    # Test sharing setting when there's only one event
    PolicyId := "GWS.DRIVEDOCS.1.6v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "NAMED_PARTIES_ONLY"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_SharingChecker_Correct_V2 if {
    # Test setting when there's multiple events and the most most recent is correct
    PolicyId := "GWS.DRIVEDOCS.1.6v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "NAMED_PARTIES_ONLY"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "DOMAIN_OR_NAMED_PARTIES"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_SharingChecker_Correct_V3 if {
    # Test sharing setting when there's multiple OUs
    PolicyId := "GWS.DRIVEDOCS.1.6v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "NAMED_PARTIES_ONLY"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "NAMED_PARTIES_ONLY"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
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

test_SharingChecker_Incorrect_V1 if {
    # Test sharing setting when there are no relevant events
    PolicyId := "GWS.DRIVEDOCS.1.6v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "NOT_ALLOWED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

test_SharingChecker_Incorrect_V2 if {
    # Test sharing setting when there's only one event and it's wrong
    PolicyId := "GWS.DRIVEDOCS.1.6v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "ALL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Top-Level OU: ",
    "Access Checker allows users to share ",
    "files to Recipients only, suggested target audience, or public (no Google account required)</li></ul>"])
}

test_SharingChecker_Incorrect_V3 if {
    # Test sharing setting when there are multiple events and the most recent is wrong
    PolicyId := "GWS.DRIVEDOCS.1.6v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "ALL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "NAMED_PARTIES_ONLY"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Top-Level OU: ",
    "Access Checker allows users to share ",
    "files to Recipients only, suggested target audience, or public (no Google account required)</li></ul>"])
}

test_SharingChecker_Incorrect_V4 if {
    # Test sharing setting when Top OU is correct but not secondary OU
    PolicyId := "GWS.DRIVEDOCS.1.6v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "NAMED_PARTIES_ONLY"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "DOMAIN_OR_NAMED_PARTIES"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Secondary OU: ",
    "Access Checker allows users to share ",
    "files to Recipients only, or suggested target audience</li></ul>"])
}

test_SharingChecker_Incorrect_V5 if {
    # Test sharing setting when Top OU is not present
    PolicyId := "GWS.DRIVEDOCS.1.6v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_ACCESS_CHECKER_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "NAMED_PARTIES_ONLY"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

#
# GWS.DRIVEDOCS.1.7v0.2
#--
test_CrossDomain_Correct_V1 if {
    # Test sharing setting when there's only one event
    PolicyId := "GWS.DRIVEDOCS.1.7v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_MOVES_BLOCKED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_CrossDomain_Correct_V2 if {
    # Test sharing setting when there's multiple events and the most most recent is correct
    PolicyId := "GWS.DRIVEDOCS.1.7v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_MOVES_BLOCKED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_FROM_INTERNAL_OR_EXTERNAL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_CrossDomain_Correct_V3 if {
    # Test sharing setting when there's multiple OUs
    PolicyId := "GWS.DRIVEDOCS.1.7v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_MOVES_BLOCKED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_MOVES_BLOCKED"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
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

test_CrossDomain_Incorrect_V1 if {
    # Test sharing setting when there are no relevant events
    PolicyId := "GWS.DRIVEDOCS.1.7v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_MOVES_BLOCKED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

test_CrossDomain_Incorrect_V2 if {
    # Test sharing setting when there's only one event and it's wrong
    PolicyId := "GWS.DRIVEDOCS.1.7v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_FROM_INTERNAL_OR_EXTERNAL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [  "The following OUs are non-compliant:",
    "<ul><li>Test Top-Level OU: ",
    "Anyone can distribute content in the organization to outside the organization</li></ul>"])
}

test_CrossDomain_Incorrect_V3 if {
    # Test sharing setting when there are multiple events and
    # the most recent is wrong, set to anyone can distribute content. 
    PolicyId := "GWS.DRIVEDOCS.1.7v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_FROM_INTERNAL_OR_EXTERNAL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_MOVES_BLOCKED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [  "The following OUs are non-compliant:",
    "<ul><li>Test Top-Level OU: ",
    "Anyone can distribute content in the organization to outside the organization</li></ul>"])
}

test_CrossDomain_Incorrect_V4 if {
    # Test sharing setting when Top OU is correct but not secondary OU,
    # which is set to Anyone in the Organization
    PolicyId := "GWS.DRIVEDOCS.1.7v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_MOVES_BLOCKED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_FROM_INTERNAL_OR_EXTERNAL"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Secondary OU: ",
    "Anyone can distribute content in the organization to outside the organization</li></ul>"])
}


test_CrossDomain_Incorrect_V5 if {
    # Test sharing setting when Top OU is not present
    PolicyId := "GWS.DRIVEDOCS.1.7v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_MOVES_BLOCKED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

test_CrossDomain_Incorrect_V6 if {
    # Test sharing setting when there are multiple events and
    # the most recent event is wrong, set to only users in the organization
    PolicyId := "GWS.DRIVEDOCS.1.7v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_FROM_INTERNAL_ONLY"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_TEAM_DRIVE_CROSS_DOMAIN_OPTIONS"},
                        {"name": "NEW_VALUE", "value": "CROSS_DOMAIN_MOVES_BLOCKED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:",
    "<ul><li>Test Top-Level OU: ",
    "Only users inside the organization can distribute content outside of the organization</li></ul>"])
}
#--

#
# GWS.DRIVEDOCS.1.8v0.2
#--
test_Default_Correct_V1 if {
    # Test sharing setting when there's only one event
    PolicyId := "GWS.DRIVEDOCS.1.8v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PRIVATE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_Default_Correct_V2 if {
    # Test sharing setting when there's multiple events and the most most recent is correct
    PolicyId := "GWS.DRIVEDOCS.1.8v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PRIVATE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PUBLIC"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_Default_Correct_V3 if {
    # Test sharing setting when there's multiple OUs
    PolicyId := "GWS.DRIVEDOCS.1.8v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PRIVATE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PRIVATE"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
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

test_Default_Incorrect_V1 if {
    # Test sharing setting when there are no relevant events
    PolicyId := "GWS.DRIVEDOCS.1.8v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "PRIVATE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

test_Default_Incorrect_V2 if {
    # Test sharing setting when there's only one event and it's wrong
    PolicyId := "GWS.DRIVEDOCS.1.8v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PUBLIC"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:",
        "<ul><li>Test Top-Level OU: When users create items, the default access is set to: ",
        "The primary target audience can search and find the item.</li></ul>"

    ])
}

test_Default_Incorrect_V3 if {
    # Test sharing setting when there are multiple events and the most recent is wrong
    PolicyId := "GWS.DRIVEDOCS.1.8v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PUBLIC"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PRIVATE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:",
        "<ul><li>Test Top-Level OU: When users create items, the default access is set to: ",
        "The primary target audience can search and find the item.</li></ul>"
    ])
}

test_Default_Incorrect_V4 if {
    # Test sharing setting when Top OU is correct but not secondary OU
    PolicyId := "GWS.DRIVEDOCS.1.8v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PRIVATE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PUBLIC"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:",
        "<ul><li>Test Secondary OU: When users create items, the default access is set to: ",
        "The primary target audience can search and find the item.</li></ul>"

    ])
}

test_Default_Incorrect_V5 if {
    # Test sharing setting when Top OU is not present
    PolicyId := "GWS.DRIVEDOCS.1.8v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PRIVATE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}

test_Default_Incorrect_V6 if {
    # Test sharing setting when Top OU is correct but not secondary OU
    PolicyId := "GWS.DRIVEDOCS.1.8v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PRIVATE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DEFAULT_LINK_SHARING_FOR_NEW_DOCS"},
                        {"name": "NEW_VALUE", "value": "PEOPLE_WITH_LINK"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:",
        "<ul><li>Test Secondary OU: When users create items,",
        " the default access is set to: ",
        "The primary target audience can access the item if they have the link</li></ul>"

    ])
}