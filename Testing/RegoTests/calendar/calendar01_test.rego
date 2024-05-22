package calendar
import future.keywords

#
# GWS.CALENDAR.1.1v0.1
#--
test_ExtSharingPrimaryCal_Correct_V1 if {
    # Test external sharing for primary calendars when there's only one event
    PolicyId := "GWS.CALENDAR.1.1v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingPrimaryCal_Correct_V2 if {
    # Test external sharing for primary calendars when there's multiple events and the most most recent is correct
    PolicyId := "GWS.CALENDAR.1.1v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingPrimaryCal_Correct_V3 if {
    # Test external sharing for primary calendars when there's multiple OUs
    PolicyId := "GWS.CALENDAR.1.1v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingPrimaryCal_Correct_V4 if {
    # Test external sharing for primary calendars when there's multiple OUs, and an older event is non-compliant
    PolicyId := "GWS.CALENDAR.1.1v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2020-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingPrimaryCal_Correct_V5 if {
    # Test external sharing for primary, inherit from parent
    PolicyId := "GWS.CALENDAR.1.1v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2020-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "something else"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "INHERIT_FROM_PARENT"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingPrimaryCal_Correct_V6 if {
    # Test group
    PolicyId := "GWS.CALENDAR.1.1v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU OU"},
                        {"name": "GROUP_EMAIL", "value": "group1@example.com"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingPrimaryCal_Incorrect_V1 if {
    # Test external sharing for primary calendars when there are no relevant events
    PolicyId := "GWS.CALENDAR.1.1v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingPrimaryCal_Incorrect_V2 if {
    # Test external sharing for primary calendars when there's only one event and it's wrong
    PolicyId := "GWS.CALENDAR.1.1v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "External sharing options for primary calendars is set to ",
        "Share all information, but outsiders cannot change calendars</li></ul>"])
}

test_ExtSharingPrimaryCal_Incorrect_V3 if {
    # Test external sharing for primary calendars when there are multiple events and the most recent is wrong
    PolicyId := "GWS.CALENDAR.1.1v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "External sharing options for primary calendars is set to ",
        "Share all information, but outsiders cannot change calendars</li></ul>"])
}

test_ExtSharingPrimaryCal_Incorrect_V4 if {
    # Test external sharing for primary calendars when there is no event for the Top-level OU
    # but there is one for a different OU
    PolicyId := "GWS.CALENDAR.1.1v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingPrimaryCal_Incorrect_V5 if {
    # Test external sharing for primary calendars when the Top-Level OU is compliant,
    # but a secondary OU is non-compliant
    PolicyId := "GWS.CALENDAR.1.1v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"}
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
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Secondary OU: ",
        "External sharing options for primary calendars is set to ",
        "Share all information, but outsiders cannot change calendars</li></ul>"])
}

test_ExtSharingPrimaryCal_Incorrect_V6 if {
    # Test: top-level OU is compliant but a group is non-compliant
    PolicyId := "GWS.CALENDAR.1.1v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "GROUP_EMAIL", "value": "group1@example.com"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"}
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
    RuleOutput[0].ReportDetails == concat("", ["The following groups are non-compliant:<ul><li>group1@example.com: ",
        "External sharing options for primary calendars is set to ",
        "Share all information, but outsiders cannot change calendars</li></ul>"])
}

test_ExtSharingPrimaryCal_Incorrect_V if {
    # Test: top-level OU and a group are non-compliant
    PolicyId := "GWS.CALENDAR.1.1v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "GROUP_EMAIL", "value": "group1@example.com"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"}
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
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "External sharing options for primary calendars is set to ",
        "Share all information, but outsiders cannot change calendars</li></ul><br>",
        "The following groups are non-compliant:<ul><li>group1@example.com: ",
        "External sharing options for primary calendars is set to ",
        "Share all information, but outsiders cannot change calendars</li></ul>"])
}
#--

#
# GWS.CALENDAR.1.2v0.1
#--
test_ExtSharingSecondaryCal_Correct_V1 if {
 # Test external sharing for secondary calendars when there's only one event
    PolicyId := "GWS.CALENDAR.1.2v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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
    RuleOutput[0].ReportDetails == concat("", [
        "Requirement met.<br>",
        "Highest Level of Sharing: Only free/busy information (hide event details)."
    ])
}

test_ExtSharingSecondaryCal_Correct_V2 if {
    # Test external sharing for secondary calendars when there's multiple events and the most most recent is correct
    PolicyId := "GWS.CALENDAR.1.2v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"},
                        {"name": "NEW_VALUE", "value": "SHOW_ONLY_FREE_BUSY_INFORMATION"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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
    RuleOutput[0].ReportDetails == concat("", [
        "Requirement met.<br>",
        "Highest Level of Sharing: Only free/busy information (hide event details)."
    ])
}

test_ExtSharingSecondaryCal_Incorrect_V1 if {
    # Test external sharing for secondary calendars when there are no relevant events
    PolicyId := "GWS.CALENDAR.1.2v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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

test_ExtSharingSecondaryCal_Incorrect_V2 if {
    # Test external sharing for secondary calendars when there's only one event and it's wrong
    PolicyId := "GWS.CALENDAR.1.2v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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
        "Requirement not met.<br>",
        "Highest Level of Sharing: Secondary Calendars Share all information,",
        " but outsiders cannot change calendars."
    ])
}

test_ExtSharingSecondaryCal_Incorrect_V3 if {
    # Test external sharing for secondary calendars when there are multiple events and the most recent is wrong
    PolicyId := "GWS.CALENDAR.1.2v0.1"
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"},
                        {"name": "NEW_VALUE", "value": "READ_ONLY_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"},
                        {"name": "NEW_VALUE", "value": "READ_WRITE_ACCESS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "DOMAIN_NAME", "value": "Test Top-Level Domain"},
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
        "Requirement not met.<br>",
        "Highest Level of Sharing: Secondary Calendars Share all information,",
        " but outsiders cannot change calendars."
    ])

}
#--