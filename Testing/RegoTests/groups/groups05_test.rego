package groups
import future.keywords


#
# Policy 1
#--
test_GroupConservationViewPermission_Correct_V1 if {
    # Test group conversation view permissions when there's only one event
    PolicyId := "GWS.GROUPS.5.1v0.2"
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "MEMBERS"},
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

test_GroupConservationViewPermission_Correct_V2 if {
    # Test group conversation view permissions when there's multiple events and the most most recent is correct
    PolicyId := "GWS.GROUPS.5.1v0.2"
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "MEMBERS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "DOMAIN_USERS"},
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
    RuleOutput[0].ReportDetails =="Requirement met in all OUs and groups."
}

test_GroupConservationViewPermission_Incorrect_V1 if {
    # Test group conversation view permissions when there are no relevant events
    PolicyId := "GWS.GROUPS.5.1v0.2"
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "MEMBERS"},
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

test_GroupConservationViewPermission_Incorrect_V2 if {
    # Test group conversation view permissions when there's only one event and it's wrong
    PolicyId := "GWS.GROUPS.5.1v0.2"
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "DOMAIN_USERS"},
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
        "Permission to view conversations is set to domain users</li></ul>"])
}

test_GroupConservationViewPermission_Incorrect_V3 if {
    # Test group conversation view permissions when there's only one event and it's wrong
    PolicyId := "GWS.GROUPS.5.1v0.2"
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "MANAGERS"},
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
        "Permission to view conversations is set to managers</li></ul>"])
}

test_GroupConservationViewPermission_Incorrect_V4 if {
    # Test group conversation view permissions when there's only one event and it's wrong
    PolicyId := "GWS.GROUPS.5.1v0.2"
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "OWNERS"},
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
        "Permission to view conversations is set to owners</li></ul>"])
}

test_GroupConservationViewPermission_Incorrect_V5 if {
    # Test group conversation view permissions when there are multiple events and the most recent is wrong
    PolicyId := "GWS.GROUPS.5.1v0.2"
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "DOMAIN_USERS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "MEMBERS"},
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
        "Permission to view conversations is set to domain users</li></ul>"])
}

test_GroupConservationViewPermission_Incorrect_V6 if {
    # Test group conversation view permissions when there are multiple events and the most recent is wrong
    PolicyId := "GWS.GROUPS.5.1v0.2"
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "MANAGERS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "MEMBERS"},
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
        "Permission to view conversations is set to managers</li></ul>"])
}

test_GroupConservationViewPermission_Incorrect_V7 if {
    # Test group conversation view permissions when there are multiple events and the most recent is wrong
    PolicyId := "GWS.GROUPS.5.1v0.2"
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "OWNERS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "MEMBERS"},
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
        "Permission to view conversations is set to owners</li></ul>"])
}
#--

test_GroupConservationViewPermission_Incorrect_V8 if {
    # Test group conversation view permissions when there are multiple events and the most recent is wrong
    PolicyId := "GWS.GROUPS.5.1v0.2"
    Output := tests with input as {
        "groups_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "PUBLIC"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "GroupsSharingSettingsProto default_view_topics_access_level"
                        },
                        {"name": "NEW_VALUE", "value": "MEMBERS"},
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
        "Permission to view conversations is set to anyone on the internet</li></ul>"])
}
#--