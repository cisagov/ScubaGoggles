package chat
import future.keywords

#
# GWS.CHAT.2.1v0.2
#--
test_External_File_Sharing_Correct_V1 if {
    # Test users are not allowed to share files externally when there's only one event
    PolicyId := "GWS.CHAT.2.1v0.2"
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DynamiteFileSharingSettingsProto external_file_sharing_setting"
                        },
                        {"name": "NEW_VALUE", "value": "NO_FILES"},
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

test_External_File_Sharing_Correct_V2 if {
    # Test users are not allowed to share files externally when there's multiple events
    # and the most most recent is correct
    PolicyId := "GWS.CHAT.2.1v0.2"
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DynamiteFileSharingSettingsProto external_file_sharing_setting"
                        },
                        {"name": "NEW_VALUE", "value": "NO_FILES"},
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
                            "value": "DynamiteFileSharingSettingsProto external_file_sharing_setting"
                        },
                        {"name": "NEW_VALUE", "value": "ALLOW_ALL_FILES"},
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

test_External_File_Sharing_Correct_V3 if {
    # Test OU inheriting from parent
    PolicyId := "GWS.CHAT.2.1v0.2"
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2020-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DynamiteFileSharingSettingsProto external_file_sharing_setting"
                        },
                        {"name": "NEW_VALUE", "value": "NO_FILES"},
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
                            "value": "DynamiteFileSharingSettingsProto external_file_sharing_setting"
                        },
                        {"name": "NEW_VALUE", "value": "ALLOW_ALL_FILES"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DynamiteFileSharingSettingsProto external_file_sharing_setting"
                        },
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

test_External_File_Sharing_Incorrect_V1 if {
    # Test no relevant events
    PolicyId := "GWS.CHAT.2.1v0.2"
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "NO_FILES"},
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

test_External_File_Sharing_Incorrect_V2 if {
    # Test all allowed
    PolicyId := "GWS.CHAT.2.1v0.2"
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DynamiteFileSharingSettingsProto external_file_sharing_setting"
                        },
                        {"name": "NEW_VALUE", "value": "ALL_FILES"},
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
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "External filesharing is set to Allow all files</li></ul>"])
}

test_External_File_Sharing_Incorrect_V3 if {
    # Test images allowed
    PolicyId := "GWS.CHAT.2.1v0.2"
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DynamiteFileSharingSettingsProto external_file_sharing_setting"
                        },
                        {"name": "NEW_VALUE", "value": "IMAGES_ONLY"},
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
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "External filesharing is set to Images only</li></ul>"])
}

test_External_File_Sharing_Incorrect_V4 if {
    # Test sharing allowed when there are multiple events
    PolicyId := "GWS.CHAT.2.1v0.2"
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DynamiteFileSharingSettingsProto external_file_sharing_setting"
                        },
                        {"name": "NEW_VALUE", "value": "ALL_FILES"},
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
                            "value": "DynamiteFileSharingSettingsProto external_file_sharing_setting"
                        },
                        {"name": "NEW_VALUE", "value": "NO_FILES"},
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
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "External filesharing is set to Allow all files</li></ul>"])
}

test_External_File_Sharing_Incorrect_V5 if {
    # Test allowing images, multiple events
    PolicyId := "GWS.CHAT.2.1v0.2"
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DynamiteFileSharingSettingsProto external_file_sharing_setting"
                        },
                        {"name": "NEW_VALUE", "value": "IMAGES_ONLY"},
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
                            "value": "DynamiteFileSharingSettingsProto external_file_sharing_setting"
                        },
                        {"name": "NEW_VALUE", "value": "NO_FILES"},
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
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "External filesharing is set to Images only</li></ul>"])
}

test_External_File_Sharing_Incorrect_V6 if {
    # Test there's one event for a secondary OU but none for the primary OU
    PolicyId := "GWS.CHAT.2.1v0.2"
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DynamiteFileSharingSettingsProto external_file_sharing_setting"
                        },
                        {"name": "NEW_VALUE", "value": "NO_FILES"},
                        {"name": "ORG_UNIT_NAME", "value": "Some other OU"},
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

test_External_File_Sharing_Incorrect_V7 if {
    # Test there's multiple OUs
    PolicyId := "GWS.CHAT.2.1v0.2"
    Output := tests with input as {
        "chat_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DynamiteFileSharingSettingsProto external_file_sharing_setting"
                        },
                        {"name": "NEW_VALUE", "value": "ALL_FILES"},
                        {"name": "ORG_UNIT_NAME", "value": "Some other OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "DynamiteFileSharingSettingsProto external_file_sharing_setting"
                        },
                        {"name": "NEW_VALUE", "value": "NO_FILES"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
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
    RuleOutput[0].ReportDetails == concat("", ["The following OUs are non-compliant:<ul><li>Some other OU: ",
        "External filesharing is set to Allow all files</li></ul>"])
}
#--