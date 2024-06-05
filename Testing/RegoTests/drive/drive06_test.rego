package drive
import future.keywords

#
# GWS.DRIVE.6.1v0.2
#--
test_DriveFs_Setting_Correct_V1 if {
    # Test Drive setting when there's OU inhertitence setting
    PolicyId := "GWS.DRIVEDOCS.6.1v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:22.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto drive_fs_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-13-20T00:02:23.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto company_owned_only_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-14-20T00:02:24.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto company_owned_only_enabled"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-15-20T00:02:25.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto drive_fs_enabled"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"}
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
    RuleOutput[0].ReportDetails == "Requirement met in all OUs."
}

test_DriveFs_Setting_Correct_V2 if {
    # Test Drive setting when there's multiple events
    PolicyId := "GWS.DRIVEDOCS.6.1v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:22.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto drive_fs_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-13-20T00:02:23.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto company_owned_only_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-14-20T00:02:22.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto drive_fs_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"}
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
    RuleOutput[0].ReportDetails == "Requirement met in all OUs."
}

test_DriveFs_Setting_Correct_V3 if {
    # Test Drive setting when there's multiple events and inherited OU setting
    PolicyId := "GWS.DRIVEDOCS.6.1v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:22.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto drive_fs_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-13-20T00:02:23.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto company_owned_only_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-17-20T00:02:24.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto company_owned_only_enabled"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-18-20T00:02:25.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto drive_fs_enabled"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-14-20T00:02:22.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto drive_fs_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"}
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
    RuleOutput[0].ReportDetails == "Requirement met in all OUs."
}

test_DriveFs_Setting_Correct_V4 if {
    # Test Drive setting when there's multiple events
    PolicyId := "GWS.DRIVEDOCS.6.1v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:22.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto drive_fs_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-13-20T00:02:23.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto company_owned_only_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"}
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
    RuleOutput[0].ReportDetails == "Requirement met in all OUs."
}

test_DriveFs_Setting_InCorrect_V1 if {
    # Test Drive setting when there's only one event
    PolicyId := "GWS.DRIVEDOCS.6.1v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:24.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto company_owned_only_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:25.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto drive_fs_enabled"},
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
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement failed in Test Top-Level OU."
}

test_DriveFs_Setting_InCorrect_V2 if {
    # Test Drive setting when there's multiple events
    PolicyId := "GWS.DRIVEDOCS.6.1v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:24.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto company_owned_only_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:25.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto drive_fs_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-22-20T00:02:24.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto company_owned_only_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-21-20T00:02:25.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto drive_fs_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary-Level OU"},
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

test_DriveFs_Setting_InCorrect_V3 if {
    # Test Drive setting when there's multiple events
    PolicyId := "GWS.DRIVEDOCS.6.1v0.2"
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:24.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto company_owned_only_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:25.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto drive_fs_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-22-20T00:02:24.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto company_owned_only_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-21-20T00:02:25.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto drive_fs_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-17-20T00:02:24.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto company_owned_only_enabled"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-18-20T00:02:25.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto drive_fs_enabled"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"}
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
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement failed in Test Top-Level OU."
}