package drive

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.DRIVE.6.1
#--

test_DriveFs_Setting_Correct_V1 if {
    # Test Drive setting when there's OU inhertitence setting
    PolicyId := DriveId6_1
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

    PassTestResult(PolicyId, Output)
}

test_DriveFs_Setting_Correct_V2 if {
    # Test Drive setting when there's multiple events
    PolicyId := DriveId6_1
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

    PassTestResult(PolicyId, Output)
}

test_DriveFs_Setting_Correct_V3 if {
    # Test Drive setting when there's multiple events and inherited OU setting
    PolicyId := DriveId6_1
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

    PassTestResult(PolicyId, Output)
}

test_DriveFs_Setting_Correct_V4 if {
    # Test Drive setting when there's multiple events
    PolicyId := DriveId6_1
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

    PassTestResult(PolicyId, Output)
}

test_DriveFs_Setting_InCorrect_V1 if {
    # Test Drive setting when there's only one event
    PolicyId := DriveId6_1
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:24.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto company_owned_only_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:25.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto drive_fs_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                  "Value": NonComplianceMessage6_1(GetFriendlyValue6_1("false", "true"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_DriveFs_Setting_InCorrect_V2 if {
    # Test Drive setting when there's multiple events
    PolicyId := DriveId6_1
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:24.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto company_owned_only_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:25.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto drive_fs_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-22-20T00:02:24.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto company_owned_only_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
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

    failedOU := [{"Name": "Test Top-Level OU",
                  "Value": NonComplianceMessage6_1(GetFriendlyValue6_1("false", "true"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_DriveFs_Setting_InCorrect_V3 if {
    # Test Drive setting when there's multiple events
    PolicyId := DriveId6_1
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:24.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto company_owned_only_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:25.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto drive_fs_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-05-20T00:02:24.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto company_owned_only_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-05-20T00:02:25.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "DriveFsSettingsProto drive_fs_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
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

    failedOU := [{"Name": "Test Top-Level OU",
                  "Value": NonComplianceMessage6_1(GetFriendlyValue6_1("false", "true"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
