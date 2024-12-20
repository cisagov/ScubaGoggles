package chat

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.CHAT.2.1
#--
test_External_File_Sharing_Correct_V1 if {
    # Test users are not allowed to share files externally when there's only one event
    PolicyId := ChatId2_1
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

    PassTestResult(PolicyId, Output)
}

test_External_File_Sharing_Correct_V2 if {
    # Test users are not allowed to share files externally when there's multiple events
    # and the most most recent is correct
    PolicyId := ChatId2_1
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

    PassTestResult(PolicyId, Output)
}

test_External_File_Sharing_Correct_V3 if {
    # Test OU inheriting from parent
    PolicyId := ChatId2_1
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

    PassTestResult(PolicyId, Output)
}

test_External_File_Sharing_Incorrect_V1 if {
    # Test no relevant events
    PolicyId := ChatId2_1
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

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_External_File_Sharing_Incorrect_V2 if {
    # Test all allowed
    PolicyId := ChatId2_1
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

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage2_1("Allow all files")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_External_File_Sharing_Incorrect_V3 if {
    # Test images allowed
    PolicyId := ChatId2_1
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

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage2_1("Images only")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_External_File_Sharing_Incorrect_V4 if {
    # Test sharing allowed when there are multiple events
    PolicyId := ChatId2_1
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

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage2_1("Allow all files")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_External_File_Sharing_Incorrect_V5 if {
    # Test allowing images, multiple events
    PolicyId := ChatId2_1
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

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage2_1("Images only")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_External_File_Sharing_Incorrect_V6 if {
    # Test there's one event for a secondary OU but none for the primary OU
    PolicyId := ChatId2_1
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

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_External_File_Sharing_Incorrect_V7 if {
    # Test there's multiple OUs
    PolicyId := ChatId2_1
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

    failedOU := [{"Name": "Some other OU",
                 "Value": NonComplianceMessage2_1("Allow all files")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--
