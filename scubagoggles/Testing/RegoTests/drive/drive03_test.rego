package drive

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.DRIVEDOCS.3.1
#--

test_Sharing_Correct_V1 if {
    # Test sharing setting when there's only one event
    PolicyId := DriveId3_1
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Link Security Update Settings allow_less_secure_link_user_restore"
                        },
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:27.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Link Security Update Settings less_secure_link_option"},
                        {"name": "NEW_VALUE", "value": "REMOVE_LESS_SECURE_LINKS"},
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

test_Sharing_Correct_V2 if {
    # Test sharing setting when there's multiple events and the most most recent is correct
    PolicyId := DriveId3_1
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Link Security Update Settings allow_less_secure_link_user_restore"
                        },
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:27.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Link Security Update Settings less_secure_link_option"},
                        {"name": "NEW_VALUE", "value": "REMOVE_LESS_SECURE_LINKS"},
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
                            "value": "Link Security Update Settings allow_less_secure_link_user_restore"
                        },
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

    PassTestResult(PolicyId, Output)
}

test_Sharing_Correct_V3 if {
    # Test sharing setting when there's multiple OUs
    PolicyId := DriveId3_1
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Link Security Update Settings allow_less_secure_link_user_restore"
                        },
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:27.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Link Security Update Settings less_secure_link_option"},
                        {"name": "NEW_VALUE", "value": "REMOVE_LESS_SECURE_LINKS"},
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
                            "value": "Link Security Update Settings allow_less_secure_link_user_restore"
                        },
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:27.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Link Security Update Settings less_secure_link_option"},
                        {"name": "NEW_VALUE", "value": "REMOVE_LESS_SECURE_LINKS"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
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

test_Sharing_Incorrect_V1 if {
    # Test sharing setting when there are no relevant events
    PolicyId := DriveId3_1
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

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}

test_Sharing_Incorrect_V2 if {
    # Test sharing setting when there's only one event and it's wrong
    PolicyId := DriveId3_1
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Link Security Update Settings allow_less_secure_link_user_restore"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:27.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Link Security Update Settings less_secure_link_option"},
                        {"name": "NEW_VALUE", "value": "LESS_SECURE_LINKS"},
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
                  "Value": NonComplianceMessage3_1("", "true")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Sharing_Incorrect_V3 if {
    # Test sharing setting when there are multiple events and the most recent is wrong
    PolicyId := DriveId3_1
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Link Security Update Settings allow_less_secure_link_user_restore"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:27.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Link Security Update Settings less_secure_link_option"},
                        {"name": "NEW_VALUE", "value": "LESS_SECURE_LINKS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:27.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Link Security Update Settings allow_less_secure_link_user_restore"
                        },
                        {"name": "NEW_VALUE", "value": "false"},
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
                  "Value": NonComplianceMessage3_1("", "true")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Sharing_Incorrect_V4 if {
    # Test sharing setting when top level ou is correct but secondary isn't
    PolicyId := DriveId3_1
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Link Security Update Settings allow_less_secure_link_user_restore"
                        },
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
            "id": {"time": "2022-12-20T00:02:27.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Link Security Update Settings less_secure_link_option"},
                        {"name": "NEW_VALUE", "value": "REMOVE_LESS_SECURE_LINKS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
            "id": {"time": "2022-12-20T00:02:27.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Link Security Update Settings less_secure_link_option"},
                        {"name": "NEW_VALUE", "value": "LESS_SECURE_LINKS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:27.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Link Security Update Settings allow_less_secure_link_user_restore"
                        },
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    failedOU := [{"Name": "Test Secondary OU",
                  "Value": NonComplianceMessage3_1("", "true")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Sharing_Incorrect_V5 if {
    # Test sharing setting when top level ou is missing
    PolicyId := DriveId3_1
    Output := tests with input as {
        "drive_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {
                            "name": "SETTING_NAME",
                            "value": "Link Security Update Settings allow_less_secure_link_user_restore"
                        },
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            },
            {
            "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Link Security Update Settings less_secure_link_option"},
                        {"name": "NEW_VALUE", "value": "REMOVE_LESS_SECURE_LINKS"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}
