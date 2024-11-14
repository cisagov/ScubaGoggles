package commoncontrols

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestGroupNonCompliant
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.COMMONCONTROLS.8.1
#--
test_SelfRecovery_Correct_V1 if {
    # Test 1 event
    PolicyId := CommonControlsId8_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {
                            "name": "SETTING_NAME",
                            "value": "AdminAccountRecoverySettingsProto Enable admin account recovery"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
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

test_SelfRecovery_Correct_V2 if {
    # Test 1 event
    PolicyId := CommonControlsId8_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {
                            "name": "SETTING_NAME",
                            "value": "AdminAccountRecoverySettingsProto Enable admin account recovery"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {
                            "name": "SETTING_NAME",
                            "value": "AdminAccountRecoverySettingsProto Enable admin account recovery"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
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

test_SelfRecovery_Correct_V3 if {
    # Test inheritance
    PolicyId := CommonControlsId8_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2020-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {
                            "name": "SETTING_NAME",
                            "value": "AdminAccountRecoverySettingsProto Enable admin account recovery"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {
                            "name": "SETTING_NAME",
                            "value": "AdminAccountRecoverySettingsProto Enable admin account recovery"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Second OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
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
                            "value": "AdminAccountRecoverySettingsProto Enable admin account recovery"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Second OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
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

test_SelfRecovery_Incorrect_V1 if {
    # Test 1 event
    PolicyId := CommonControlsId8_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {
                            "name": "SETTING_NAME",
                            "value": "AdminAccountRecoverySettingsProto Enable admin account recovery"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": "Allow super admins to recover their account is ON"}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SelfRecovery_Incorrect_V2 if {
    # Test multiple events
    PolicyId := CommonControlsId8_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {
                            "name": "SETTING_NAME",
                            "value": "AdminAccountRecoverySettingsProto Enable admin account recovery"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {
                            "name": "SETTING_NAME",
                            "value": "AdminAccountRecoverySettingsProto Enable admin account recovery"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": "Allow super admins to recover their account is ON"}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SelfRecovery_Incorrect_V3 if {
    # Test no relevant events
    PolicyId := CommonControlsId8_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [

        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_SelfRecovery_Incorrect_V4 if {
    # Test no relevant events in the top-level OU
    PolicyId := CommonControlsId8_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {
                            "name": "SETTING_NAME",
                            "value": "AdminAccountRecoverySettingsProto Enable admin account recovery"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_SelfRecovery_Incorrect_V5 if {
    # Test multiple OUs
    PolicyId := CommonControlsId8_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {
                            "name": "SETTING_NAME",
                            "value": "AdminAccountRecoverySettingsProto Enable admin account recovery"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {
                            "name": "SETTING_NAME",
                            "value": "AdminAccountRecoverySettingsProto Enable admin account recovery"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Second-Level OU",
                 "Value": "Allow super admins to recover their account is ON"},
                 {"Name": "Test Top-Level OU",
                 "Value": "Allow super admins to recover their account is ON"}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SelfRecovery_Incorrect_V6 if {
    # Test group
    PolicyId := CommonControlsId8_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {
                            "name": "SETTING_NAME",
                            "value": "AdminAccountRecoverySettingsProto Enable admin account recovery"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {
                            "name": "SETTING_NAME",
                            "value": "AdminAccountRecoverySettingsProto Enable admin account recovery"
                        },
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "GROUP_EMAIL", "value": "test@test"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "test@test",
                 "Value": "Allow super admins to recover their account is ON"}]
    FailTestGroupNonCompliant(PolicyId, Output, failedOU)
}
#--
