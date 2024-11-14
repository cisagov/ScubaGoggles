package commoncontrols

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestGroupNonCompliant
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.COMMONCONTROLS.11.1
#--

test_Installation_Correct_V1 if {
    # Test 1 event
    PolicyId := CommonControlsId11_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-11-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {"name": "NEW_VALUE", "value": "ALLOW_SPECIFIED"},
                            {"name": "SETTING_NAME", "value": "Apps Access Setting Allowlist access"},
                            {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                            {"name": "APPLICATION_NAME", "value": "Security"}
                        ]
                    },
                ]
            },
            {
                "id": {"time": "2022-11-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {"name": "NEW_VALUE", "value": "false"},
                            {"name": "SETTING_NAME", "value": "Apps Access Setting allow_all_internal_apps"},
                            {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                            {"name": "APPLICATION_NAME", "value": "Security"}
                        ]
                    },
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_Installation_Correct_V2 if {
    # Test multiple events
    PolicyId := CommonControlsId11_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-11-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ALLOW_SPECIFIED"},
                        {"name": "SETTING_NAME", "value": "Apps Access Setting Allowlist access"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-11-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "SOMETHING_ELSE"},
                        {"name": "SETTING_NAME", "value": "Apps Access Setting Allowlist access"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-11-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {"name": "NEW_VALUE", "value": "false"},
                            {"name": "SETTING_NAME", "value": "Apps Access Setting allow_all_internal_apps"},
                            {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                            {"name": "APPLICATION_NAME", "value": "Security"}
                        ]
                    },
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_Installation_Correct_V3 if {
    # Test inheritance
    PolicyId := CommonControlsId11_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2020-11-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ALLOW_SPECIFIED"},
                        {"name": "SETTING_NAME", "value": "Apps Access Setting Allowlist access"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-11-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ALLOW_ALL"},
                        {"name": "SETTING_NAME", "value": "Apps Access Setting Allowlist access"},
                        {"name": "ORG_UNIT_NAME", "value": "Second OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-11-20T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Apps Access Setting Allowlist access"},
                        {"name": "ORG_UNIT_NAME", "value": "Second OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-11-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {"name": "NEW_VALUE", "value": "false"},
                            {"name": "SETTING_NAME", "value": "Apps Access Setting allow_all_internal_apps"},
                            {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                            {"name": "APPLICATION_NAME", "value": "Security"}
                        ]
                    },
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_Installation_Incorrect_V1 if {
    # Test 1 event
    PolicyId := CommonControlsId11_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-11-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "SOMETHING_ELSE"},
                        {"name": "SETTING_NAME", "value": "Apps Access Setting Allowlist access"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-11-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {"name": "NEW_VALUE", "value": "false"},
                            {"name": "SETTING_NAME", "value": "Apps Access Setting allow_all_internal_apps"},
                            {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                            {"name": "APPLICATION_NAME", "value": "Security"}
                        ]
                    },
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                  "Value": NonComplianceMessage11_1(true)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Installation_Incorrect_V2 if {
    # Test multiple events
    PolicyId := CommonControlsId11_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-11-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "SOMETHING_ELSE"},
                        {"name": "SETTING_NAME", "value": "Apps Access Setting Allowlist access"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-11-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ALLOW_SPECIFIED"},
                        {"name": "SETTING_NAME", "value": "Apps Access Setting Allowlist access"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-11-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {"name": "NEW_VALUE", "value": "false"},
                            {"name": "SETTING_NAME", "value": "Apps Access Setting allow_all_internal_apps"},
                            {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                            {"name": "APPLICATION_NAME", "value": "Security"}
                        ]
                    },
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                  "Value": NonComplianceMessage11_1(true)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Installation_Incorrect_V3 if {
    # Test no relevant events
    PolicyId := CommonControlsId11_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [

        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_Installation_Incorrect_V4 if {
    # Test no relevant events in top-level OU
    PolicyId := CommonControlsId11_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2021-11-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ALLOW_SPECIFIED"},
                        {"name": "SETTING_NAME", "value": "Apps Access Setting Allowlist access"},
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

test_Installation_Incorrect_V5 if {
    # Test multiple OUs
    PolicyId := CommonControlsId11_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2021-11-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "something else"},
                        {"name": "SETTING_NAME", "value": "Apps Access Setting Allowlist access"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-11-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ALLOW_SPECIFIED"},
                        {"name": "SETTING_NAME", "value": "Apps Access Setting Allowlist access"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-11-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {"name": "NEW_VALUE", "value": "false"},
                            {"name": "SETTING_NAME", "value": "Apps Access Setting allow_all_internal_apps"},
                            {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                            {"name": "APPLICATION_NAME", "value": "Security"}
                        ]
                    },
                ]
            },
            {
                "id": {"time": "2022-11-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {"name": "NEW_VALUE", "value": "false"},
                            {"name": "SETTING_NAME", "value": "Apps Access Setting allow_all_internal_apps"},
                            {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                            {"name": "APPLICATION_NAME", "value": "Security"}
                        ]
                    },
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Second-Level OU",
                  "Value": NonComplianceMessage11_1(true)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Installation_Incorrect_V6 if {
    # Test internal allowed
    PolicyId := CommonControlsId11_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-11-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ALLOW_SPECIFIED"},
                        {"name": "SETTING_NAME", "value": "Apps Access Setting Allowlist access"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-11-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {"name": "NEW_VALUE", "value": "true"},
                            {"name": "SETTING_NAME", "value": "Apps Access Setting allow_all_internal_apps"},
                            {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                            {"name": "APPLICATION_NAME", "value": "Security"}
                        ]
                    },
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                  "Value": NonComplianceMessage11_1(false)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Installation_Incorrect_V7 if {
    # Test group
    PolicyId := CommonControlsId11_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-11-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "ALLOW_SPECIFIED"},
                        {"name": "SETTING_NAME", "value": "Apps Access Setting Allowlist access"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-11-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {"name": "NEW_VALUE", "value": "false"},
                            {"name": "SETTING_NAME", "value": "Apps Access Setting allow_all_internal_apps"},
                            {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                            {"name": "APPLICATION_NAME", "value": "Security"}
                        ]
                    },
                ]
            },
            {
                "id": {"time": "2022-11-20T00:02:28.672Z"},
                "events": [
                    {
                        "parameters": [
                            {"name": "NEW_VALUE", "value": "true"},
                            {"name": "SETTING_NAME", "value": "Apps Access Setting allow_all_internal_apps"},
                            {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                            {"name": "GROUP_EMAIL", "value": "test@test"},
                            {"name": "APPLICATION_NAME", "value": "Security"}
                        ]
                    },
                ]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedGroup := [{"Name": "test@test",
                     "Value": NonComplianceMessage11_1(false)}]
    FailTestGroupNonCompliant(PolicyId, Output, failedGroup)
}
#--
