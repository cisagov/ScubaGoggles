package commoncontrols

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.COMMONCONTROLS.4.1
#--
test_Limit_Correct_V1 if {
    # Test 1 event
    PolicyId := CommonControlsId4_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "43200"},
                        {"name": "SETTING_NAME", "value": "Session management settings - Session length in seconds"},
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

test_Limit_Correct_V2 if {
    # Test 1 event, smaller limit than needed
    PolicyId := CommonControlsId4_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "3600"},
                        {"name": "SETTING_NAME", "value": "Session management settings - Session length in seconds"},
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

test_Limit_Correct_V3 if {
    # Test multiple events
    PolicyId := CommonControlsId4_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "3600"},
                        {"name": "SETTING_NAME", "value": "Session management settings - Session length in seconds"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "86400"},
                        {"name": "SETTING_NAME", "value": "Session management settings - Session length in seconds"},
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

test_Limit_Correct_V4 if {
    # Test 1 event, tenant_info["topLevelOU"] empty
    PolicyId := CommonControlsId4_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "3600"},
                        {"name": "SETTING_NAME", "value": "Session management settings - Session length in seconds"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "" # The rego should needs to be able to infer the top-level OU if it's not provided here
            # input.tenant_info.topLevelOU will be empty when
            # no custom OUs have been created, as in this case
            # the top-level OU cannot be determined via the API.
            # Fortunately, in this case, we know there's literally
            # only one OU, so we can grab the OU listed on any of
            # the events and know that it is the top-level OU
        }
    }

    PassTestResult(PolicyId, Output)
}

test_Limit_Correct_V5 if {
    # Test inheritance
    PolicyId := CommonControlsId4_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2020-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "43200"},
                        {"name": "SETTING_NAME", "value": "Session management settings - Session length in seconds"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "4320000"},
                        {"name": "SETTING_NAME", "value": "Session management settings - Session length in seconds"},
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
                        {"name": "SETTING_NAME", "value": "Session management settings - Session length in seconds"},
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

test_Limit_Incorrect_V1 if {
    # Test 1 event
    PolicyId := CommonControlsId4_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "86400"},
                        {"name": "SETTING_NAME", "value": "Session management settings - Session length in seconds"},
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
                 "Value": NonComplianceMessage4_1(GetFriendlyValue4_1(86400))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Limit_Incorrect_V2 if {
    # Test multiple events
    PolicyId := CommonControlsId4_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "86400"},
                        {"name": "SETTING_NAME", "value": "Session management settings - Session length in seconds"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "43200"},
                        {"name": "SETTING_NAME", "value": "Session management settings - Session length in seconds"},
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
                 "Value": NonComplianceMessage4_1(GetFriendlyValue4_1(86400))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Limit_Incorrect_V3 if {
    # Test multiple OUs
    PolicyId := CommonControlsId4_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "86400"},
                        {"name": "SETTING_NAME", "value": "Session management settings - Session length in seconds"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Security"}
                    ]
                }]
            },
            {
                "id": {"time": "2023-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "43200"},
                        {"name": "SETTING_NAME", "value": "Session management settings - Session length in seconds"},
                        {"name": "ORG_UNIT_NAME", "value": "Custom OU"},
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
                 "Value": NonComplianceMessage4_1(GetFriendlyValue4_1(86400))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Limit_Incorrect_V4 if {
    # Test no relevant events
    PolicyId := CommonControlsId4_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_Limit_Incorrect_V5 if {
    # Test no relevant events in top-level OU
    PolicyId := CommonControlsId4_1
    Output := tests with input as {
        "commoncontrols_logs": {"items": [
            {
                "id": {"time": "2023-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "43200"},
                        {"name": "SETTING_NAME", "value": "Session management settings - Session length in seconds"},
                        {"name": "ORG_UNIT_NAME", "value": "Custom OU"},
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
#--
