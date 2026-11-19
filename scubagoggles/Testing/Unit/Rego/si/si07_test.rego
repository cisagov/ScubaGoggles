package si
import future.keywords

import data.utils.FailTestGroupNonCompliant
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.SI.7.1
#--

test_DataRegions_Correct_V1 if {
    # Multi-region processing disabled for the top-level OU
    PolicyId := SIId7_1
    Output := tests with input as {
        "si_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME",
                         "value": "GeminiNonRegionalizedFunctionalityStateSettingsProto state"},
                        {"name": "NEW_VALUE", "value": "DISABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
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

test_DataRegions_Correct_V2 if {
    # Most recent event disables multi-region processing
    PolicyId := SIId7_1
    Output := tests with input as {
        "si_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME",
                         "value": "GeminiNonRegionalizedFunctionalityStateSettingsProto state"},
                        {"name": "NEW_VALUE", "value": "DISABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME",
                         "value": "GeminiNonRegionalizedFunctionalityStateSettingsProto state"},
                        {"name": "NEW_VALUE", "value": "ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
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

test_DataRegions_Correct_V3 if {
    # Data regions settings for other GWS products are not evaluated
    PolicyId := SIId7_1
    Output := tests with input as {
        "si_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME",
                         "value": "GeminiNonRegionalizedFunctionalityStateSettingsProto state"},
                        {"name": "NEW_VALUE", "value": "DISABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME",
                         "value": "CalendarNonRegionalizedFunctionalityStateSettingsProto state"},
                        {"name": "NEW_VALUE", "value": "ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
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

test_DataRegions_Incorrect_V1 if {
    # Multi-region processing enabled for the top-level OU
    PolicyId := SIId7_1
    Output := tests with input as {
        "si_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME",
                         "value": "GeminiNonRegionalizedFunctionalityStateSettingsProto state"},
                        {"name": "NEW_VALUE", "value": "ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                  "Value": NonComplianceMessage7_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_DataRegions_Incorrect_V2 if {
    # Most recent event enables multi-region processing
    PolicyId := SIId7_1
    Output := tests with input as {
        "si_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME",
                         "value": "GeminiNonRegionalizedFunctionalityStateSettingsProto state"},
                        {"name": "NEW_VALUE", "value": "ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME",
                         "value": "GeminiNonRegionalizedFunctionalityStateSettingsProto state"},
                        {"name": "NEW_VALUE", "value": "DISABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                  "Value": NonComplianceMessage7_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_DataRegions_Incorrect_V3 if {
    # No events
    PolicyId := SIId7_1
    Output := tests with input as {
        "si_logs": {"items": []},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_DataRegions_Incorrect_V4 if {
    # Events only for the data regions settings of other GWS products
    PolicyId := SIId7_1
    Output := tests with input as {
        "si_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME",
                         "value": "MeetNonRegionalizedFunctionalityStateSettingsProto state"},
                        {"name": "NEW_VALUE", "value": "DISABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
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

test_DataRegions_Incorrect_V5 if {
    # Disabled for the top-level OU but enabled for a child OU
    PolicyId := SIId7_1
    Output := tests with input as {
        "si_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME",
                         "value": "GeminiNonRegionalizedFunctionalityStateSettingsProto state"},
                        {"name": "NEW_VALUE", "value": "DISABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME",
                         "value": "GeminiNonRegionalizedFunctionalityStateSettingsProto state"},
                        {"name": "NEW_VALUE", "value": "ENABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Second-Level OU",
                  "Value": NonComplianceMessage7_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_DataRegions_Incorrect_V6 if {
    # Disabled for the top-level OU but enabled for a group
    PolicyId := SIId7_1
    Output := tests with input as {
        "si_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME",
                         "value": "GeminiNonRegionalizedFunctionalityStateSettingsProto state"},
                        {"name": "NEW_VALUE", "value": "DISABLED"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME",
                         "value": "GeminiNonRegionalizedFunctionalityStateSettingsProto state"},
                        {"name": "NEW_VALUE", "value": "ENABLED"},
                        {"name": "GROUP_EMAIL", "value": "group1"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Data regions"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedGroup := [{"Name": "group1",
                     "Value": NonComplianceMessage7_1}]
    FailTestGroupNonCompliant(PolicyId, Output, failedGroup)
}
#--
