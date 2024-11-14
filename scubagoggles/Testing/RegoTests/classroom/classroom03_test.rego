package classroom
import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.FailTestNoEvent
import data.utils.PassTestResult

# GWS.CLASSROOM.3.1
#--

test_CleverRosterDisabled_Correct_V1 if {
    # Test Clever Roster is disabled when there's only one event
    PolicyId := ClassroomId3_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SIS_INTEGRATOR_NONE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
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

test_CleverRosterDisabled_Correct_V2 if {
    # Test enforcing Clever Roster is disabled when there's multiple events, with the chronological latest
    # correct but not last in json list
    PolicyId := ClassroomId3_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SIS_INTEGRATOR_NONE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SIS_INTEGRATOR_CLEVER"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
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

test_CleverRosterDisabled_Correct_V3 if {
    # Test enforcing Clever Roster is disabled is correct when there are events in multiple OUs
    PolicyId := ClassroomId3_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SIS_INTEGRATOR_NONE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SIS_INTEGRATOR_NONE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    PassTestResult(PolicyId, Output)
}

test_CleverRosterDisabled_Correct_V4 if {
    # Test Clever Roster is disabled when set to inherit from parent
    PolicyId := ClassroomId3_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2020-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SIS_INTEGRATOR_NONE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SIS_INTEGRATOR_CLEVER"},
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

test_CleverRosterDisabled_Incorrect_V1 if {
    # Test Clever Roster is disabled when there's only one event and it's wrong
    PolicyId := ClassroomId3_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SIS_INTEGRATOR_CLEVER"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage3_1("ON - CLEVER")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_CleverRosterDisabled_Incorrect_V2 if {
    # Test Clever Roster is disabled when there's multiple events, with the chronological latest
    # incorrect but not last in json list
    PolicyId := ClassroomId3_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SIS_INTEGRATOR_CLEVER"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SIS_INTEGRATOR_NONE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage3_1("ON - CLEVER")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}


test_CleverRosterDisabled_Incorrect_V3 if {
    # Test Clever Roster is disabled when there no applicable event
    PolicyId := ClassroomId3_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "something else"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}

test_CleverRosterDisabled_Incorrect_V4 if {
    # Test allow Clever Roster is disabled when there are multiple OU and a secondary OU is wrong
    PolicyId := ClassroomId3_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SIS_INTEGRATOR_NONE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SIS_INTEGRATOR_CLEVER"},
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
                 "Value": NonComplianceMessage3_1("ON - CLEVER")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--

test_CleverRosterDisabled_Incorrect_V5 if {
    # Test Clever Roster is disabled when the primary OU is missing but a different one is present
    PolicyId := ClassroomId3_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SIS_INTEGRATOR_CLEVER"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
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

test_CleverRosterDisabled_Incorrect_V6 if {
    # Test Clever Roster is disabled access when there's only one event and it's wrong
    PolicyId := ClassroomId3_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
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
                 "Value": NonComplianceMessage3_1("SAME_DOMAIN")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_CleverRosterDisabled_Incorrect_V7 if {
    # Test Clever Roster is disabled when there are multiple events and the most recent is wrong
    PolicyId := ClassroomId3_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SIS_INTEGRATOR_NONE"},
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
                 "Value": NonComplianceMessage3_1("SAME_DOMAIN")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_CleverRosterDisabled_Incorrect_V8 if {
    # Test Clever Roster is disabled when there are multiple OU and a secondary OU is wrong
    PolicyId := ClassroomId3_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SIS_INTEGRATOR_NONE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
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
                 "Value": NonComplianceMessage3_1("SAME_DOMAIN")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--

test_CleverRosterDisabled_Incorrect_V9 if {
    # Test Clever Roster is disabled when the primary OU is missing but a different one is present
    PolicyId := ClassroomId3_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "RosterImportSettingsProto sis_integrator"},
                        {"name": "NEW_VALUE", "value": "SIS_INTEGRATOR_NONE"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
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
#--
