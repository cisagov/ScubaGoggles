package classroom
import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.FailTestNoEvent
import data.utils.PassTestResult

#
# GWS.CLASSROOM.4.1
#--

test_UnenrollStudents_Correct_V1 if {
    # Test only teachers can unenroll students when there's only one event
    PolicyId := ClassroomId4_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
                        {"name": "NEW_VALUE", "value": "ONLY_TEACHERS_CAN_UNENROLL_STUDENTS"},
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

test_UnenrollStudents_Correct_V2 if {
    # Test enforcing only teachers can unenroll students when there's multiple events, with the chronological latest
    # correct but not last in json list
    PolicyId := ClassroomId4_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
                        {"name": "NEW_VALUE", "value": "ONLY_TEACHERS_CAN_UNENROLL_STUDENTS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
                        {"name": "NEW_VALUE", "value": "STUDENTS_AND_TEACHERS_CAN_UNENROLL_STUDENTS"},
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

test_UnenrollStudents_Correct_V3 if {
    # Test enforcing only teachers can unenroll students is correct when there are events in multiple OUs
    PolicyId := ClassroomId4_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
                        {"name": "NEW_VALUE", "value": "ONLY_TEACHERS_CAN_UNENROLL_STUDENTS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
                        {"name": "NEW_VALUE", "value": "ONLY_TEACHERS_CAN_UNENROLL_STUDENTS"},
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

test_UnenrollStudents_Correct_V4 if {
    # Test only teachers can unenroll students when set to inherit from parent
    PolicyId := ClassroomId4_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2020-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
                        {"name": "NEW_VALUE", "value": "ONLY_TEACHERS_CAN_UNENROLL_STUDENTS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "name": "DELETE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Second-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
                        {"name": "NEW_VALUE", "value": "STUDENTS_AND_TEACHERS_CAN_UNENROLL_STUDENTS"},
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

test_UnenrollStudents_Incorrect_V1 if {
    # Test only teachers can unenroll students when there's only one event and it's wrong
    PolicyId := ClassroomId4_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
                        {"name": "NEW_VALUE", "value": "STUDENTS_AND_TEACHERS_CAN_UNENROLL_STUDENTS"},
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
                 "Value": NonComplianceMessage4_1("Students and teachers")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_UnenrollStudents_Incorrect_V2 if {
    # Test only teachers can unenroll students when there's multiple events, with the chronological latest
    # incorrect but not last in json list
    PolicyId := ClassroomId4_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
                        {"name": "NEW_VALUE", "value": "STUDENTS_AND_TEACHERS_CAN_UNENROLL_STUDENTS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
                        {"name": "NEW_VALUE", "value": "ONLY_TEACHERS_CAN_UNENROLL_STUDENTS"},
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
                 "Value": NonComplianceMessage4_1("Students and teachers")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}


test_UnenrollStudents_Incorrect_V3 if {
    # Test only teachers can unenroll students when there no applicable event
    PolicyId := ClassroomId4_1
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

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", false)
}

test_UnenrollStudents_Incorrect_V4 if {
    # Test allow only teachers can unenroll students when there are multiple OU and a secondary OU is wrong
    PolicyId := ClassroomId4_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
                        {"name": "NEW_VALUE", "value": "ONLY_TEACHERS_CAN_UNENROLL_STUDENTS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
                        {"name": "NEW_VALUE", "value": "STUDENTS_AND_TEACHERS_CAN_UNENROLL_STUDENTS"},
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
                 "Value": NonComplianceMessage4_1("Students and teachers")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--

test_UnenrollStudents_Incorrect_V5 if {
    # Test only teachers can unenroll students when the primary OU is missing but a different one is present
    PolicyId := ClassroomId4_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
                        {"name": "NEW_VALUE", "value": "STUDENTS_AND_TEACHERS_CAN_UNENROLL_STUDENTS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
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

test_UnenrollStudents_Incorrect_V6 if {
    # Test only teachers can unenroll students access when there's only one event and it's wrong
    PolicyId := ClassroomId4_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
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
                 "Value": NonComplianceMessage4_1("SAME_DOMAIN")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_UnenrollStudents_Incorrect_V7 if {
    # Test only teachers can unenroll students when there are multiple events and the most recent is wrong
    PolicyId := ClassroomId4_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
                        {"name": "NEW_VALUE", "value": "SAME_DOMAIN"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
                        {"name": "NEW_VALUE", "value": "ONLY_TEACHERS_CAN_UNENROLL_STUDENTS"},
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
                 "Value": NonComplianceMessage4_1("SAME_DOMAIN")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_UnenrollStudents_Incorrect_V8 if {
    # Test only teachers can unenroll students when there are multiple OU and a secondary OU is wrong
    PolicyId := ClassroomId4_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
                        {"name": "NEW_VALUE", "value": "ONLY_TEACHERS_CAN_UNENROLL_STUDENTS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
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
                 "Value": NonComplianceMessage4_1("SAME_DOMAIN")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--

test_UnenrollStudents_Incorrect_V9 if {
    # Test only teachers can unenroll students when the primary OU is missing but a different one is present
    PolicyId := ClassroomId4_1
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "StudentUnenrollmentSettingsProto who_can_unenroll_students"},
                        {"name": "NEW_VALUE", "value": "ONLY_TEACHERS_CAN_UNENROLL_STUDENTS"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Secondary OU"},
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
#--
