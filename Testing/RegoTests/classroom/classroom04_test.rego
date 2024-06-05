package classroom
import future.keywords

#
# GWS.CLASSROOM.4.1v0.2
#--

test_UnenrollStudents_Correct_V1 if {
    # Test only teachers can unenroll students when there's only one event
    PolicyId := "GWS.CLASSROOM.4.1v0.2"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_UnenrollStudents_Correct_V2 if {
    # Test enforcing only teachers can unenroll students when there's multiple events, with the chronological latest
    # correct but not last in json list
    PolicyId := "GWS.CLASSROOM.4.1v0.2"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_UnenrollStudents_Correct_V3 if {
    # Test enforcing only teachers can unenroll students is correct when there are events in multiple OUs
    PolicyId := "GWS.CLASSROOM.4.1v0.2"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_UnenrollStudents_Correct_V4 if {
    # Test only teachers can unenroll students when set to inherit from parent
    PolicyId := "GWS.CLASSROOM.4.1v0.2"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met in all OUs and groups."
}

test_UnenrollStudents_Incorrect_V1 if {
    # Test only teachers can unenroll students when there's only one event and it's wrong
    PolicyId := "GWS.CLASSROOM.4.1v0.2"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "Who can unenroll students from classes is set to Students and teachers</li></ul>"
    ])
}

test_UnenrollStudents_Incorrect_V2 if {
    # Test only teachers can unenroll students when there's multiple events, with the chronological latest
    # incorrect but not last in json list
    PolicyId := "GWS.CLASSROOM.4.1v0.2"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "Who can unenroll students from classes is set to Students and teachers</li></ul>"
    ])
}


test_UnenrollStudents_Incorrect_V3 if {
    # Test only teachers can unenroll students when there no applicable event
    PolicyId := "GWS.CLASSROOM.4.1v0.2"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is compliant; manual check recommended."
    ])
}
test_UnenrollStudents_Incorrect_V4 if {
    # Test allow only teachers can unenroll students when there are multiple OU and a secondary OU is wrong
    PolicyId := "GWS.CLASSROOM.4.1v0.2"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul><li>Test Secondary OU: ",
        "Who can unenroll students from classes is set to Students and teachers</li></ul>"
    ])
}
#--

test_UnenrollStudents_Incorrect_V5 if {
    # Test only teachers can unenroll students when the primary OU is missing but a different one is present
    PolicyId := "GWS.CLASSROOM.4.1v0.2"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is compliant; manual check recommended."
    ])
}

test_UnenrollStudents_Incorrect_V6 if {
    # Test only teachers can unenroll students access when there's only one event and it's wrong
    PolicyId := "GWS.CLASSROOM.4.1v0.2"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "Who can unenroll students from classes is set to SAME_DOMAIN</li></ul>"
    ])
}

test_UnenrollStudents_Incorrect_V7 if {
    # Test only teachers can unenroll students when there are multiple events and the most recent is wrong
    PolicyId := "GWS.CLASSROOM.4.1v0.2"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul><li>Test Top-Level OU: ",
        "Who can unenroll students from classes is set to SAME_DOMAIN</li></ul>"
    ])
}

test_UnenrollStudents_Incorrect_V8 if {
    # Test only teachers can unenroll students when there are multiple OU and a secondary OU is wrong
    PolicyId := "GWS.CLASSROOM.4.1v0.2"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "The following OUs are non-compliant:<ul><li>Test Secondary OU: ",
        "Who can unenroll students from classes is set to SAME_DOMAIN</li></ul>"
    ])
}
#--

test_UnenrollStudents_Incorrect_V9 if {
    # Test only teachers can unenroll students when the primary OU is missing but a different one is present
    PolicyId := "GWS.CLASSROOM.4.1v0.2"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is compliant; manual check recommended."
    ])
}
#--
