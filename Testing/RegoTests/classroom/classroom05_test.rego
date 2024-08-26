package classroom
import future.keywords

#
# GWS.CLASSROOM.5.1v0.3
#--

test_ClassroomCreation_Correct_V1 if {
    # Test only teachers can unenroll students when there's only one event
    PolicyId := "GWS.CLASSROOM.5.1v0.3"
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "TeacherPermissionsSettingProto who_can_create_class"},
                        {"name": "NEW_VALUE", "value": "3"},
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

test_ClassroomCreation_Correct_V2 if {
    # Test when there's multiple events, with the chronological latest
    # correct but not last in json list
    PolicyId := "GWS.CLASSROOM.5.1v0.3"
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "TeacherPermissionsSettingProto who_can_create_class"},
                        {"name": "NEW_VALUE", "value": "3"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "TeacherPermissionsSettingProto who_can_create_class"},
                        {"name": "NEW_VALUE", "value": "2"},
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

# No tests for multiple OUs, inheritance, groups, etc as this setting can't be controlled at the OU or group level

test_ClassroomCreation_Incorrect_V1 if {
    # Test when there's only one event and it's wrong
    PolicyId := "GWS.CLASSROOM.5.1v0.3"
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "TeacherPermissionsSettingProto who_can_create_class"},
                        {"name": "NEW_VALUE", "value": "1"},
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
        "Who can create classes is set to anyone in this domain</li></ul>"
    ])
}

test_ClassroomCreation_Incorrect_V2 if {
    # Test when there's multiple events, with the chronological latest
    # incorrect but not last in json list
    PolicyId := "GWS.CLASSROOM.5.1v0.3"
    Output := tests with input as {
        "classroom_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "TeacherPermissionsSettingProto who_can_create_class"},
                        {"name": "NEW_VALUE", "value": "2"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name":"SETTING_NAME",
                        "value": "TeacherPermissionsSettingProto who_can_create_class"},
                        {"name": "NEW_VALUE", "value": "3"},
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
        "Who can create classes is set to all pending and verified teachers</li></ul>"
    ])
}


test_ClassroomCreation_Incorrect_V3 if {
    # Test when there no applicable event
    PolicyId := "GWS.CLASSROOM.5.1v0.3"
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
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "No relevant event in the current logs for the top-level OU, Test Top-Level OU. ",
        "While we are unable to determine the state from the logs, the default setting ",
        "is non-compliant; manual check recommended."
    ])
}
