package classroom
import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.FailTestNoEvent
import data.utils.PassTestResult

#
# GWS.CLASSROOM.5.1
#--

test_ClassroomCreation_Correct_V1 if {
    # Test only teachers can unenroll students when there's only one event
    PolicyId := ClassroomId5_1
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

    PassTestResult(PolicyId, Output)
}

test_ClassroomCreation_Correct_V2 if {
    # Test when there's multiple events, with the chronological latest
    # correct but not last in json list
    PolicyId := ClassroomId5_1
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

    PassTestResult(PolicyId, Output)
}

# No tests for multiple OUs, inheritance, groups, etc as this setting can't be controlled at the OU or group level

test_ClassroomCreation_Incorrect_V1 if {
    # Test when there's only one event and it's wrong
    PolicyId := ClassroomId5_1
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

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage5_1("anyone in this domain")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ClassroomCreation_Incorrect_V2 if {
    # Test when there's multiple events, with the chronological latest
    # incorrect but not last in json list
    PolicyId := ClassroomId5_1
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

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage5_1("all pending and verified teachers")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ClassroomCreation_Incorrect_V3 if {
    # Test when there no applicable event
    PolicyId := ClassroomId5_1
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
