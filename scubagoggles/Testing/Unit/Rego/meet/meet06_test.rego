package meet
import future.keywords

import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.MEET.6.1
#--

test_Sharing_Correct_V1 if {
    PolicyId := MeetId6_1
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "SETTING_NAME", "value": "MeetGenAiSmartNotesDocAccessProto manage_smart_notes_doc_access"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Google Meet GenAI"}
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
    # Test not implemented
    PolicyId := MeetId6_1
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "SETTING_NAME", "value": "MeetGenAiSmartNotesDocAccessProto manage_smart_notes_doc_access"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Google Meet GenAI"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage6_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

#--

#
# GWS.MEET.6.1
#--

test_Default_Correct_V1 if {
    # Test not implemented
    PolicyId := MeetId6_2
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "IN_DOMAIN"},
                        {"name": "SETTING_NAME", "value": "MeetGenAiSmartNotesDocAccessProto default_smart_notes_doc_access"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Google Meet GenAI"}
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

test_Default_Correct_V1 if {
    # Test not implemented
    PolicyId := MeetId6_2
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "HOSTS_AND_COHOSTS_ONLY"},
                        {"name": "SETTING_NAME", "value": "MeetGenAiSmartNotesDocAccessProto default_smart_notes_doc_access"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Google Meet GenAI"}
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

test_Default_Incorrect_V1 if {
    # Test not implemented
    PolicyId := MeetId6_2
    Output := tests with input as {
        "meet_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "NEW_VALUE", "value": "EVERYONE"},
                        {"name": "SETTING_NAME", "value": "MeetGenAiSmartNotesDocAccessProto default_smart_notes_doc_access"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                        {"name": "APPLICATION_NAME", "value": "Google Meet GenAI"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage6_2}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--