package chat

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodChatApi01 := {
    "policies": {
        "topOU": {
            "chat_chat_history": {"allowUserModification": false,
                                    "historyOnByDefault": true},
            "chat_service_status": {"serviceState": "ENABLED"}
        },
         "nextOU": {
            "chat_chat_history": {"allowUserModification": true,
                                    "historyOnByDefault": false},
            "chat_service_status": {"serviceState": "DISABLED"}
        },
        "thirdOU": {
            "security_session_controls": {
                "webSessionDuration": "700m"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadChatApi01 := {
    "policies": {
        "topOU": {
            "chat_chat_history": {"allowUserModification": true,
                                    "historyOnByDefault": false},
            "chat_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_ChatAPI_History_Correct_1 if {
    PolicyId := ChatId1_1
    Output := tests with input as GoodChatApi01

    PassTestResult(PolicyId, Output)
}

test_ChatAPI_History_Incorrect_1 if {
    PolicyId := ChatId1_1
    Output := tests with input as BadChatApi01

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage1_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ChatAPI_Change_History_Correct_1 if {
    PolicyId := ChatId1_2
    Output := tests with input as GoodChatApi01

    PassTestResult(PolicyId, Output)
}

test_ChatAPI_Change_History_Incorrect_1 if {
    PolicyId := ChatId1_2
    Output := tests with input as BadChatApi01

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage1_2("are")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
