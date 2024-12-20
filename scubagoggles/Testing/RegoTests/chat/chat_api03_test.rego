package chat

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodChatApi03 := {
    "policies": {
        "topOU": {
            "chat_space_history": {"historyState": "DEFAULT_HISTORY_ON"},
            "chat_service_status": {"serviceState": "ENABLED"}
        },
         "nextOU": {
            "chat_space_history": {"historyState": "HISTORY_ALWAYS_ON"}
        },
        "thirdOU": {
            "security_session_controls": {
                "webSessionDuration": "700m"
            }
        },
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadChatApi03 := {
    "policies": {
        "topOU": {
            "chat_space_history": {"historyState": "DEFAULT_HISTORY_OFF"},
            "chat_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadChatApi03a := {
    "policies": {
        "topOU": {
            "chat_space_history": {"historyState": "HISTORY_ALWAYS_ON"},
            "chat_service_status": {"serviceState": "ENABLED"}
        },
        "secondOU": {
            "chat_space_history": {"historyState": "HISTORY_ALWAYS_OFF"}
        },
        "thirdOU": {
            "chat_space_history": {"historyState": "HISTORY_STATE_UNSPECIFIED"}
        },
     },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_ChatAPI_Space_History_Correct_1 if {
    PolicyId := ChatId3_1
    Output := tests with input as GoodChatApi03

    PassTestResult(PolicyId, Output)
}

test_ChatAPI_Space_History_Incorrect_1 if {
    PolicyId := ChatId3_1
    Output := tests with input as BadChatApi03

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage3_1("OFF by default")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ChatAPI_Space_History_Incorrect_2 if {
    PolicyId := ChatId3_1
    Output := tests with input as BadChatApi03a

    failedOU := [{"Name": "secondOU",
                 "Value": NonComplianceMessage3_1("ALWAYS OFF")},
                 {"Name": "thirdOU",
                 "Value": NonComplianceMessage3_1("Unspecified")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
