package chat

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodChatApi04 := {
    "policies": {
        "topOU": {
            "chat_external_chat_restriction": {
                "allowExternalChat": false,
                "externalChatRestriction": "TRUSTED_DOMAINS"},
            "chat_service_status": {"serviceState": "ENABLED"}
        },
         "nextOU": {
            "chat_external_chat_restriction": {
                "allowExternalChat": true,
                "externalChatRestriction": "TRUSTED_DOMAINS"}
        },
        "thirdOU": {
            "chat_external_chat_restriction": {
                "allowExternalChat": true,
                "externalChatRestriction": "NO_RESTRICTION"},
            "chat_service_status": {"serviceState": "DISABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadChatApi04 := {
    "policies": {
        "topOU": {
            "chat_external_chat_restriction": {
                "allowExternalChat": true,
                "externalChatRestriction": "NO_RESTRICTION"},
            "chat_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadChatApi04a := {
    "policies": {
        "topOU": {
            "chat_external_chat_restriction": {
                "allowExternalChat": true,
                "externalChatRestriction": "TRUSTED_DOMAINS"},
            "chat_service_status": {"serviceState": "ENABLED"}
        },
        "secondOU": {
            "chat_external_chat_restriction": {
                "allowExternalChat": true,
                "externalChatRestriction": "RESTRICTION_UNSPECIFIED"},
        },
        "thirdOU": {
            "chat_space_history": {"historyState": "HISTORY_STATE_UNSPECIFIED"}
        },
     },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_ChatAPI_External_Messages_Correct_1 if {
    PolicyId := ChatId4_1
    Output := tests with input as GoodChatApi04

    PassTestResult(PolicyId, Output)
}

test_ChatAPI_External_Messages_Incorrect_1 if {
    PolicyId := ChatId4_1
    Output := tests with input as BadChatApi04

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage4_1("all domains")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ChatAPI_External_Messages_Incorrect_2 if {
    PolicyId := ChatId4_1
    Output := tests with input as BadChatApi04a

    failedOU := [{"Name": "secondOU",
                 "Value": NonComplianceMessage4_1("Unspecified")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
