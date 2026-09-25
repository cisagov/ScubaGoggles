package chat

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodChatApi02 := {
    "policies": {
        "topOU": {
            "chat_chat_file_sharing": {"externalFileSharing": "NO_FILES",
                                       "internalFileSharing": "ALL_FILES"},
            "chat_service_status": {"serviceState": "ENABLED"}
        },
         "nextOU": {
            "chat_chat_file_sharing": {"externalFileSharing": "IMAGES_ONLY",
                                       "internalFileSharing": "ALL_FILES"},
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

BadChatApi02 := {
    "policies": {
        "topOU": {
            "chat_chat_file_sharing": {"externalFileSharing": "IMAGES_ONLY",
                                       "internalFileSharing": "FILE_SHARING_OPTION_UNSPECIFIED"},
            "chat_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_ChatAPI_External_Sharing_Correct_1 if {
    PolicyId := ChatId2_1
    Output := tests with input as GoodChatApi02

    PassTestResult(PolicyId, Output)
}

test_ChatAPI_External_Sharing_Incorrect_1 if {
    PolicyId := ChatId2_1
    Output := tests with input as BadChatApi02

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage2_1("Images only")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
