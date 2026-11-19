package gemini

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGeminiApi04 := {
    "policies": {
        "topOU": {
            "gemini_app_conversation_sharing": {
                "conversationSharingOption": "DISABLED"
            },
            "gemini_app_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGeminiApi04 := {
    "policies": {
        "topOU": {
            "gemini_app_conversation_sharing": {
                "conversationSharingOption": "ALLOW_SHARING_VIA_LINK"
            },
            "gemini_app_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

#
# GWS.GEMINI.4.1
#--

test_ConversationSharing_Correct_1 if {
    PolicyId := GeminiId4_1
    Output := tests with input as GoodGeminiApi04

    PassTestResult(PolicyId, Output)
}

test_ConversationSharing_Correct_2 if {
    # Sharing enabled but Gemini app disabled for OU
    PolicyId := GeminiId4_1
    Output := tests with input as {
        "policies": {
            "topOU": {
                "gemini_app_conversation_sharing": {
                    "conversationSharingOption": "ALLOW_SHARING_VIA_LINK"
                },
                "gemini_app_service_status": {"serviceState": "DISABLED"}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_ConversationSharing_Incorrect_1 if {
    PolicyId := GeminiId4_1
    Output := tests with input as BadGeminiApi04

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage4_1("Allow sharing via link")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ConversationSharing_Incorrect_2 if {
    # Sharing via Drive is also non-compliant
    PolicyId := GeminiId4_1
    Output := tests with input as {
        "policies": {
            "topOU": {
                "gemini_app_conversation_sharing": {
                    "conversationSharingOption": "ALLOW_SHARING_VIA_DRIVE"
                },
                "gemini_app_service_status": {"serviceState": "ENABLED"}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage4_1("Allow sharing via Drive")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ConversationSharing_Incorrect_3 if {
    # Child OU override enables conversation sharing
    PolicyId := GeminiId4_1
    Output := tests with input as {
        "policies": {
            "topOU": {
                "gemini_app_conversation_sharing": {
                    "conversationSharingOption": "DISABLED"
                },
                "gemini_app_service_status": {"serviceState": "ENABLED"}
            },
            "nextOU": {
                "gemini_app_conversation_sharing": {
                    "conversationSharingOption": "ALLOW_SHARING_VIA_LINK"
                },
                "gemini_app_service_status": {"serviceState": "ENABLED"}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage4_1("Allow sharing via link")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--
