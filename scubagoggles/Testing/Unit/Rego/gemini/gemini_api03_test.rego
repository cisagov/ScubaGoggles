package gemini

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGeminiApi03 := {
    "policies": {
        "topOU": {
            "gemini_app_conversation_history": {
                "conversationHistoryState": "ENABLED",
                "conversationRetention": "EIGHTEEN_MONTHS"
            },
            "gemini_app_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGeminiApi03History := {
    "policies": {
        "topOU": {
            "gemini_app_conversation_history": {
                "conversationHistoryState": "DISABLED",
                "conversationRetention": "EIGHTEEN_MONTHS"
            },
            "gemini_app_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGeminiApi03Retention := {
    "policies": {
        "topOU": {
            "gemini_app_conversation_history": {
                "conversationHistoryState": "ENABLED",
                "conversationRetention": "THREE_MONTHS"
            },
            "gemini_app_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

#
# GWS.GEMINI.3.1
#--

test_ConversationHistory_Correct_1 if {
    PolicyId := GeminiId3_1
    Output := tests with input as GoodGeminiApi03

    PassTestResult(PolicyId, Output)
}

test_ConversationHistory_Correct_2 if {
    # History disabled but Gemini app disabled for OU
    PolicyId := GeminiId3_1
    Output := tests with input as {
        "policies": {
            "topOU": {
                "gemini_app_conversation_history": {
                    "conversationHistoryState": "DISABLED",
                    "conversationRetention": "EIGHTEEN_MONTHS"
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

test_ConversationHistory_Incorrect_1 if {
    PolicyId := GeminiId3_1
    Output := tests with input as BadGeminiApi03History

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage3_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ConversationHistory_Incorrect_2 if {
    # Child OU override disables conversation history
    PolicyId := GeminiId3_1
    Output := tests with input as {
        "policies": {
            "topOU": {
                "gemini_app_conversation_history": {
                    "conversationHistoryState": "ENABLED",
                    "conversationRetention": "EIGHTEEN_MONTHS"
                },
                "gemini_app_service_status": {"serviceState": "ENABLED"}
            },
            "nextOU": {
                "gemini_app_conversation_history": {
                    "conversationHistoryState": "DISABLED",
                    "conversationRetention": "EIGHTEEN_MONTHS"
                },
                "gemini_app_service_status": {"serviceState": "ENABLED"}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage3_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--

#
# GWS.GEMINI.3.2
#--

test_ConversationRetention_Correct_1 if {
    PolicyId := GeminiId3_2
    Output := tests with input as GoodGeminiApi03

    PassTestResult(PolicyId, Output)
}

test_ConversationRetention_Correct_2 if {
    # 36 months also meets the minimum of 18 months
    PolicyId := GeminiId3_2
    Output := tests with input as {
        "policies": {
            "topOU": {
                "gemini_app_conversation_history": {
                    "conversationHistoryState": "ENABLED",
                    "conversationRetention": "THIRTY_SIX_MONTHS"
                },
                "gemini_app_service_status": {"serviceState": "ENABLED"}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_ConversationRetention_Correct_3 if {
    # Short retention but Gemini app disabled for OU
    PolicyId := GeminiId3_2
    Output := tests with input as {
        "policies": {
            "topOU": {
                "gemini_app_conversation_history": {
                    "conversationHistoryState": "ENABLED",
                    "conversationRetention": "THREE_MONTHS"
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

test_ConversationRetention_Incorrect_1 if {
    PolicyId := GeminiId3_2
    Output := tests with input as BadGeminiApi03Retention

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage3_2("3 months")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ConversationRetention_Incorrect_2 if {
    # Child OU override sets retention below 18 months
    PolicyId := GeminiId3_2
    Output := tests with input as {
        "policies": {
            "topOU": {
                "gemini_app_conversation_history": {
                    "conversationHistoryState": "ENABLED",
                    "conversationRetention": "EIGHTEEN_MONTHS"
                },
                "gemini_app_service_status": {"serviceState": "ENABLED"}
            },
            "nextOU": {
                "gemini_app_conversation_history": {
                    "conversationHistoryState": "ENABLED",
                    "conversationRetention": "THREE_MONTHS"
                },
                "gemini_app_service_status": {"serviceState": "ENABLED"}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage3_2("3 months")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--
