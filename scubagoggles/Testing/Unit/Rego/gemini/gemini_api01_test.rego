package gemini

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGeminiApi01 := {
    "policies": {
        "topOU": {
            "gemini_app_unlicensed_user_access": {"enabled": false},
            "gemini_app_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGeminiApi01 := {
    "policies": {
        "topOU": {
            "gemini_app_unlicensed_user_access": {"enabled": true},
            "gemini_app_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

#
# GWS.GEMINI.1.1
#--

test_UnlicensedAccess_Correct_1 if {
    PolicyId := GeminiId1_1
    Output := tests with input as GoodGeminiApi01

    PassTestResult(PolicyId, Output)
}

test_UnlicensedAccess_Correct_2 if {
    # Unlicensed access allowed but Gemini disabled for OU
    PolicyId := GeminiId1_1
    Output := tests with input as {
        "policies": {
            "topOU": {
                "gemini_app_unlicensed_user_access": {"enabled": true},
                "gemini_app_service_status": {"serviceState": "DISABLED"}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_UnlicensedAccess_Incorrect_1 if {
    PolicyId := GeminiId1_1
    Output := tests with input as BadGeminiApi01

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage1_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_UnlicensedAccess_Incorrect_2 if {
    # Child OU override enables unlicensed access
    PolicyId := GeminiId1_1
    Output := tests with input as {
        "policies": {
            "topOU": {
                "gemini_app_unlicensed_user_access": {"enabled": false},
                "gemini_app_service_status": {"serviceState": "ENABLED"}
            },
            "nextOU": {
                "gemini_app_unlicensed_user_access": {"enabled": true},
                "gemini_app_service_status": {"serviceState": "ENABLED"}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage1_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--
