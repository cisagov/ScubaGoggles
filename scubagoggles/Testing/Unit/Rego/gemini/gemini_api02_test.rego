package gemini

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGeminiApi02 := {
    "policies": {
        "topOU": {
            "gemini_for_workspace_beta_features": {"enabled": false}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGeminiApi02 := {
    "policies": {
        "topOU": {
            "gemini_for_workspace_beta_features": {"enabled": true}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

#
# GWS.GEMINI.2.1
#--

test_BetaFeatures_Correct_1 if {
    PolicyId := GeminiId2_1
    Output := tests with input as GoodGeminiApi02

    PassTestResult(PolicyId, Output)
}

test_BetaFeatures_Incorrect_1 if {
    PolicyId := GeminiId2_1
    Output := tests with input as BadGeminiApi02

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage2_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_BetaFeatures_Incorrect_2 if {
    # Beta features enabled even when Gemini app is disabled
    PolicyId := GeminiId2_1
    Output := tests with input as {
        "policies": {
            "topOU": {
                "gemini_for_workspace_beta_features": {"enabled": true},
                "gemini_app_service_status": {"serviceState": "DISABLED"}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage2_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_BetaFeatures_Incorrect_3 if {
    # Child OU override enables beta features
    PolicyId := GeminiId2_1
    Output := tests with input as {
        "policies": {
            "topOU": {
                "gemini_for_workspace_beta_features": {"enabled": false}
            },
            "nextOU": {
                "gemini_for_workspace_beta_features": {"enabled": true}
            }
        },
        "tenant_info": {
            "topLevelOU": "topOU"
        }
    }

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage2_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--
