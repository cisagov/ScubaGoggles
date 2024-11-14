package commoncontrols

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCaseInputApi09 := {
    "policies": {
        "topOU": {
            "security_advanced_protection_program": {
                "enableAdvancedProtectionSelfEnrollment": true
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi09 := {
    "policies": {
        "topOU": {
            "security_advanced_protection_program": {
                "enableAdvancedProtectionSelfEnrollment": false
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_HighPrivAccountsAPP_Correct_1 if {
    PolicyId := CommonControlsId9_1
    Output := tests with input as GoodCaseInputApi09

    PassTestResult(PolicyId, Output)
}

test_HighPrivAccountsAPP_Incorrect_1 if {
    PolicyId := CommonControlsId9_1
    Output := tests with input as BadCaseInputApi09

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage9_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SensitiveAccountsAPP_Correct_1 if {
    PolicyId := CommonControlsId9_2
    Output := tests with input as GoodCaseInputApi09

    PassTestResult(PolicyId, Output)
}

test_SensitiveAccountsAPP_Incorrect_1 if {
    PolicyId := CommonControlsId9_2
    Output := tests with input as BadCaseInputApi09

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage9_2}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
