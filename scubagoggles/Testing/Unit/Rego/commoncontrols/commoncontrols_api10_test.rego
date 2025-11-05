package commoncontrols

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCaseInputApi10 := {
    "policies": {
        "topOU": {
            "security_less_secure_apps": {"allowLessSecureApps": false}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi10 := {
    "policies": {
        "topOU": {
            "security_less_secure_apps": {"allowLessSecureApps": true}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_LessSecureApps_Correct_1 if {
    PolicyId := CommonControlsId10_5
    Output := tests with input as GoodCaseInputApi10

    PassTestResult(PolicyId, Output)
}

test_LessSecureApps_Incorrect_1 if {
    PolicyId := CommonControlsId10_5
    Output := tests with input as BadCaseInputApi10

    failedOU := [{"Name": "topOU",
                  "Value": NonComplianceMessage10_5}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
