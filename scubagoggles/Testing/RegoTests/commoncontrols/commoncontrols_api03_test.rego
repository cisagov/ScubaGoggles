package commoncontrols

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCaseInputApi03 := {
    "policies": {
        "topOU": {
            "security_login_challenges": {
                "enableEmployeeIdChallenge": true
            }
        },
         "nextOU": {
            "security_login_challenges": {
                "enableEmployeeIdChallenge": true
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BaseCaseInputApi03 := {
    "policies": {
        "topOU": {
            "security_login_challenges": {
                "enableEmployeeIdChallenge": false
            }
        },
         "nextOU": {
            "security_session_controls": {
                "webSessionDuration": "800m"
            },
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BaseCaseInputApi03a := {
    "policies": {
        "topOU": {
            "security_login_challenges": {
                "enableEmployeeIdChallenge": true
            }
        },
         "nextOU": {
            "security_login_challenges": {
                "enableEmployeeIdChallenge": false
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_PostSSO_Correct_1 if {
    PolicyId := CommonControlsId3_1
    Output := tests with input as GoodCaseInputApi03

    PassTestResult(PolicyId, Output)
}

test_PostSSO_Incorrect_1 if {
    PolicyId := CommonControlsId3_1
    Output := tests with input as BaseCaseInputApi03

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage3_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_PostSSO_Incorrect_2 if {
    PolicyId := CommonControlsId3_1
    Output := tests with input as BaseCaseInputApi03a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage3_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
