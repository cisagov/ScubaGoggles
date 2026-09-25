package commoncontrols

import future.keywords
import data.utils
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCaseInputApi08 := {
    "policies": {
        "topOU": {
            "security_super_admin_account_recovery": {
                "enableAccountRecovery": false
            },
            "security_user_account_recovery": {
                "enableAccountRecovery": false
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi08 := {
    "policies": {
        "topOU": {
            "security_super_admin_account_recovery": {
                "enableAccountRecovery": true
            },
            "security_user_account_recovery": {
                "enableAccountRecovery": true
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi08a := {
    "policies": {
        "topOU": {
            "security_super_admin_account_recovery": {
                "enableAccountRecovery": false
            },
            "security_user_account_recovery": {
                "enableAccountRecovery": false
            }
        },
        "nextOU": {
            "security_super_admin_account_recovery": {
                "enableAccountRecovery": true
            },
            "security_user_account_recovery": {
                "enableAccountRecovery": true
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_SAAcctRecovery_Correct_1 if {
    PolicyId := CommonControlsId8_1
    Output := tests with input as GoodCaseInputApi08

    PassTestResult(PolicyId, Output)
}

test_SAAcctRecovery_Incorrect_1 if {
    PolicyId := CommonControlsId8_1
    Output := tests with input as BadCaseInputApi08

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage8_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SAAcctRecovery_Incorrect_2 if {
    PolicyId := CommonControlsId8_1
    Output := tests with input as BadCaseInputApi08a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage8_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_UserAcctRecovery_Correct_1 if {
    PolicyId := CommonControlsId8_2
    Output := tests with input as GoodCaseInputApi08

    PassTestResult(PolicyId, Output)
}

test_UserAcctRecovery_Incorrect_1 if {
    PolicyId := CommonControlsId8_2
    Output := tests with input as BadCaseInputApi08

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage8_2}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_UserAcctRecovery_Incorrect_2 if {
    PolicyId := CommonControlsId8_2
    Output := tests with input as BadCaseInputApi08a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage8_2}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_NotImplemented_0803_1 if {
    PolicyId := CommonControlsId8_3
    Output := tests with input as GoodCaseInputApi08

    utils.NotImplementedTestResult(PolicyId, Output)
}