package commoncontrols

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCaseInputApi08 := {
    "policies": {
        "topOU": {
            "security_super_admin_account_recovery": {
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
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_CCAPI_SAAcctRecovery_Comply_1 if {
    PolicyId := CommonControlsId8_1
    Output := tests with input as GoodCaseInputApi08

    PassTestResult(PolicyId, Output)
}

test_CCAPI_SAAcctRecovery_NonComply_1 if {
    PolicyId := CommonControlsId8_1
    Output := tests with input as BadCaseInputApi08

    failedOU := [{"Name": "topOU",
                 "Value": "Allow super admins to recover their account is ON"}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
