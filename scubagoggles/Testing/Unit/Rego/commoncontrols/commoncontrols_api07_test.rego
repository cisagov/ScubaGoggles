package commoncontrols

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCaseInputApi07 := {
    "policies": {
        "topOU": {
            "provisioning_conflicting_accounts_management": {
                "option": "REPLACE_CONFLICTING_ACCOUNT"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi07 := {
    "policies": {
        "topOU": {
            "provisioning_conflicting_accounts_management": {
                "option": "AUTOMATICALLY_SEND_INVITATIONS"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi07a := {
    "policies": {
        "topOU": {
            "provisioning_conflicting_accounts_management": {
                "option": "PRESERVE_CONFLICTING_ACCOUNT"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_ConflictingAccounts_Correct_1 if {
    PolicyId := CommonControlsId7_1
    Output := tests with input as GoodCaseInputApi07

    PassTestResult(PolicyId, Output)
}

test_ConflictingAccounts_Incorrect_1 if {
    PolicyId := CommonControlsId7_1
    Output := tests with input as BadCaseInputApi07

    message := NonComplianceMessage7_1(GetFriendlyConflictMethod("AUTOMATICALLY_SEND_INVITATIONS"))
    failedOU := [{"Name": "topOU",
                 "Value": message}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ConflictingAccounts_Incorrect_2 if {
    PolicyId := CommonControlsId7_1
    Output := tests with input as BadCaseInputApi07a

    message := NonComplianceMessage7_1(GetFriendlyConflictMethod("PRESERVE_CONFLICTING_ACCOUNT"))
    failedOU := [{"Name": "topOU",
                 "Value": message}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
