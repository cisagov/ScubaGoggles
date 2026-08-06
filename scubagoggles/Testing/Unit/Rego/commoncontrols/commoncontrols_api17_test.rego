package commoncontrols

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCaseInputApi17 := {
    "policies": {
        "topOU": {
            "multi_party_approval_require_approvals": {
                "multiPartyApprovalState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi17 := {
    "policies": {
        "topOU": {
            "multi_party_approval_require_approvals": {
                "multiPartyApprovalState": "DISABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi17a := {
    "policies": {
        "topOU": {
            "multi_party_approval_require_approvals": {
                "multiPartyApprovalState": "ENABLED"}
        },
        "nextOU": {
            "multi_party_approval_require_approvals": {
                "multiPartyApprovalState": "DISABLED"}
        },
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_MultiPartyApproval_Correct_1 if {
    PolicyId := CommonControlsId17_1
    Output := tests with input as GoodCaseInputApi17

    PassTestResult(PolicyId, Output)
}

test_MultiPartyApproval_Incorrect_1 if {
    PolicyId := CommonControlsId17_1
    Output := tests with input as BadCaseInputApi17

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage17_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_MultiPartyApproval_Incorrect_2 if {
    PolicyId := CommonControlsId17_1
    Output := tests with input as BadCaseInputApi17a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage17_1}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
