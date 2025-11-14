package commoncontrols

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCaseInputApi04 := {
    "policies": {
        "topOU": {
            "security_session_controls": {
                "webSessionDuration": "43200s"
            },
        },
         "nextOU": {
        },
        "thirdOU": {
            "security_session_controls": {
                "webSessionDuration": "700m"
            },
        },
        "fourthOU": {
            "security_session_controls": {
                "webSessionDuration": "12H"
            },
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi04 := {
    "policies": {
        "topOU": {
            "security_session_controls": {
                "webSessionDuration": "43200s"
            },
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

test_CCAPI_ReAuth_Comply_1 if {
    PolicyId := CommonControlsId4_1
    Output := tests with input as GoodCaseInputApi04

    PassTestResult(PolicyId, Output)
}

test_CCAPI_ReAuth_NonComply_1 if {
    PolicyId := CommonControlsId4_1
    Output := tests with input as BadCaseInputApi04

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage4_1(GetFriendlyValue4_1(800 * 60))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
