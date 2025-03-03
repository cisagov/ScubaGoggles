package commoncontrols

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCaseInputApi05 := {
    "policies": {
        "topOU": {
            "security_password": {
                "allowedStrength": "STRONG",
                "minimumLength": 15,
                "maximumLength": 100,
                "enforceRequirementsAtLogin": true,
                "allowReuse": false,
                "expirationDuration": "0s"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi05 := {
    "policies": {
        "topOU": {
            "security_password": {
                "allowedStrength": "WEAK",
                "minimumLength": 6,
                "maximumLength": 100,
                "enforceRequirementsAtLogin": false,
                "allowReuse": true,
                "expirationDuration": "10h"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi05a := {
    "policies": {
        "topOU": {
            "security_password": {
                "allowedStrength": "STRONG",
                "minimumLength": 15,
                "maximumLength": 100,
                "enforceRequirementsAtLogin": true,
                "allowReuse": false,
                "expirationDuration": "0s"
            }
        },
        "nextOU": {
            "security_password": {
                "minimumLength": 13,
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_CCAPI_PwdStrength_Comply_1 if {
    PolicyId := CommonControlsId5_1
    Output := tests with input as GoodCaseInputApi05

    PassTestResult(PolicyId, Output)
}

test_CCAPI_PwdStrength_NonComply_1 if {
    PolicyId := CommonControlsId5_1
    Output := tests with input as BadCaseInputApi05

    failedOU := [{"Name": "topOU",
                 "Value": "Password strength is WEAK, not STRONG"}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_CCAPI_PwdLength_Comply_1 if {
    PolicyId := CommonControlsId5_2
    Output := tests with input as GoodCaseInputApi05

    PassTestResult(PolicyId, Output)
}

test_CCAPI_PwdLength_NonComply_1 if {
    PolicyId := CommonControlsId5_2
    Output := tests with input as BadCaseInputApi05

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage5_2(6)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_CCAPI_PwdSuggestLength_Comply_1 if {
    PolicyId := CommonControlsId5_3
    Output := tests with input as GoodCaseInputApi05

    PassTestResult(PolicyId, Output)
}

test_CCAPI_PwdSuggestLength_NonComply_1 if {
    PolicyId := CommonControlsId5_3
    Output := tests with input as BadCaseInputApi05a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage5_3(13)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_CCAPI_PwdNextLogin_Comply_1 if {
    PolicyId := CommonControlsId5_4
    Output := tests with input as GoodCaseInputApi05

    PassTestResult(PolicyId, Output)
}

test_CCAPI_PwdNextLogin_NonComply_1 if {
    PolicyId := CommonControlsId5_4
    Output := tests with input as BadCaseInputApi05

    failedOU := [{"Name": "topOU",
                 "Value": "Enforce password policy at next sign-in is OFF"}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_CCAPI_PwdReuse_Comply_1 if {
    PolicyId := CommonControlsId5_5
    Output := tests with input as GoodCaseInputApi05

    PassTestResult(PolicyId, Output)
}

test_CCAPI_PwdReuse_NonComply_1 if {
    PolicyId := CommonControlsId5_5
    Output := tests with input as BadCaseInputApi05

    failedOU := [{"Name": "topOU",
                 "Value": "Allow password reuse is ON"}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_CCAPI_PwdResetFrequency_Comply_1 if {
    PolicyId := CommonControlsId5_6
    Output := tests with input as GoodCaseInputApi05

    PassTestResult(PolicyId, Output)
}

test_CCAPI_PwdResetFrequency_NonComply_1 if {
    PolicyId := CommonControlsId5_6
    Output := tests with input as BadCaseInputApi05

    failedOU := [{"Name": "topOU",
                 "Value": "Password reset frequency is 36000 seconds"}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
