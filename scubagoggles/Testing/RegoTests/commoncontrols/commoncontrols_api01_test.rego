package commoncontrols

import future.keywords
import data.utils
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCaseInputApi01 := {
    "policies": {
        "topOU": {
            "security_two_step_verification_device_trust": {
                "allowTrustingDevice": false
            },
            "security_two_step_verification_enforcement": {
                "enforcedFrom": "2024-02-16T23:22:21.732Z"
            },
            "security_two_step_verification_enforcement_factor": {
                "allowedSignInFactorSet": "PASSKEY_ONLY"
            },
            "security_two_step_verification_enrollment": {
                "allowEnrollment": true
            },
            "security_two_step_verification_grace_period": {
                "enrollmentGracePeriod": "168h"}
        },
        "nextOU": {
            "security_two_step_verification_grace_period": {
                "enrollmentGracePeriod": "604800s"}
        },
        "thirdOU": {
            "security_two_step_verification_grace_period": {
                "enrollmentGracePeriod": "86400s"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi01 := {
    "policies": {
        "topOU": {
            "security_two_step_verification_device_trust": {
                "allowTrustingDevice": true
            },
            "security_two_step_verification_enforcement": {
                "enforcedFrom": "2025-02-16T23:22:21.732Z"
            },
            "security_two_step_verification_enforcement_factor": {
                "allowedSignInFactorSet": "ALL"
            },
            "security_two_step_verification_enrollment": {
                "allowEnrollment": false
            },
            "security_two_step_verification_grace_period": {
                "enrollmentGracePeriod": "1209600s"}
        },
        "nextOU": {
            "security_two_step_verification_enforcement": {
                "enforcedFrom": "2028-02-16T23:22:21.732Z"
            },
            "security_two_step_verification_enforcement_factor": {
                "allowedSignInFactorSet": "ALL"
            },
            "security_two_step_verification_enrollment": {
                "allowEnrollment": true
            }
        },
        "thirdOU": {
            "security_two_step_verification_enforcement": {
                "enforcedFrom": "2035-02-16T23:22:21.732Z"
            },
            "security_two_step_verification_enforcement_factor": {
                "allowedSignInFactorSet": "PASSKEY_ONLY"
            },
            "security_two_step_verification_enrollment": {
                "allowEnrollment": true
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi01a := {
    "policies": {
        "topOU": {
            "security_login_challenges": {
                "enableEmployeeIdChallenge": true
            }
        },
         "nextOU": {
            "security_login_challenges": {
                "enableEmployeeIdChallenge": false
            },
            "security_two_step_verification_grace_period": {
                "enrollmentGracePeriod": "0s"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_2SV_Correct_1 if {
    PolicyId := CommonControlsId1_1
    Output := tests with input as GoodCaseInputApi01

    PassTestResult(PolicyId, Output)
}

test_2SV_Incorrect_1 if {
    PolicyId := CommonControlsId1_1
    Output := tests with input as BadCaseInputApi01

    failedOU := [{"Name": "nextOU",
                  "Value": NonComplianceMessage1_1b(GetFriendlyMethods("ALL"))},
                 {"Name": "thirdOU",
                  "Value": NonComplianceMessage1_1c},
                 {"Name": "topOU",
                  "Value": NonComplianceMessage1_1a}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_EnrollPeriod_Correct_1 if {
    PolicyId := CommonControlsId1_2
    Output := tests with input as GoodCaseInputApi01

    PassTestResult(PolicyId, Output)
}

test_EnrollPeriod_Incorrect_1 if {
    PolicyId := CommonControlsId1_2
    Output := tests with input as BadCaseInputApi01

    failedOU := [{"Name": "topOU",
                  "Value": NonComplianceMessage1_2(1209600,
                                                   utils.DurationToSeconds("7d"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_EnrollPeriod_Incorrect_2 if {
    PolicyId := CommonControlsId1_2
    Output := tests with input as BadCaseInputApi01a

    failedOU := [{"Name": "nextOU",
                  "Value": NonComplianceMessage1_2(0,
                                                   utils.DurationToSeconds("7d"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_DeviceTrust_Correct_1 if {
    PolicyId := CommonControlsId1_3
    Output := tests with input as GoodCaseInputApi01

    PassTestResult(PolicyId, Output)
}

test_DeviceTrust_Incorrect_1 if {
    PolicyId := CommonControlsId1_3
    Output := tests with input as BadCaseInputApi01

    failedOU := [{"Name": "topOU",
                  "Value": NonComplianceMessage1_3}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
