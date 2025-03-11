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
                "enforcedFrom": "2032-02-16T23:22:21.732Z"
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

# For the following test input, the top-level orgunit is compliant with all 1.*
# baselines.  It's the settings in the sub-orgunits that deviate from the
# requirements.

BadCaseInputApi01a := {
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
            "security_two_step_verification_enforcement_factor": {
                "allowedSignInFactorSet": "ALL"
            }
        },
        "thirdOU": {
            "security_two_step_verification_enrollment": {
                "allowEnrollment": false},
            "security_two_step_verification_device_trust": {
                "allowTrustingDevice": true}
        },
        "fourthOU": {
            "security_two_step_verification_grace_period": {
                "enrollmentGracePeriod": "0s"}
        },
        "fifthOU": {
            "security_two_step_verification_enforcement_factor": {
                "allowedSignInFactorSet": "NO_TELEPHONY"},
        },
        "sixthOU": {
            "security_two_step_verification_enforcement": {
                "enforcedFrom": "2035-02-16T23:22:21.732Z"},
            "security_two_step_verification_device_trust": {
                "allowTrustingDevice": true}
        },
        "seventhOU": {
            # This is the value Google provides for 2SV enforcement "Off".
            "security_two_step_verification_enforcement": {
                "enforcedFrom": "1970-01-01T00:00:00Z"}
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

test_2SV_Incorrect_2 if {
    PolicyId := CommonControlsId1_1
    Output := tests with input as BadCaseInputApi01a

    failedOU := [{"Name": "fifthOU",
                  "Value": NonComplianceMessage1_1b(GetFriendlyMethods("NO_TELEPHONY"))},
                  {"Name": "nextOU",
                  "Value": NonComplianceMessage1_1b(GetFriendlyMethods("ALL"))},
                  {"Name": "seventhOU",
                  "Value": NonComplianceMessage1_1c},
                  {"Name": "sixthOU",
                  "Value": NonComplianceMessage1_1c},
                  {"Name": "thirdOU",
                  "Value": NonComplianceMessage1_1a}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Alt2SV_Correct_1 if {
    PolicyId := CommonControlsId1_2
    Output := tests with input as GoodCaseInputApi01

    PassTestResult(PolicyId, Output)
}

test_Alt2SV_Incorrect_1 if {
    PolicyId := CommonControlsId1_2
    Output := tests with input as BadCaseInputApi01

    failedOU := [{"Name": "nextOU",
                  "Value": NonComplianceMessage1_2b},
                 {"Name": "thirdOU",
                  "Value": NonComplianceMessage1_2b},
                 {"Name": "topOU",
                  "Value": NonComplianceMessage1_2a}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Alt2SV_Incorrect_2 if {
    PolicyId := CommonControlsId1_2
    Output := tests with input as BadCaseInputApi01a

    failedOU := [{"Name": "seventhOU",
                  "Value": NonComplianceMessage1_2b},
                 {"Name": "sixthOU",
                  "Value": NonComplianceMessage1_2b},
                 {"Name": "thirdOU",
                  "Value": NonComplianceMessage1_2a}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_NoTelephony2SV_Correct_1 if {
    PolicyId := CommonControlsId1_3
    Output := tests with input as GoodCaseInputApi01

    PassTestResult(PolicyId, Output)
}

test_NoTelephony2SV_Incorrect_1 if {
    PolicyId := CommonControlsId1_3
    Output := tests with input as BadCaseInputApi01

    failedOU := [{"Name": "nextOU",
                  "Value": NonComplianceMessage1_3b},
                 {"Name": "thirdOU",
                  "Value": NonComplianceMessage1_3c},
                 {"Name": "topOU",
                  "Value": NonComplianceMessage1_3a}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_NoTelephony2SV_Incorrect_2 if {
    PolicyId := CommonControlsId1_3
    Output := tests with input as BadCaseInputApi01a

    failedOU := [{"Name": "nextOU",
                  "Value": NonComplianceMessage1_3b},
                 {"Name": "seventhOU",
                  "Value": NonComplianceMessage1_3c},
                 {"Name": "sixthOU",
                  "Value": NonComplianceMessage1_3c},
                 {"Name": "thirdOU",
                  "Value": NonComplianceMessage1_3a}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_2SVUserEnrollment_Correct_1 if {
    PolicyId := CommonControlsId1_4
    Output := tests with input as GoodCaseInputApi01

    PassTestResult(PolicyId, Output)
}

test_2SVUserEnrollment_Incorrect_1 if {
    PolicyId := CommonControlsId1_4
    Output := tests with input as BadCaseInputApi01

    failedOU := [{"Name": "topOU",
                  "Value": NonComplianceMessage1_4(1209600,
                                                   utils.DurationToSeconds("7d"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_2SVUserEnrollment_Incorrect_2 if {
    PolicyId := CommonControlsId1_4
    Output := tests with input as BadCaseInputApi01a

    failedOU := [{"Name": "fourthOU",
                  "Value": NonComplianceMessage1_4(0,
                                                   utils.DurationToSeconds("7d"))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_2SVDeviceTrust_Correct_1 if {
    PolicyId := CommonControlsId1_5
    Output := tests with input as GoodCaseInputApi01

    PassTestResult(PolicyId, Output)
}

test_2SVDeviceTrust_Incorrect_1 if {
    PolicyId := CommonControlsId1_5
    Output := tests with input as BadCaseInputApi01

    failedOU := [{"Name": "topOU",
                  "Value": NonComplianceMessage1_5}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_2SVDeviceTrust_Incorrect_2 if {
    PolicyId := CommonControlsId1_5
    Output := tests with input as BadCaseInputApi01a

    failedOU := [{"Name": "sixthOU",
                  "Value": NonComplianceMessage1_5},
                  {"Name": "thirdOU",
                  "Value": NonComplianceMessage1_5}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
