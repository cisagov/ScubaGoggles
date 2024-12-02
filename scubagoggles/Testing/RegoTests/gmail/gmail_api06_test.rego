package gmail

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGmailApi06 := {
    "policies": {
        "topOU": {
            "gmail_links_and_external_images": {
                "applyFutureSettingsAutomatically": true,
                "enableAggressiveWarningsOnUntrustedLinks": true,
                "enableExternalImageScanning": true,
                "enableShortenerScanning": true
            },
        },
         "nextOU": {
        },
        "thirdOU": {
            "security_session_controls": {
                "webSessionDuration": "700m"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGmailApi06 := {
    "policies": {
        "topOU": {
            "gmail_links_and_external_images": {
                "applyFutureSettingsAutomatically": false,
                "enableAggressiveWarningsOnUntrustedLinks": false,
                "enableExternalImageScanning": false,
                "enableShortenerScanning": false
            },
                "gmail_service_status": {"serviceState": "ENABLED"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGmailApi06a := {
    "policies": {
        "topOU": {
            "gmail_links_and_external_images": {
                "applyFutureSettingsAutomatically": true,
                "enableAggressiveWarningsOnUntrustedLinks": true,
                "enableExternalImageScanning": true,
                "enableShortenerScanning": true
            },
                "gmail_service_status": {"serviceState": "ENABLED"
            }
        },
        "nextOU": {
            "gmail_links_and_external_images": {
                "applyFutureSettingsAutomatically": false,
                "enableAggressiveWarningsOnUntrustedLinks": false,
                "enableExternalImageScanning": false,
                "enableShortenerScanning": false
            },
                "gmail_service_status": {"serviceState": "ENABLED"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_ShortLinks_Correct_1 if {
    PolicyId := GmailId6_1
    Output := tests with input as GoodGmailApi06

    PassTestResult(PolicyId, Output)
}

test_ShortLinks_Incorrect_1 if {
    PolicyId := GmailId6_1
    Output := tests with input as BadGmailApi06

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage6_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ShortLinks_Incorrect_2 if {
    PolicyId := GmailId6_1
    Output := tests with input as BadGmailApi06a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage6_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ScanImages_Correct_1 if {
    PolicyId := GmailId6_2
    Output := tests with input as GoodGmailApi06

    PassTestResult(PolicyId, Output)
}

test_ScanImages_Incorrect_1 if {
    PolicyId := GmailId6_2
    Output := tests with input as BadGmailApi06

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage6_2("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ScanImages_Incorrect_2 if {
    PolicyId := GmailId6_2
    Output := tests with input as BadGmailApi06a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage6_2("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_WarnEnabled_Correct_1 if {
    PolicyId := GmailId6_3
    Output := tests with input as GoodGmailApi06

    PassTestResult(PolicyId, Output)
}

test_WarnEnabled_Incorrect_1 if {
    PolicyId := GmailId6_3
    Output := tests with input as BadGmailApi06

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage6_3("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_WarnEnabled_Incorrect_2 if {
    PolicyId := GmailId6_3
    Output := tests with input as BadGmailApi06a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage6_3("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ApplyFuture_Correct_1 if {
    PolicyId := GmailId6_4
    Output := tests with input as GoodGmailApi06

    PassTestResult(PolicyId, Output)
}

test_ApplyFuture_Incorrect_1 if {
    PolicyId := GmailId6_4
    Output := tests with input as BadGmailApi06

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage6_4("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_ApplyFuture_Incorrect_2 if {
    PolicyId := GmailId6_4
    Output := tests with input as BadGmailApi06a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage6_4("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
