package gmail

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGmailApi05 := {
    "policies": {
        "topOU": {
            "gmail_email_attachment_safety": {
                "applyFutureRecommendedSettingsAutomatically": true,
                "enableAnomalousAttachmentProtection": true,
                "enableAttachmentWithScriptsProtection": true,
                "enableEncryptedAttachmentProtection": true,
                "anomalousAttachmentProtectionConsequence": "SPAM_FOLDER",
                "attachmentWithScriptsProtectionConsequence": "QUARANTINE",
                "encryptedAttachmentProtectionConsequence": "QUARANTINE"
            },
                "gmail_service_status": {"serviceState": "ENABLED"
            }
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

BadGmailApi05 := {
    "policies": {
        "topOU": {
            "gmail_email_attachment_safety": {
                "applyFutureRecommendedSettingsAutomatically": false,
                "enableAnomalousAttachmentProtection": false,
                "enableAttachmentWithScriptsProtection": false,
                "enableEncryptedAttachmentProtection": false,
                "anomalousAttachmentProtectionConsequence": "WARNING",
                "attachmentWithScriptsProtectionConsequence": "WARNING",
                "encryptedAttachmentProtectionConsequence": "WARNING"
            },
                "gmail_service_status": {"serviceState": "ENABLED"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGmailApi05a := {
    "policies": {
        "topOU": {
            "gmail_email_attachment_safety": {
                "applyFutureRecommendedSettingsAutomatically": true,
                "enableAnomalousAttachmentProtection": true,
                "enableAttachmentWithScriptsProtection": true,
                "enableEncryptedAttachmentProtection": true,
                "anomalousAttachmentProtectionConsequence": "SPAM_FOLDER",
                "attachmentWithScriptsProtectionConsequence": "QUARANTINE",
                "encryptedAttachmentProtectionConsequence": "QUARANTINE"
            },
                "gmail_service_status": {"serviceState": "ENABLED"
            }
        },
        "nextOU": {
            "gmail_email_attachment_safety": {
                "applyFutureRecommendedSettingsAutomatically": false,
                "enableAnomalousAttachmentProtection": false,
                "enableAttachmentWithScriptsProtection": false,
                "enableEncryptedAttachmentProtection": false,
                "anomalousAttachmentProtectionConsequence": "WARNING",
                "encryptedAttachmentProtectionConsequence": "WARNING"
            },
                "gmail_service_status": {"serviceState": "ENABLED"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_Encrypted_Correct_1 if {
    PolicyId := GmailId5_1
    Output := tests with input as GoodGmailApi05

    PassTestResult(PolicyId, Output)
}

test_Encrypted_Incorrect_1 if {
    PolicyId := GmailId5_1
    Output := tests with input as BadGmailApi05

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage5_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Encrypted_Incorrect_2 if {
    PolicyId := GmailId5_1
    Output := tests with input as BadGmailApi05a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage5_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Scripts_Correct_1 if {
    PolicyId := GmailId5_2
    Output := tests with input as GoodGmailApi05

    PassTestResult(PolicyId, Output)
}

test_Scripts_Incorrect_1 if {
    PolicyId := GmailId5_2
    Output := tests with input as BadGmailApi05

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage5_2("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Scripts_Incorrect_2 if {
    PolicyId := GmailId5_2
    Output := tests with input as BadGmailApi05a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage5_2("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_AnomalousAttach_Correct_1 if {
    PolicyId := GmailId5_3
    Output := tests with input as GoodGmailApi05

    PassTestResult(PolicyId, Output)
}

test_AnomalousAttach_Incorrect_1 if {
    PolicyId := GmailId5_3
    Output := tests with input as BadGmailApi05

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage5_3("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_AnomalousAttach_Incorrect_2 if {
    PolicyId := GmailId5_3
    Output := tests with input as BadGmailApi05a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage5_3("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_FutureSettings_Correct_1 if {
    PolicyId := GmailId5_4
    Output := tests with input as GoodGmailApi05

    PassTestResult(PolicyId, Output)
}

test_FutureSettings_Incorrect_1 if {
    PolicyId := GmailId5_4
    Output := tests with input as BadGmailApi05

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage5_4("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_FutureSettings_Incorrect_2 if {
    PolicyId := GmailId5_4
    Output := tests with input as BadGmailApi05a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage5_4("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_AttachConsequence_Correct_1 if {
    PolicyId := GmailId5_5
    Output := tests with input as GoodGmailApi05

    PassTestResult(PolicyId, Output)
}

test_AttachConsequence_Incorrect_1 if {
    PolicyId := GmailId5_5
    Output := tests with input as BadGmailApi05

    types := ["anomalous type", "encrypted", "scripts"]
    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage5_5(types)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_AttachConsequence_Incorrect_2 if {
    PolicyId := GmailId5_5
    Output := tests with input as BadGmailApi05a

    types := ["anomalous type", "encrypted"]
    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage5_5(types)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
