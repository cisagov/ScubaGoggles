package gmail

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGmailApi07 := {
    "policies": {
        "topOU": {
            "gmail_spoofing_and_authentication": {
                "applyFutureSettingsAutomatically": true,
                "detectDomainNameSpoofing": true,
                "detectDomainSpoofingFromUnauthenticatedSenders": true,
                "detectEmployeeNameSpoofing": true,
                "detectGroupsSpoofing": true,
                "detectUnauthenticatedEmails": true,
                "domainNameSpoofingConsequence": "SPAM_FOLDER",
                "domainSpoofingConsequence": "SPAM_FOLDER",
                "employeeNameSpoofingConsequence": "QUARANTINE",
                "groupsSpoofingConsequence": "QUARANTINE",
                "unauthenticatedEmailConsequence": "QUARANTINE"
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

BadGmailApi07 := {
    "policies": {
        "topOU": {
            "gmail_spoofing_and_authentication": {
                "applyFutureSettingsAutomatically": false,
                "detectDomainNameSpoofing": false,
                "detectDomainSpoofingFromUnauthenticatedSenders": false,
                "detectEmployeeNameSpoofing": false,
                "detectGroupsSpoofing": false,
                "detectUnauthenticatedEmails": false,
                "domainNameSpoofingConsequence": "WARNING",
                "domainSpoofingConsequence": "WARNING",
                "employeeNameSpoofingConsequence": "WARNING",
                "groupsSpoofingConsequence": "WARNING",
                "unauthenticatedEmailConsequence": "WARNING"
            },
                "gmail_service_status": {"serviceState": "ENABLED"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGmailApi07a := {
    "policies": {
        "topOU": {
            "gmail_spoofing_and_authentication": {
                "applyFutureSettingsAutomatically": true,
                "detectDomainNameSpoofing": true,
                "detectDomainSpoofingFromUnauthenticatedSenders": true,
                "detectEmployeeNameSpoofing": true,
                "detectGroupsSpoofing": true,
                "detectUnauthenticatedEmails": true,
                "domainNameSpoofingConsequence": "QUARANTINE",
                "domainSpoofingConsequence": "SPAM_FOLDER",
                "employeeNameSpoofingConsequence": "QUARANTINE",
                "groupsSpoofingConsequence": "SPAM_FOLDER",
                "unauthenticatedEmailConsequence": "QUARANTINE"
            },
                "gmail_service_status": {"serviceState": "ENABLED"
            }
        },
        "nextOU": {
            "gmail_spoofing_and_authentication": {
                "applyFutureSettingsAutomatically": false,
                "detectDomainNameSpoofing": false,
                "detectDomainSpoofingFromUnauthenticatedSenders": false,
                "detectEmployeeNameSpoofing": false,
                "detectGroupsSpoofing": false,
                "detectUnauthenticatedEmails": false,
                "domainNameSpoofingConsequence": "WARNING",
                "domainSpoofingConsequence": "WARNING",
                "unauthenticatedEmailConsequence": "WARNING"
            },
                "gmail_service_status": {"serviceState": "ENABLED"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_DomainNameSpoofing_Correct_1 if {
    PolicyId := GmailId7_1
    Output := tests with input as GoodGmailApi07

    PassTestResult(PolicyId, Output)
}

test_DomainNameSpoofing_Incorrect_1 if {
    PolicyId := GmailId7_1
    Output := tests with input as BadGmailApi07

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage7_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_DomainNameSpoofing_Incorrect_2 if {
    PolicyId := GmailId7_1
    Output := tests with input as BadGmailApi07a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage7_1("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_EmployeeNameSpoofing_Correct_1 if {
    PolicyId := GmailId7_2
    Output := tests with input as GoodGmailApi07

    PassTestResult(PolicyId, Output)
}

test_EmployeeNameSpoofing_Incorrect_1 if {
    PolicyId := GmailId7_2
    Output := tests with input as BadGmailApi07

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage7_2("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_EmployeeNameSpoofing_Incorrect_2 if {
    PolicyId := GmailId7_2
    Output := tests with input as BadGmailApi07a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage7_2("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_DomainSpoofing_Correct_1 if {
    PolicyId := GmailId7_3
    Output := tests with input as GoodGmailApi07

    PassTestResult(PolicyId, Output)
}

test_DomainSpoofing_Incorrect_1 if {
    PolicyId := GmailId7_3
    Output := tests with input as BadGmailApi07

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage7_3("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_DomainSpoofing_Incorrect_2 if {
    PolicyId := GmailId7_3
    Output := tests with input as BadGmailApi07a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage7_3("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_UnauthenticatedEmailSpoofing_Correct_1 if {
    PolicyId := GmailId7_4
    Output := tests with input as GoodGmailApi07

    PassTestResult(PolicyId, Output)
}

test_UnauthenticatedEmailSpoofing_Incorrect_1 if {
    PolicyId := GmailId7_4
    Output := tests with input as BadGmailApi07

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage7_4("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_UnauthenticatedEmailSpoofing_Incorrect_2 if {
    PolicyId := GmailId7_4
    Output := tests with input as BadGmailApi07a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage7_4("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_GroupsSpoofing_Correct_1 if {
    PolicyId := GmailId7_5
    Output := tests with input as GoodGmailApi07

    PassTestResult(PolicyId, Output)
}

test_GroupsSpoofing_Incorrect_1 if {
    PolicyId := GmailId7_5
    Output := tests with input as BadGmailApi07

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage7_5("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_GroupsSpoofing_Incorrect_2 if {
    PolicyId := GmailId7_5
    Output := tests with input as BadGmailApi07a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage7_5("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofConsequence_Correct_1 if {
    PolicyId := GmailId7_6
    Output := tests with input as GoodGmailApi07

    PassTestResult(PolicyId, Output)
}

test_SpoofConsequence_Incorrect_1 if {
    PolicyId := GmailId7_6
    Output := tests with input as BadGmailApi07

    types := ["domain", "domain name", "employee name", "groups",
              "unauthenticated"]
    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage7_6(types)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpoofConsequence_Incorrect_2 if {
    PolicyId := GmailId7_6
    Output := tests with input as BadGmailApi07a

    types := ["domain", "domain name", "unauthenticated"]
    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage7_6(types)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_FutureSettings_Correct_1 if {
    PolicyId := GmailId7_7
    Output := tests with input as GoodGmailApi07

    PassTestResult(PolicyId, Output)
}

test_FutureSettings_Incorrect_1 if {
    PolicyId := GmailId7_7
    Output := tests with input as BadGmailApi07

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage7_7("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_FutureSettings_Incorrect_2 if {
    PolicyId := GmailId7_7
    Output := tests with input as BadGmailApi07a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage7_7("disabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
