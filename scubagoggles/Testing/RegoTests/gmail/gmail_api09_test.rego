package gmail

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGmailApi09 := {
    "policies": {
        "topOU": {
            "gmail_pop_access": {"enablePopAccess": false},
            "gmail_imap_access": {"enableImapAccess": false},
            "gmail_service_status": {"serviceState": "ENABLED"},
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGmailApi09 := {
    "policies": {
        "topOU": {
            "gmail_pop_access": {"enablePopAccess": true},
            "gmail_imap_access": {"enableImapAccess": true},
            "gmail_service_status": {"serviceState": "ENABLED"}
        },
        "nextOU": {
            "gmail_imap_access": {"enableImapAccess": false}
        },
        "thirdOU": {
            "gmail_pop_access": {"enablePopAccess": false}
        },
        "fourthOU": {
            "gmail_imap_access": {"enableImapAccess": false},
            "gmail_pop_access": {"enablePopAccess": false}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_ImapPopEnable_Correct_1 if {
    PolicyId := GmailId9_1
    Output := tests with input as GoodGmailApi09

    PassTestResult(PolicyId, Output)
}

test_ImapPopEnable_Incorrect_1 if {
    PolicyId := GmailId9_1
    Output := tests with input as BadGmailApi09

    failedOU := [{"Name": "nextOU",
                 "Value": GetFriendlyValue9_1(false, true)},
                 {"Name": "thirdOU",
                 "Value": GetFriendlyValue9_1(true, false)},
                 {"Name": "topOU",
                 "Value": GetFriendlyValue9_1(true, true)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
