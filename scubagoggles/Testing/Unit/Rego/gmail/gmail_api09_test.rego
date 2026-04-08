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
    },
    "imap_exclusions": []
}

BadGmailApi09 := {
    "policies": {
        "topOU": {
            "gmail_pop_access": {"enablePopAccess": true},
            "gmail_imap_access": {"enableImapAccess": true},
            "gmail_service_status": {"serviceState": "ENABLED"}
        },
        "nextOU": {
            "gmail_imap_access": {"enableImapAccess": true}
        },
        "thirdOU": {
            "gmail_pop_access": {"enablePopAccess": true}
        },
        "fourthOU": {
            "gmail_imap_access": {"enableImapAccess": false},
            "gmail_pop_access": {"enablePopAccess": false}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    },
    "imap_exclusions": []
}

ImapExceptionsGmailApi09 := {
    "policies": {
        "topOU": {
            "gmail_pop_access": {"enablePopAccess": false},
            "gmail_imap_access": {"enableImapAccess": false},
            "gmail_service_status": {"serviceState": "ENABLED"}
        },
        "nextOU": {
            "gmail_imap_access": {"enableImapAccess": true}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    },
    "imap_exclusions": [
        {
            "ou": "nextOU",
            "group": "",
            "justification": "perfectly valid reason"
        }
    ]
}

test_ImapPopEnable_Correct_1 if {
    PolicyId := GmailId9_1
    Output := tests with input as GoodGmailApi09

    PassTestResult(PolicyId, Output)
}

test_ImapPopEnable_Correct_2 if {
    PolicyId := GmailId9_1
    Output := tests with input as ImapExceptionsGmailApi09

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat("", [
        "Requirement met in all OUs and groups.",
        "<br>Note: IMAP is enabled in the following locations but ScubaGoggles was configured to ",
        "allow exceptions for them:<ul><li>nextOU. <i>Justification: perfectly valid reason</i></li></ul>"
    ])
}


test_ImapPopEnable_Incorrect_1 if {
    PolicyId := GmailId9_1
    Output := tests with input as BadGmailApi09

    failedOU := [{"Name": "nextOU",
                 "Value": GetFriendlyValue9_1(true, false)},
                 {"Name": "thirdOU",
                 "Value": GetFriendlyValue9_1(false, true)},
                 {"Name": "topOU",
                 "Value": GetFriendlyValue9_1(true, true)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

