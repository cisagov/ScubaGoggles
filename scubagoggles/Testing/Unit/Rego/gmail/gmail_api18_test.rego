package gmail

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodGmailApi18 := {
    "policies": {
        "topOU": {
            "gmail_spam_override_lists": {
                "spamOverride": [
                    {
                        "description": "Scuba",
                        "enableAggressiveFiltering": true,
                        "addToQuarantine": true,
                        "quarantineId": 0,
                        "bypassInternalSenders": false,
                        "bypassSelectedSenders": true,
                        "bypassSenderAllowlist": [],
                        "hideWarningBannerFromSelectedSenders": true,
                        "hideWarningBannerSenderAllowlist": [],
                        "hideWarningBannerForAll": false,
                        "ruleId": "6776f-02rvqlb32nzzmh1:00gjdgxs17dp8vu"
                    },
                    {
                        "description": "Second Rule",
                        "enableAggressiveFiltering": false,
                        "addToQuarantine": false,
                        "bypassInternalSenders": false,
                        "bypassSelectedSenders": true,
                        "hideWarningBannerFromSelectedSenders": true,
                        "hideWarningBannerSenderAllowlist": [],
                        "ruleId": "4f41d-02rvqlb32nzzmh1:00gjdgxs46r0co2"
                    }
                ],
            },
            "gmail_service_status": {
                "serviceState": "ENABLED"
            }
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGmailApi18 := {
    "policies": {
        "topOU": {
            "gmail_spam_override_lists": {
                "spamOverride": [
                    {
                        "description": "Scuba",
                        "enableAggressiveFiltering": true,
                        "addToQuarantine": true,
                        "quarantineId": 0,
                        "bypassInternalSenders": false,
                        "bypassSelectedSenders": true,
                        "bypassSenderAllowlist": [
                        {
                            "name": "Scuba",
                            "list": [
                            "cisaent.onmicrosoft.com",
                            "scubagws.org",
                            "spam@example.com"
                            ]
                        }
                        ],
                        "hideWarningBannerFromSelectedSenders": true,
                        "hideWarningBannerSenderAllowlist": [
                        {
                            "name": "Scuba",
                            "list": [
                            "cisaent.onmicrosoft.com",
                            "scubagws.org",
                            "spam@example.com"
                            ]
                        },
                        {
                            "name": "Example",
                            "list": [
                            "spam@example.com"
                            ]
                        },
                        {
                            "name": "MyTestList",
                            "list": [
                            "test.com"
                            ]
                        }
                        ],
                        "hideWarningBannerForAll": true,
                        "ruleId": "6776f-02rvqlb32nzzmh1:00gjdgxs17dp8vu"
                    },
                    {
                        "description": "Second Rule",
                        "enableAggressiveFiltering": false,
                        "addToQuarantine": false,
                        "bypassInternalSenders": true,
                        "bypassSelectedSenders": true,
                        "hideWarningBannerFromSelectedSenders": true,
                        "hideWarningBannerSenderAllowlist": [
                        {
                            "name": "MyTestList",
                            "list": [
                            "test.com"
                            ]
                        }
                        ],
                        "hideWarningBannerForAll": true,
                        "ruleId": "4f41d-02rvqlb32nzzmh1:00gjdgxs46r0co2"
                    }
                ],
                "warningDomainsFound": "{Scuba: [Scuba: (cisaent.onmicrosoft.com, scubagws.org), MyTestList: (test.com)]}, {Second Rule: [MyTestList: (test.com)]}", # regal ignore:line-length
                "senderDomainsFound": "{Scuba: [Scuba: (cisaent.onmicrosoft.com, scubagws.org)]}"
            },
            "gmail_service_status": {"serviceState": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadGmailApi18a := {
    "policies": {
        "topOU": {
            "gmail_service_status": {"serviceState": "ENABLED"}
        },
        "nextOU": {
            "gmail_spam_override_lists": {
                "spamOverride": [
                    {
                        "description": "test spam filter",
                        "enableAggressiveFiltering": false,
                        "addToQuarantine": false,
                        "bypassInternalSenders": true,
                        "bypassSelectedSenders": true,
                        "hideWarningBannerFromSelectedSenders": true,
                        "hideWarningBannerSenderAllowlist": [
                            {
                                "name": "Example",
                                "list": [
                                    "bbc.co.uk",
                                    "npr.org",
                                    "spam@example.com"
                                ]
                            }
                        ],
                        "ruleId": "03b58-02rvqlb31lmj79f:00gjdgxs30j0zll"
                    },
                    {
                        "description": "UseMyTestList",
                        "enableAggressiveFiltering": false,
                        "addToQuarantine": false,
                        "bypassInternalSenders": true,
                        "bypassSelectedSenders": true,
                        "bypassSenderAllowlist": [
                            {
                                "name": "MyTestList",
                                "list": [
                                    "test.com"
                                ]
                            }
                        ],
                        "hideWarningBannerFromSelectedSenders": false,
                        "ruleId": "a89e8-02rvqlb31lmj79f:00gjdgxs1fob9te"
                    },
                    {
                        "description": "BypassAll Case",
                        "hideWarningBannerForAll": true
                    }
                ],
                "warningDomainsFound": "{test spam filter: [Example: (bbc.co.uk, npr.org)]}",
                "senderDomainsFound": "{UseMyTestList: [MyTestList: (test.com)]}"
            },
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

test_SpamFilterDomains_Correct_1 if {
    PolicyId := GmailId18_1
    Output := tests with input as GoodGmailApi18

    PassTestResult(PolicyId, Output)
}

test_SpamFilterDomains_Incorrect_1 if {
    PolicyId := GmailId18_1
    Output := tests with input as BadGmailApi18

    value := concat("",
                    ["{Scuba: [Scuba: (cisaent.onmicrosoft.com, ",
                       "scubagws.org)]}"])
    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage18_1(value)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpamFilterDomains_Incorrect_2 if {
    PolicyId := GmailId18_1
    Output := tests with input as BadGmailApi18a

    value := "{UseMyTestList: [MyTestList: (test.com)]}"
    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage18_1(value)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpamFilterWarnings_Correct_1 if {
    PolicyId := GmailId18_2
    Output := tests with input as GoodGmailApi18

    PassTestResult(PolicyId, Output)
}

test_SpamFilterWarnings_Incorrect_1 if {
    PolicyId := GmailId18_2
    Output := tests with input as BadGmailApi18

    value := concat("",
                    ["{Scuba: [Scuba: (cisaent.onmicrosoft.com, ",
                       "scubagws.org), MyTestList: (test.com)]}, ",
                       "{Second Rule: [MyTestList: (test.com)]}"])
    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage18_2(value)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpamFilterWarnings_Incorrect_2 if {
    PolicyId := GmailId18_2
    Output := tests with input as BadGmailApi18a

    value := "{test spam filter: [Example: (bbc.co.uk, npr.org)]}"
    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage18_2(value)}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpamFilterBypass_Correct_1 if {
    PolicyId := GmailId18_3
    Output := tests with input as GoodGmailApi18

    PassTestResult(PolicyId, Output)
}

test_SpamFilterBypass_Incorrect_1 if {
    PolicyId := GmailId18_3
    Output := tests with input as BadGmailApi18

    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage18_3("'Scuba', 'Second Rule'")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_SpamFilterBypass_Incorrect_2 if {
    PolicyId := GmailId18_3
    Output := tests with input as BadGmailApi18a

    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage18_3("'BypassAll Case'")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
