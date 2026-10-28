package gmail
import future.keywords
import data.utils.FailTestResult
import data.utils.PassTestResultWithMessage

Gmail3SuccessMessage := sprintf("Requirement met.  %s", [DNSLink])

Gmail3FailMessage(domain, message) := sprintf("1 failing domain(s): %s%s: %s%s%s",
                                              ["<ul id=\"spf-domains\"><li>\n  ",
                                               domain,
                                               message,
                                               "\n</li>\n</ul> ",
                                               DNSLink])

NoAnsMsg := "Domain exists but no answers returned."

NoHardFailMsg := "SPF record found, but it does not hardfail (\"-all\") or redirect to one that does."

#
# GWS.GMAIL.3.1
#--
test_SPF_Correct_V1 if {
    # Test SPF when there's only one domain
    PolicyId := GmailId3_1
    Output := tests with input as {
        "spf_records": [
            {
                "domain": "test.name",
                "rdata": ["v=spf1 include:_spf.google.com -all"]
            }
        ],
        "domains": ["test.name"]
    }

    PassTestResultWithMessage(PolicyId, Output, Gmail3SuccessMessage)
}

test_SPF_Correct_V2 if {
    # Test SPF when there's multiple domains
    PolicyId := GmailId3_1
    Output := tests with input as {
        "spf_records": [
            {
                "domain": "test1.name",
                "rdata": ["v=spf1 include:_spf.google.com -all"]
            },
            {
                "domain": "test2.name",
                "rdata": ["v=spf1 -all"]
            }
        ],
        "domains": ["test1.name", "test2.name"]
    }

    PassTestResultWithMessage(PolicyId, Output, Gmail3SuccessMessage)
}

test_SPF_Correct_V3 if {
    # Test SPF redirect
    PolicyId := GmailId3_1
    Output := tests with input as {
        "spf_records": [
            {
                "domain": "test1.name",
                "rdata": ["v=spf1 redirect=_spf.example.com"]
            }
        ],
        "domains": ["test1.name"]
    }

    PassTestResultWithMessage(PolicyId, Output, Gmail3SuccessMessage)
}

test_SPF_Incorrect_V1 if {
    # Test softfail
    PolicyId := GmailId3_1
    Output := tests with input as {
        "spf_records": [
            {
                "domain": "test.name",
                "rdata": ["v=spf1 include:_spf.google.com ~all"]
            }
        ],
        "domains": ["test.name"]
    }

    FailTestResult(PolicyId, Output, Gmail3FailMessage("test.name", NoHardFailMsg))
}

test_SPF_Incorrect_V2 if {
    # Test SPF when there's multiple domains and only one is correct
    PolicyId := GmailId3_1
    Output := tests with input as {
        "spf_records": [
            {
                "domain": "test1.name",
                "rdata": ["v=spf1 include:_spf.google.com -all"]
            },
            {
                "domain": "test2.name",
                "rdata": []
            }
        ],
        "domains": ["test1.name", "test2.name"]
    }

    FailTestResult(PolicyId, Output, Gmail3FailMessage("test2.name", NoAnsMsg))
}

test_SPF_Incorrect_V3 if {
    # Test SPF when there's only one domain and it's wrong
    PolicyId := GmailId3_1
    Output := tests with input as {
        "spf_records": [
            {
                "domain": "test.name",
                "rdata": []
            }
        ],
        "domains": ["test.name"]
    }

    FailTestResult(PolicyId, Output, Gmail3FailMessage("test.name", NoAnsMsg))
}
#--

test_SPF_Incorrect_V4 if {
    # Test no "all" mechanism
    PolicyId := GmailId3_1
    Output := tests with input as {
        "spf_records": [
            {
                "domain": "test.name",
                "rdata": ["v=spf1 include:_spf.google.com"]
            }
        ],
        "domains": ["test.name"]
    }

    FailTestResult(PolicyId, Output, Gmail3FailMessage("test.name", NoHardFailMsg))
}

test_SPF_Incorrect_V5 if {
    # Fail if multiple records
    PolicyId := GmailId3_1
    Output := tests with input as {
        "spf_records": [
            {
                "domain": "test.name",
                "rdata": ["v=spf1 include:_spf.google.com -all", "v=spf1 include:_spf.google.com -all"]
            }
        ],
        "domains": ["test.name"]
    }

    failMsg := "More than one record found."
    FailTestResult(PolicyId, Output, Gmail3FailMessage("test.name", failMsg))
}
#--
