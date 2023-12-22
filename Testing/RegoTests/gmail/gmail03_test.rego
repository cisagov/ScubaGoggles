package gmail
import future.keywords


#
# GWS.GMAIL.3.1v0.1
#--
test_SPF_Correct_V1 if {
    # Test SPF when there's only one domain
    PolicyId := "GWS.GMAIL.3.1v0.1"
    Output := tests with input as {
        "dkim_records": [
            {
                "domain": "test.name",
                "rdata": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlaknWsKvtbTLAxtWSF5sDt+"]
            }
        ],
        "spf_records": [
            {
                "domain": "test.name",
                "rdata": ["v=spf1 include:_spf.google.com ~all"]
            }
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_SPF_Correct_V2 if {
    # Test SPF when there's multiple domains
    PolicyId := "GWS.GMAIL.3.1v0.1"
    Output := tests with input as {
        "dkim_records": [
            {
                "domain": "test1.name",
                "rdata": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlaknWsKvtbTLAxtWSF5sDt+"]
            },
            {
                "domain": "test2.name",
                "rdata": ["v=DKIM1;"]
            }
        ],
        "spf_records": [
            {
                "domain": "test1.name",
                "rdata": ["v=spf1 include:_spf.google.com ~all"]
            },
            {
                "domain": "test2.name",
                "rdata": ["v=spf1 "]
            }
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_SPF_Incorrect_V1 if {
    # Test SPF when there's multiple domains and only one is correct
    PolicyId := "GWS.GMAIL.3.1v0.1"
    Output := tests with input as {
        "dkim_records": [
            {
                "domain": "test1.name",
                "rdata": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlaknWsKvtbTLAxtWSF5sDt+"]
            },
            {
                "domain": "test2.name",
                "rdata": ["v=DKIM1;"]
            }
        ],
        "spf_records": [
            {
                "domain": "test1.name",
                "rdata": ["v=spf1 include:_spf.google.com ~all"]
            },
            {
                "domain": "test2.name",
                "rdata": []
            }
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "1 of 2 agency domain(s) found in violation: test2.name."
}

test_SPF_Incorrect_V2 if {
    # Test SPF when there's only one domain and it's wrong
    PolicyId := "GWS.GMAIL.3.1v0.1"
    Output := tests with input as {
        "dkim_records": [
            {
                "domain": "test.name",
                "rdata": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlaknWsKvtbTLAxtWSF5sDt+"]
            }
        ],
        "spf_records": [
            {
                "domain": "test.name",
                "rdata": []
            }
        ]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "1 of 1 agency domain(s) found in violation: test.name."
}
#--