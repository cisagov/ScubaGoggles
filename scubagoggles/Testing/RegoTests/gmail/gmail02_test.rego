package gmail
import future.keywords

#
# GWS.GMAIL.2.1
#--
test_DKIM_Correct_V1 if {
    # Test DKIM when there's only one domain
    PolicyId := GmailId2_1
    Output := tests with input as {
        "dkim_records": [
            {
                "domain": "test.name",
                "rdata": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlaknWsKvtbTLAxtWSF5sDt"]
            }
        ],
        "domains": ["test.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_DKIM_Correct_V2 if {
    # Test DKIM when there's multiple domains
    PolicyId := GmailId2_1
    Output := tests with input as {
        "dkim_records": [
            {
                "domain": "test1.name",
                "rdata": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlaknWsKvtbTLAxtWSF5sDt"]
            },
            {
                "domain": "test2.name",
                "rdata": ["v=DKIM1;"]
            }
        ],
        "domains": ["test1.name", "test2.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_DKIM_Incorrect_V1 if {
    # Test DKIM when there's multiple domains and only one is correct
    PolicyId := GmailId2_1
    Output := tests with input as {
        "dkim_records": [
            {
                "domain": "test1.name",
                "rdata": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlaknWsKvtbTLAxtWSF5sDt"]
            },
            {
                "domain": "test2.name",
                "rdata": []
            }
        ],
        "domains": ["test1.name", "test2.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "1 of 2 agency domain(s) found in violation: test2.name."
}

test_DKIM_Incorrect_V2 if {
    # Test DKIM when there's only one domain and it's wrong
    PolicyId := GmailId2_1
    Output := tests with input as {
        "dkim_records": [
            {
                "domain": "test.name",
                "rdata": []
            }
        ],
        "domains": ["test.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "1 of 1 agency domain(s) found in violation: test.name."
}
#--
