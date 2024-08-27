package gmail
import future.keywords


#
# GWS.GMAIL.3.1v0.3
#--
test_SPF_Correct_V1 if {
    # Test SPF when there's only one domain
    PolicyId := "GWS.GMAIL.3.1v0.3"
    Output := tests with input as {
        "spf_records": [
            {
                "domain": "test.name",
                "rdata": ["v=spf1 include:_spf.google.com -all"]
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

test_SPF_Correct_V2 if {
    # Test SPF when there's multiple domains
    PolicyId := "GWS.GMAIL.3.1v0.3"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_SPF_Correct_V3 if {
    # Test SPF redirect
    PolicyId := "GWS.GMAIL.3.1v0.3"
    Output := tests with input as {
        "spf_records": [
            {
                "domain": "test1.name",
                "rdata": ["v=spf1 redirect=_spf.example.com"]
            }
        ],
        "domains": ["test1.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Requirement met."
}

test_SPF_Incorrect_V1 if {
    # Test SPF when there's multiple domains and only one is correct
    PolicyId := "GWS.GMAIL.3.1v0.3"
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "1 of 2 agency domain(s) found in violation: test2.name."
}

test_SPF_Incorrect_V2 if {
    # Test SPF when there's only one domain and it's wrong
    PolicyId := "GWS.GMAIL.3.1v0.3"
    Output := tests with input as {
        "spf_records": [
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

test_SPF_Incorrect_V3 if {
    # Test softfail
    PolicyId := "GWS.GMAIL.3.1v0.3"
    Output := tests with input as {
        "spf_records": [
            {
                "domain": "test.name",
                "rdata": ["v=spf1 include:_spf.google.com ~all"]
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

test_SPF_Incorrect_V4 if {
    # Test no "all" mechanism
    PolicyId := "GWS.GMAIL.3.1v0.3"
    Output := tests with input as {
        "spf_records": [
            {
                "domain": "test.name",
                "rdata": ["v=spf1 include:_spf.google.com"]
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