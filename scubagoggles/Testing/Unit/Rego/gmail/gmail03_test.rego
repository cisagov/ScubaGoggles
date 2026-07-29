package gmail
import future.keywords

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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["Requirement met. ", DNSLink])
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["Requirement met. ", DNSLink])
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["Requirement met. ", DNSLink])
}

test_SPF_Correct_V4 if {
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["Requirement met. ", DNSLink])
}

test_SPF_Incorrect_V1 if {
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 failing domain(s): <ul id=\"spf-domains\"><li>test2.name: Domain exists but no answers returned.</li></ul>", DNSLink])
}

test_SPF_Incorrect_V2 if {
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 failing domain(s): <ul id=\"spf-domains\"><li>test.name: Domain exists but no answers returned.</li></ul>", DNSLink])
}
#--

test_SPF_Incorrect_V3 if {
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 failing domain(s): <ul id=\"spf-domains\"><li>test.name: SPF record found, but it does not hardfail (`\"-all`\") or redirect to one that does.</li></ul>", DNSLink])
}

test_SPF_Incorrect_V4 if {
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

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 failing domain(s): <ul id=\"spf-domains\"><li>test.name: More than one record found</li></ul>", DNSLink])
}
#--
