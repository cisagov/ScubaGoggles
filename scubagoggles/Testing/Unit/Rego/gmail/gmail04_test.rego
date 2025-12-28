package gmail
import future.keywords

#
# GWS.GMAIL.4.1
#--
test_DMARC_Correct_V1 if {
    # Test DMARC when there's only one domain
    PolicyId := GmailId4_1
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov"
                ]
            }
        ],
        "domains": ["test.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["Requirement met.", DNSLink])
}

test_DMARC_Correct_V2 if {
    # Test DMARC when there's multiple domains
    PolicyId := GmailId4_1
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test1.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov"
                ]
            },
            {
                "domain": "test2.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov"
                ]
            }
        ],
        "domains": ["test1.name", "test2.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["Requirement met.", DNSLink])
}

test_DMARC_Incorrect_V1 if {
    # Test DMARC when there's multiple domains and only one is correct
    PolicyId := GmailId4_1
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test1.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov"
                ]
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
    RuleOutput[0].ReportDetails == concat(" ", ["1 of 2 agency domain(s) found in violation: test2.name.", DNSLink])
    
}

test_DMARC_Incorrect_V2 if {
    # Test DMARC when there's only one domain and it's wrong
    PolicyId := GmailId4_1
    Output := tests with input as {
        "dmarc_records": [
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
    RuleOutput[0].ReportDetails == concat(" ", ["1 of 1 agency domain(s) found in violation: test.name.", DNSLink])
}

test_DMARC_Multiple_Records_V1 if {
    # Test DMARC when a domain has multiple DMARC records (should FAIL per RFC 7489)
    PolicyId := GmailId4_1
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:reports@dmarc.cyber.dhs.gov",
                    "v=DMARC1; p=quarantine; pct=100; rua=mailto:admin@test.name"
                ]
            }
        ],
        "domains": ["test.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 of 1 agency domain(s) found in violation: test.name.", DNSLink])
}

test_DMARC_Multiple_Records_V2 if {
    # Test DMARC when one domain has single record and another has multiple (mixed scenario)
    PolicyId := GmailId4_1
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "good.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:reports@dmarc.cyber.dhs.gov"
                ]
            },
            {
                "domain": "bad.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:reports@dmarc.cyber.dhs.gov",
                    "v=DMARC1; p=quarantine; pct=50; rua=mailto:admin@bad.name"
                ]
            }
        ],
        "domains": ["good.name", "bad.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 of 2 agency domain(s) found in violation: bad.name.", DNSLink])
}

#
# GWS.GMAIL.4.2
#--

test_DMARCMessageReject_Correct_V1 if {
    # Test DMARC when there's only one domain
    PolicyId := GmailId4_2
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov"
                ]
            }
        ],
        "domains": ["test.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["Requirement met.", DNSLink])
}

test_DMARCMessageReject_Correct_V2 if {
    # Test DMARC when there's multiple domains
    PolicyId := GmailId4_2
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test1.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov"
                ]
            },
            {
                "domain": "test2.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov"
                ]
            }
        ],
        "domains": ["test1.name", "test2.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["Requirement met.", DNSLink])
}

test_DMARCMessageReject_Incorrect_V1 if {
    # Test DMARC when there's multiple domains and only one is correct
    PolicyId := GmailId4_2
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test1.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov"
                ]
            },
            {
                "domain": "test2.name",
                "rdata": ["v=DMARC1; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov"]
            }
        ],
        "domains": ["test1.name", "test2.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 of 2 agency domain(s) found in violation: test2.name.", DNSLink])
}

test_DMARCMessageReject_Incorrect_V2 if {
    # Test DMARC when there's only one domain and it's wrong
    PolicyId := GmailId4_2
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": ["v=DMARC1; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov"]
            }
        ],
        "domains": ["test.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 of 1 agency domain(s) found in violation: test.name.", DNSLink])
}

test_DMARCMessageReject_Multiple_Records if {
    # Test that domains with multiple DMARC records fail p=reject check
    PolicyId := GmailId4_2
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:reports@dmarc.cyber.dhs.gov",
                    "v=DMARC1; p=quarantine; pct=100; rua=mailto:admin@test.name"
                ]
            }
        ],
        "domains": ["test.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 of 1 agency domain(s) found in violation: test.name.", DNSLink])
}

#
# GWS.GMAIL.4.3
#--

test_DMARCAggregateReports_Correct_V1 if {
    # Test DMARC when there's only one domain
    PolicyId := GmailId4_3
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov"
                ]
            }
        ],
        "domains": ["test.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["Requirement met.", DNSLink])
}

test_DMARCAggregateReports_Correct_V2 if {
    # Test DMARC when there's multiple domains
    PolicyId := GmailId4_3
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test1.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov"
                ]
            },
            {
                "domain": "test2.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov"
                ]
            }
        ],
        "domains": ["test1.name", "test2.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["Requirement met.", DNSLink])
}

test_DMARCAggregateReports_Incorrect_V1 if {
    # Test DMARC when there's multiple domains and only one is correct
    PolicyId := GmailId4_3
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test1.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov"
                ]
            },
            {
                "domain": "test2.name",
                "rdata": ["v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov"]
            }
        ],
        "domains": ["test1.name", "test2.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 of 2 agency domain(s) found in violation: test2.name.", DNSLink])
}

test_DMARCAggregateReports_Incorrect_V2 if {
    # Test DMARC when there's only one domain and it's wrong
    PolicyId := GmailId4_3
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": ["v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov"]
            }
        ],
        "domains": ["test.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 of 1 agency domain(s) found in violation: test.name.", DNSLink])
}

test_DMARCAggregateReports_Multiple_Records if {
    # Test that domains with multiple DMARC records fail DHS contact check
    PolicyId := GmailId4_3
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:reports@dmarc.cyber.dhs.gov",
                    "v=DMARC1; p=reject; pct=100; rua=mailto:reports@dmarc.cyber.dhs.gov"
                ]
            }
        ],
        "domains": ["test.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 of 1 agency domain(s) found in violation: test.name.", DNSLink])
}

#
# GWS.GMAIL.4.4
#--

test_DMARCAgencyPOC_Correct_V1 if {
    # Test DMARC when there's only one domain
    PolicyId := GmailId4_4
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov"
                ]
            }
        ],
        "domains": ["test.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["Requirement met.", DNSLink])
}

test_DMARCAgencyPOC_Correct_V2 if {
    # Test DMARC when there's multiple domains
    PolicyId := GmailId4_4
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test1.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov"
                ]
            },
            {
                "domain": "test2.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov"
                ]
            }
        ],
        "domains": ["test1.name", "test2.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["Requirement met.", DNSLink])
}

test_DMARCAgencyPOC_Incorrect_V1 if {
    # Test DMARC when there's multiple domains and only one is correct
    PolicyId := GmailId4_4
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test1.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov"
                ]
            },
            {
                "domain": "test2.name",
                "rdata": ["v=DMARC1; p=reject; pct=100; mailto:reports@dmarc.cyber.dhs.gov"]
            }
        ],
        "domains": ["test1.name", "test2.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 of 2 agency domain(s) found in violation: test2.name.", DNSLink])
}

test_DMARCAgencyPOC_Incorrect_V2 if {
    # Test DMARC when there's only one domain and it's wrong
    PolicyId := GmailId4_4
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": ["v=DMARC1; p=reject; pct=100; mailto:reports@dmarc.cyber.dhs.gov"]
            }
        ],
        "domains": ["test.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 of 1 agency domain(s) found in violation: test.name.", DNSLink])
}

test_DMARCAgencyPOC_Multiple_Records if {
    # Test that domains with multiple DMARC records fail agency POC check
    PolicyId := GmailId4_4
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov",
                    "v=DMARC1; p=reject; pct=100; rua=mailto:admin@test.name, mailto:reports@dmarc.cyber.dhs.gov"
                ]
            }
        ],
        "domains": ["test.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 of 1 agency domain(s) found in violation: test.name.", DNSLink])
}
#--
