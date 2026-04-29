package gmail
import future.keywords

MultipleWarning := "1 domain(s) have multiple DMARC records: test.name."
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

test_DMARC_Incorrect_V3 if {
    # Test DMARC when there are multiple dmarc records
    PolicyId := GmailId4_1
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov",
                    "v=DMARC1; p=reject"
                ]
            }
        ],
        "domains": ["test.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 of 1 agency domain(s) found in violation: test.name.",
        MultipleWarning, DNSLink])
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

test_DMARCMessageReject_Incorrect_V3 if {
    # Test DMARC when there are multiple dmarc records
    PolicyId := GmailId4_2
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov",
                    "v=DMARC1; p=reject"
                ]
            }
        ],
        "domains": ["test.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 of 1 agency domain(s) found in violation: test.name.",
        MultipleWarning, DNSLink])
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

test_DMARCAggregateReports_Incorrect_V3 if {
    # Test DMARC when there are multiple dmarc records
    PolicyId := GmailId4_3
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov",
                    "v=DMARC1; p=reject"
                ]
            }
        ],
        "domains": ["test.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 of 1 agency domain(s) found in violation: test.name.",
        MultipleWarning, DNSLink])
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
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:forensics@dhs.gov"
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
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:forensics@dhs.gov"
                ]
            },
            {
                "domain": "test2.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:forensics@dhs.gov"
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
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:forensics@dhs.gov"
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

test_DMARCAgencyPOC_Incorrect_V3 if {
    # Test DMARC when there are multiple dmarc records
    PolicyId := GmailId4_4
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov",
                    "v=DMARC1; p=reject"
                ]
            }
        ],
        "domains": ["test.name"]
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 of 1 agency domain(s) found in violation: test.name.",
        MultipleWarning,
        DNSLink])
}

test_DMARCAgencyPOC_Incorrect_MissingRuf if {
    # Test DMARC when it's missing a RUF value
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
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == concat(" ", ["1 of 1 agency domain(s) found in violation: test.name.", DNSLink])
}

test_DMARCAgencyPOC_Incorrect_MissingRua if {
    # Test DMARC when it's missing a RUA value
    PolicyId := GmailId4_4
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; ruf=mailto:forensics@dhs.gov"
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

test_DMARCAgencyPOC_Incorrect_DuplicateRuaTags if {
    # Test DMARC record if there's multiple RUA fields in the DMARC record
    PolicyId := GmailId4_4
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov; rua=mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:forensics@dhs.gov"
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

test_DMARCAgencyPOC_Incorrect_DuplicateRufTags if {
    # Test DMARC record if there's multiple RUF fields in the DMARC record
    PolicyId := GmailId4_4
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:forensics1@dhs.gov; ruf=mailto:forensics2@dhs.gov"
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

test_DMARCAgencyPOC_Incorrect_OneRuaAddress if {
    # Test DMARC record if there's only one RUA address
    PolicyId := GmailId4_4
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov; ruf=mailto:forensics@dhs.gov"
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

test_DMARCAgencyPOC_Incorrect_RufNotMailto if {
    # Test DMARC record RUF field if it's not formed correctly (not "mailto")
    PolicyId := GmailId4_4
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=mailto:DMARC@hq.dhs.gov, mailto:reports@dmarc.cyber.dhs.gov; ruf=https://dhs.gov/forensics"
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

test_DMARCAgencyPOC_Incorrect_RuaNotMailto if {
    # Test DMARC record RUA field if it's not formed correctly (not "mailto")
    PolicyId := GmailId4_4
    Output := tests with input as {
        "dmarc_records": [
            {
                "domain": "test.name",
                "rdata": [
                    "v=DMARC1; p=reject; pct=100; rua=https://dhs.gov/aggregateReporting, mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:forensics2@dhs.gov"
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
