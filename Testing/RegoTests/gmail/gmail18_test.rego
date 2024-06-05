package gmail
import future.keywords


#
# GWS.GMAIL.18.1v0.2
#--
test_AdvanvedEmailContentFitlering_Correct_V1 if {
    # Test Advanced Email Content Filtering when there's only one event
    PolicyId := "GWS.GMAIL.18.1v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Currently not able to be tested automatically; please manually check."
}
#--

#
# GWS.GMAIL.18.2v0.2
#--
test_Other_Correct_V1 if {
    # Test not implemented
    PolicyId := "GWS.GMAIL.18.2v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Currently not able to be tested automatically; please manually check."
}
#--

#
# GWS.GMAIL.18.3v0.2
#--
test_PII_Correct_V1 if {
    # Test not implemented
    PolicyId := "GWS.GMAIL.18.3v0.2"
    Output := tests with input as {
        "gmail_logs": {"items": [
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    not RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Currently not able to be tested automatically; please manually check."
}
#--