package meet
import future.keywords

#
# GWS.MEET.6.1
#--

test_AutoRecording_Correct_V1 if {
    # Test not implemented
    PolicyId := MeetId6_1
    Output := tests with input as {
        "meet_logs": {"items": [

        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Currently not able to be tested automatically; please manually check."
}
#--

#
# GWS.MEET.6.2
#--

test_AutoTranscript_Correct_V1 if {
    # Test not implemented
    PolicyId := MeetId6_2
    Output := tests with input as {
        "meet_logs": {"items": [

        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    RuleOutput := [Result | some Result in Output; Result.PolicyId == PolicyId]
    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].NoSuchEvent
    RuleOutput[0].ReportDetails == "Currently not able to be tested automatically; please manually check."
}

#--