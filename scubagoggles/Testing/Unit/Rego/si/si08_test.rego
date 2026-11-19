package si
import future.keywords

import data.utils.FailTestNonCompliant

#
# GWS.SI.8.1
#--

test_NotebookExternalSharing_NotImplemented_V1 if {
    # Not-Implemented
    PolicyId := SIId8_1
    Output := tests with input as {
        "si_logs": {"items": []},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    Message := "Currently not able to be tested automatically; please manually check."
    FailTestNonCompliant(PolicyId, Output, Message)
}
#--

#
# GWS.SI.8.2
#--

test_NotebookPublicSharing_NotImplemented_V1 if {
    # Not-Implemented
    PolicyId := SIId8_2
    Output := tests with input as {
        "si_logs": {"items": []},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    Message := "Currently not able to be tested automatically; please manually check."
    FailTestNonCompliant(PolicyId, Output, Message)
}
#--
