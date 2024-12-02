package commoncontrols

import future.keywords
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

GoodCaseInputApi12 := {
    "policies": {
        "topOU": {
            "blogger_user_takeout": {"takeoutStatus": "DISABLED"},
            "books_user_takeout": {"takeoutStatus": "DISABLED"},
            "location_history_user_takeout": {"takeoutStatus": "DISABLED"},
            "maps_user_takeout": {"takeoutStatus": "DISABLED"},
            "pay_user_takeout": {"takeoutStatus": "DISABLED"},
            "photos_user_takeout": {"takeoutStatus": "DISABLED"},
            "play_console_user_takeout": {"takeoutStatus": "DISABLED"},
            "play_user_takeout": {"takeoutStatus": "DISABLED"},
            "youtube_user_takeout": {"takeoutStatus": "DISABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi12 := {
    "policies": {
        "topOU": {
            "blogger_user_takeout": {"takeoutStatus": "ENABLED"},
            "books_user_takeout": {"takeoutStatus": "ENABLED"},
            "location_history_user_takeout": {"takeoutStatus": "ENABLED"},
            "maps_user_takeout": {"takeoutStatus": "ENABLED"},
            "pay_user_takeout": {"takeoutStatus": "ENABLED"},
            "photos_user_takeout": {"takeoutStatus": "ENABLED"},
            "play_console_user_takeout": {"takeoutStatus": "ENABLED"},
            "play_user_takeout": {"takeoutStatus": "ENABLED"},
            "youtube_user_takeout": {"takeoutStatus": "ENABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

BadCaseInputApi12a := {
    "policies": {
        "topOU": {
            "blogger_user_takeout": {"takeoutStatus": "DISABLED"},
            "books_user_takeout": {"takeoutStatus": "DISABLED"},
            "location_history_user_takeout": {"takeoutStatus": "DISABLED"},
            "maps_user_takeout": {"takeoutStatus": "DISABLED"},
            "pay_user_takeout": {"takeoutStatus": "DISABLED"},
            "photos_user_takeout": {"takeoutStatus": "DISABLED"},
            "play_console_user_takeout": {"takeoutStatus": "DISABLED"},
            "play_user_takeout": {"takeoutStatus": "DISABLED"},
            "youtube_user_takeout": {"takeoutStatus": "DISABLED"}
        },
        "nextOU": {
            "location_history_user_takeout": {"takeoutStatus": "ENABLED"},
            "play_console_user_takeout": {"takeoutStatus": "ENABLED"},
            "youtube_user_takeout": {"takeoutStatus": "ENABLED"}
        },
        "thirdOU": {
            "blogger_user_takeout": {"takeoutStatus": "ENABLED"},
            "maps_user_takeout": {"takeoutStatus": "ENABLED"},
            "play_user_takeout": {"takeoutStatus": "ENABLED"},
            "youtube_user_takeout": {"takeoutStatus": "DISABLED"}
        }
    },
    "tenant_info": {
        "topLevelOU": "topOU"
    }
}

TakeoutApps(keys) := [Takeout[key] | some key in keys]

test_Takeout_Correct_1 if {
    PolicyId := CommonControlsId12_1
    Output := tests with input as GoodCaseInputApi12

    PassTestResult(PolicyId, Output)
}

test_Takeout_Incorrect_1 if {
    PolicyId := CommonControlsId12_1
    Output := tests with input as BadCaseInputApi12

    EnabledApps := ["blogger",
                    "books",
                    "location_history",
                    "maps",
                    "pay",
                    "photos",
                    "play_console",
                    "play",
                    "youtube"]
    failedOU := [{"Name": "topOU",
                 "Value": NonComplianceMessage12_1(TakeoutApps(EnabledApps))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_Takeout_Incorrect_2 if {
    PolicyId := CommonControlsId12_1
    Output := tests with input as BadCaseInputApi12a

    EnabledApps1 := ["location_history", "play_console", "youtube"]
    EnabledApps2 := ["blogger", "maps", "play"]
    failedOU := [{"Name": "nextOU",
                 "Value": NonComplianceMessage12_1(TakeoutApps(EnabledApps1))},
                 {"Name": "thirdOU",
                 "Value": NonComplianceMessage12_1(TakeoutApps(EnabledApps2))}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
