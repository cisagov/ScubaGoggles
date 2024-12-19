package calendar

import future.keywords
import data.utils.FailTestNoEvent
import data.utils.FailTestOUNonCompliant
import data.utils.PassTestResult

#
# GWS.CALENDAR.4.1
#--
test_CalendarAppointmentSlot_Correct_V1 if {
    # Test Calendar Appointment Slot when there's only one event
    PolicyId := CalendarId4_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "CalendarAppointmentSlotAdminSettingsProto payments_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"}
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    PassTestResult(PolicyId, Output)
}

test_CalendarAppointmentSlot_Correct_V2 if {
    # Test Calendar Appointment Slot when there's multiple events and the most recent is correct
    PolicyId := CalendarId4_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "CalendarAppointmentSlotAdminSettingsProto payments_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "CalendarAppointmentSlotAdminSettingsProto payments_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    PassTestResult(PolicyId, Output)
}

test_CalendarAppointmentSlot_Correct_V3 if {
    # Test Calendar Appointment Slot when there's correct events in multiple OUs
    PolicyId := CalendarId4_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "CalendarAppointmentSlotAdminSettingsProto payments_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2022-12-21T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "CalendarAppointmentSlotAdminSettingsProto payments_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        }
    }

    PassTestResult(PolicyId, Output)
}

test_CalendarAppointmentSlot_Incorrect_V1 if {
    # Test Calendar Appointment Slot when there are no relevant events
    PolicyId := CalendarId4_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "Something else"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    FailTestNoEvent(PolicyId, Output, "Test Top-Level OU", true)
}

test_CalendarAppointmentSlot_Incorrect_V2 if {
    # Test Calendar Appointment Slot when there's only one event and it's wrong
    PolicyId := CalendarId4_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "CalendarAppointmentSlotAdminSettingsProto payments_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage4_1("enabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_CalendarAppointmentSlot_Incorrect_V3 if {
    # Test Calendar Appointment Slot when there are multiple events and the most recent is wrong
    PolicyId := CalendarId4_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "CalendarAppointmentSlotAdminSettingsProto payments_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "CalendarAppointmentSlotAdminSettingsProto payments_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        },
    }

    failedOU := [{"Name": "Test Top-Level OU",
                 "Value": NonComplianceMessage4_1("enabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_CalendarAppointmentSlot_Incorrect_V4 if {
    # Test Calendar Appointment Slot when there's only one event and it's wrong
    PolicyId := CalendarId4_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "CalendarAppointmentSlotAdminSettingsProto payments_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": ""
        }
    }

    failedOU := [{"Name": "Secondary OU",
                 "Value": NonComplianceMessage4_1("enabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}

test_CalendarAppointmentSlot_Incorrect_V5 if {
    # Test Calendar Appointment Slot when there are multiple events and the most recent is wrong
    PolicyId := CalendarId4_1
    Output := tests with input as {
        "calendar_logs": {"items": [
            {
                "id": {"time": "2022-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "CalendarAppointmentSlotAdminSettingsProto payments_enabled"},
                        {"name": "NEW_VALUE", "value": "true"},
                        {"name": "ORG_UNIT_NAME", "value": "Secondary OU"},
                    ]
                }]
            },
            {
                "id": {"time": "2021-12-20T00:02:28.672Z"},
                "events": [{
                    "parameters": [
                        {"name": "SETTING_NAME", "value": "CalendarAppointmentSlotAdminSettingsProto payments_enabled"},
                        {"name": "NEW_VALUE", "value": "false"},
                        {"name": "ORG_UNIT_NAME", "value": "Test Top-Level OU"},
                    ]
                }]
            }
        ]},
        "tenant_info": {
            "topLevelOU": "Test Top-Level OU"
        },
    }

    failedOU := [{"Name": "Secondary OU",
                 "Value": NonComplianceMessage4_1("enabled")}]
    FailTestOUNonCompliant(PolicyId, Output, failedOU)
}
#--
