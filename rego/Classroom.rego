package classroom
import future.keywords
import data.utils.TopLevelOU
import data.utils.FilterEvents
import data.utils.GetLastEvent
import data.utils.OUsWithEvents
import data.utils.ReportDetailsOUs
import data.utils.NoSuchEventDetails

###################
# GWS.CLASSROOM.1 #
###################

#
# Baseline GWS.CLASSROOM.1.1v0.1
#--
NonCompliantOUs1_1 contains OU if {
   some OU in OUsWithEvents
    Events := FilterEvents("ClassMembershipSettingsGroup who_can_join_classes", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "1"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEvents("ClassMembershipSettingsGroup who_can_join_classes", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.1.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {

    Events := FilterEvents("ClassMembershipSettingsGroup who_can_join_classes", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_1) == 0
}
#--

#
# Baseline GWS.CLASSROOM.1.2v0.1
#--
NonCompliantOUs1_2 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEvents("ClassMembershipSettingsGroup which_classes_can_users_join", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "1"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.1.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEvents("ClassMembershipSettingsGroup which_classes_can_users_join", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.1.2v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs1_2),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs1_2},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEvents("ClassMembershipSettingsGroup which_classes_can_users_join", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs1_2) == 0
}
#--

###################
# GWS.CLASSROOM.2 #
###################

#
# Baseline GWS.CLASSROOM.2.1v0.1
#--
NonCompliantOUs2_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEvents("ApiDataAccessSettingProto api_access_enabled", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "false"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.2.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := false
    Events := FilterEvents("ApiDataAccessSettingProto api_access_enabled", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.2.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs2_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs2_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEvents("ApiDataAccessSettingProto api_access_enabled", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs2_1) == 0
}
#--

###################
# GWS.CLASSROOM.3 #
###################

#
# Baseline GWS.CLASSROOM.3.1v0.1
#--
NonCompliantOUs3_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEvents("RosterImportSettingsProto sis_integrator", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "SIS_INTEGRATOR_NONE"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.3.1v0.1",
    "Criticality": "Should",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    Events := FilterEvents("RosterImportSettingsProto sis_integrator", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.3.1v0.1",
    "Criticality": "Should",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs3_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs3_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEvents("RosterImportSettingsProto sis_integrator", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs3_1) == 0
}
#--

###################
# GWS.CLASSROOM.4 #
###################

#
# Baseline GWS.CLASSROOM.4.1v0.1
#--
NonCompliantOUs4_1 contains OU if {
    some OU in OUsWithEvents
    Events := FilterEvents("StudentUnenrollmentSettingsProto who_can_unenroll_students", OU)
    count(Events) > 0 # Ignore OUs without any events. We're already
    # asserting that the top-level OU has at least one event; for all
    # other OUs we assume they inherit from a parent OU if they have
    # no events.
    LastEvent := GetLastEvent(Events)
    LastEvent.NewValue != "ONLY_TEACHERS_CAN_UNENROLL_STUDENTS"
    LastEvent.NewValue != "DELETE_APPLICATION_SETTING"
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": NoSuchEventDetails(DefaultSafe, TopLevelOU),
    "ActualValue": "No relevant event in the current logs",
    "RequirementMet": DefaultSafe,
    "NoSuchEvent": true
}
if {
    DefaultSafe := true
    Events := FilterEvents("StudentUnenrollmentSettingsProto who_can_unenroll_students", TopLevelOU)
    count(Events) == 0
}

tests contains {
    "PolicyId": "GWS.CLASSROOM.4.1v0.1",
    "Criticality": "Shall",
    "ReportDetails": ReportDetailsOUs(NonCompliantOUs4_1),
    "ActualValue": {"NonCompliantOUs": NonCompliantOUs4_1},
    "RequirementMet": Status,
    "NoSuchEvent": false
}
if {
    Events := FilterEvents("StudentUnenrollmentSettingsProto who_can_unenroll_students", TopLevelOU)
    count(Events) > 0
    Status := count(NonCompliantOUs4_1) == 0
}
#--
