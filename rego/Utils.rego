package utils
import future.keywords

NoSuchEventDetails(DefaultSafe, TopLevelOU) := Message if {
    DefaultSafe == true
    Message := concat("", [
        "No relevant event in the current logs for the top-level OU, ",
        TopLevelOU,
        ". While we are unable to determine the state from the logs, the default setting is compliant",
        "; manual check recommended."
    ])
}

NoSuchEventDetails(DefaultSafe, TopLevelOU) := Message if {
    DefaultSafe == false
    Message := concat("", [
        "No relevant event in the current logs for the top-level OU, ",
        TopLevelOU,
        ". While we are unable to determine the state from the logs, the default setting is non-compliant",
        "; manual check recommended."
    ])
}

ReportDetailsOUs(OUs) := "Requirement met in all OUs." if {count(OUs) == 0}
ReportDetailsOUs(OUs) := Message if {
    count(OUs) > 0
    Message := concat("", ["Requirement failed in ", concat(", ", OUs), "."])
}