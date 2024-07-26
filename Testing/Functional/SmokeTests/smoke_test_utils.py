import pytest
import os

required_contents = [
    "BaselineReports.html", 
    "IndividualReports", 
    "ScubaResults.json",
    "TestResults.json",
    "images",
    "CalendarReport.html",
    "ChatReport.html",
    "ClassroomReport.html",
    "CommoncontrolsReport.html",
    "DriveReport.html",
    "GmailReport.html",
    "GroupsReport.html",
    "MeetReport.html",
    "RulesReport.html",
    "SitesReport.html",
    "cisa_logo.png",
    "triangle-exclamation-solid.svg"
]

def verify_output_type(output_path, contents):
    entries = os.listdir(output_path)

    for entry in entries:
        contents.append(entry)

        # Check if entry is a valid directory or file
        child_path = os.path.join(output_path, entry)
        if os.path.isdir(child_path):
            assert True
            verify_output_type(child_path, contents)
        elif os.path.isfile(child_path):
            assert True
        else:
            raise OSError(f"Entry is not a directory or file (symlink, etc.)")

    return contents

def verify_all_outputs_exist(contents):
    for required_content in required_contents:
        if required_content in contents:
            assert True
        else:
            raise ValueError(f"{required_content} was not found in the generated report")