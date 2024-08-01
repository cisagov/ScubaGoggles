import pytest
import os
import json

def get_output_path() -> str:
    directories: list[str] = [d for d in os.listdir() if os.path.isdir(d) and d.startswith("GWSBaselineConformance")]
    directories.sort(key=lambda d: os.path.getctime(d), reverse=True)
    return os.path.join(os.getcwd(), directories[0])

def prepend_file_protocol(path: str) -> str:
    if not path.startswith("file://"):
        path = "file://" + path
    return path

def verify_output_type(output_path: str, contents: list[str]) -> list[str]:
    entries: list[str] = os.listdir(output_path)
    for entry in entries:
        contents.append(entry)
        # Check if entry is a valid directory or file
        child_path: str = os.path.join(output_path, entry)
        if os.path.isdir(child_path):
            assert True
            verify_output_type(child_path, contents)
        elif os.path.isfile(child_path):
            # Check for valid json
            if child_path.endswith(".json"):
                try:
                    with open(child_path) as jsonfile:
                        json.load(jsonfile)
                except ValueError as e:
                    pytest.fail(f"Invalid json, ${e}")
            assert True
        else:
            raise OSError(f"Entry is not a directory or file (symlink, etc.)")
    return contents

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

def verify_all_outputs_exist(contents: list[str]):
    for required_content in required_contents:
        if required_content in contents:
            assert True
        else:
            raise ValueError(f"{required_content} was not found in the generated report")