import os

required_contents = [
    "BaselineReports.html", 
    "IndividualReports", 
    "ProviderSettingsExport.json", 
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

def verify_all_outputs_exist(contents):
    try: 
        for required_content in required_contents:
            if required_content in contents:
                assert True
            else:
                assert False, f"{required_content} was not found in the generated report"
    except Exception as e:
        assert False, f"An error occurred, {e}"

def verify_output_type(output_path, contents):
    try:
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
                assert False, f"Entry is not a directory or file (symlink, etc.)"

        return contents
    except FileNotFoundError:
        assert False, f"The directory {output_path} does not exist"
    except Exception as e:
        assert False, f"An error occurred, {e}"