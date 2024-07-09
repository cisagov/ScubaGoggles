"""
run_smoke_test.py is a test script to verify `scubagoggles gws`
outputs (i.e., files) are generated.
"""

import pytest
import subprocess
import os

"""
    Test virtualenv setup, activation

    Test installing dependencies for running scuba.py script 

    Test installing dependencies for running scubagoggles directly 

"""

def verify_output_type(output_path, contents):
    try:
        entries = os.listdir(output_path)
        print(entries)
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
        print(contents)
        for required_content in required_contents:
            if required_content in contents:
                assert True
            else:
                assert False, f"{required_content} was not found in the generated report"
    except Exception as e:
        assert False, f"An error occurred, {e}"
    

class TestScuba:
    #def test_venv_setup(self):
    #    command = f"scubagoggles gws "
    #    result = subprocess.run(command, shell=True)
    #    print(result.stdout)
    #    print(result.stderr)


    def test_cli(self, subjectemail):
        command = f"scubagoggles gws --subjectemail {subjectemail} --quiet -b commoncontrols"
        result = subprocess.run(command)

        if result.returncode != 0:
            raise AssertionError(f"Expected 0, but got {result.returncode}")
        
        cwd = os.getcwd()
        print(cwd)
        prefix = "GWSBaselineConformance"

        directories = [d for d in os.listdir() if os.path.isdir(d) and d.startswith(prefix)]
        directories.sort(key=lambda d: os.path.getctime(d), reverse=True)

        output_path = os.path.join(cwd, directories[0])
        individual_reports_path = f"{output_path}/IndividualReports"
        print(individual_reports_path)

        
        contents = verify_output_type(output_path, [])
        verify_all_outputs_exist(contents)

        #assert "BaselineReports.html" in entries and os.path.isfile(f"{output_path}/BaselineReports.html")
        #assert "IndividualReports" in entries and os.path.isdir(individual_reports_path)
        #assert "ProviderSettingsExport.json" in entries and os.path.isfile(f"{output_path}/ProviderSettingsExport.json")
        #assert "TestResults.json" in entries and os.path.isfile(f"{output_path}/TestResults.json")
#
        #assert "CalendarReport.html" in os.listdir(individual_reports_path)
        #assert "ChatReport.html" in os.listdir(individual_reports_path)
        #assert "ClassroomReport.html" in os.listdir(individual_reports_path)
        #assert "CommoncontrolsReport.html" in os.listdir(individual_reports_path)
        #assert "DriveReport.html" in os.listdir(individual_reports_path)
        #assert "GmailReport.html" in os.listdir(individual_reports_path)
        #assert "GroupsReport.html" in os.listdir(individual_reports_path)
        #assert "MeetReport.html" in os.listdir(individual_reports_path)
        #assert "RulesReport.html" in os.listdir(individual_reports_path)
        #assert "SitesReport.html" in os.listdir(individual_reports_path)







#def create_venv(env):
#    result = subprocess.run(["python", "-m", "venv", env])
#    if result.returncode == 0:
#        raise RuntimeError(f"Failed to create virtual environment, {result.stderr}")
#
#def activate_venv(env):
#    command = f"{env}\\Scripts\\activate"
#    result = subprocess.run(command)
#    if result.returncode == 0:
#        raise RuntimeError(f"Failed to activate virtual environment, {result.stderr}")
