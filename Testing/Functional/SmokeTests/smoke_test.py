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

        def check_output_contents(output_path):
            try:
                entries = os.listdir(output_path)
                print(entries)
                for entry in entries:
                    child_path = os.path.join(output_path, entry)

                    # Directory case
                    if os.path.isdir(child_path):
                        assert os.path.isdir(child_path)
                        check_output_contents(child_path)
                    
                    # File case
                    elif os.path.isfile(child_path):
                        assert os.path.isfile(child_path)
                    
                    # Neither a directory or file (symlink, etc.)
                    else:
                        assert False
            except FileNotFoundError:
                assert False, f"The directory {output_path} does not exist"
            except Exception as e:
                assert False, f"An error occurred, {e}"
        
        check_output_contents(output_path)

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
