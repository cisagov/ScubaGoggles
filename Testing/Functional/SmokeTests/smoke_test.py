"""
run_smoke_test.py is a test script to verify `scubagoggles gws`
outputs (i.e., files) are generated.
"""

import pytest
import subprocess
import os

from smoke_test_utils import verify_all_outputs_exist, verify_output_type

"""
    Test virtualenv setup, activation

    Test installing dependencies for running scuba.py script 

    Test installing dependencies for running scubagoggles directly 

"""    

class SmokeTest:
    def test_venv_creation(self):
        result = subprocess.run(["dir", ".venv"], shell=True, capture_output=True, text=True)
        if "Scripts" in result.stdout: 
            assert True
        else: 
            assert False, f"Scripts was not found in the virtual environment"

    def test_scubagoggles(self, subjectemail):
        command = f"scubagoggles gws --subjectemail {subjectemail} --quiet"
        subprocess.run(command)
        
        prefix = "GWSBaselineConformance"
        directories = [d for d in os.listdir() if os.path.isdir(d) and d.startswith(prefix)]
        directories.sort(key=lambda d: os.path.getctime(d), reverse=True)

        cwd = os.getcwd()
        output_path = os.path.join(cwd, directories[0])
        contents = verify_output_type(output_path, [])
        verify_all_outputs_exist(contents)







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
