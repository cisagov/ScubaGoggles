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
        print(directories)
        print(directories[0])


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
