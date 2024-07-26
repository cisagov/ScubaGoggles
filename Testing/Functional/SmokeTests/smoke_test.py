"""
smoke_test.py is a test script to verify `scubagoggles gws`
generates the correct outputs (i.e., directories, files).
"""

import pytest
import subprocess
import os

from smoke_test_utils import verify_all_outputs_exist, verify_output_type

class SmokeTest:
    def test_venv_creation(self):
        try:
            result = subprocess.run(["ls", ".venv"], shell=True, capture_output=True, text=True, check=True)
            if "Scripts" in result.stdout: 
                assert True
        except subprocess.CalledProcessError as e:
            pytest.fail(f"An error occurred, {e}")

    def test_scubagoggles(self, subjectemail):
        try:
            command = f"scubagoggles gws --subjectemail {subjectemail} --quiet"
            subprocess.run(command, shell=True)

            prefix = "GWSBaselineConformance"
            directories = [d for d in os.listdir() if os.path.isdir(d) and d.startswith(prefix)]
            directories.sort(key=lambda d: os.path.getctime(d), reverse=True)

            cwd = os.getcwd()
            output_path = os.path.join(cwd, directories[0])
            contents = verify_output_type(output_path, [])
            verify_all_outputs_exist(contents)
        except (OSError, ValueError, Exception) as e:
            pytest.fail(f"An error occurred, {e}")

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
