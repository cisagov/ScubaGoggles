"""
smoke_test.py is a test script to verify `scubagoggles gws`
generates the correct outputs (i.e., directories, files).
"""

import pytest
import subprocess
import os

from smoke_test_utils import verify_all_outputs_exist, verify_output_type

class SmokeTest:
    def test_scubagoggles_output(self, subjectemail):
        try:
            command: str = f"scubagoggles gws --subjectemail {subjectemail} --quiet"
            subprocess.run(command, shell=True)

            prefix: str = "GWSBaselineConformance"
            directories: list[str] = [d for d in os.listdir() if os.path.isdir(d) and d.startswith(prefix)]
            directories.sort(key=lambda d: os.path.getctime(d), reverse=True)

            # Access the latest output directory at the 0th index after sorting
            cwd: str = os.getcwd()
            output_path: str = os.path.join(cwd, directories[0])
            contents: list[str] = verify_output_type(output_path, [])
            verify_all_outputs_exist(contents)
        except (OSError, ValueError, Exception) as e:
            pytest.fail(f"An error occurred, {e}")
