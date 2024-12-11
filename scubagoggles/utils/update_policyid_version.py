"""
Updates the Policy ID version of SCuBA security baselines
in both the markdown documents and the Rego.

Note: This script could be modified to take in
arguments for now just modify the constants below.
"""

import os
import re

CURRENT_VERSION = 'v0.1'
REPLACEMENT_VERSION ='v0.2'

PATH_TO_FILES = os.path.dirname(os.path.dirname(__file__))
FILES_TO_PROCESS = ['.md','rego','.csv']

def replace_last_n_chars(match):
    """
    Replace the current version number with the desired number
    """
    return match.group().replace(CURRENT_VERSION, REPLACEMENT_VERSION)

def replace_version_number(file_path):
    """
    Parses the file at file_path and
    replaces the SCuBA Policy ID version number
    """
    try:
        # Read the file line by line
        with open(file_path, 'r', encoding='UTF-8') as file:
            lines = file.readlines()

        # SCuBA Policy ID regex pattern
        pattern = r'[A-Za-z]+\.[A-Za-z]+\.\d+\.\d+v\d+\.*\d*'

        # Replace matching Policy ID version number
        modified_lines = [re.sub(pattern, replace_last_n_chars, line) for line in lines]

        # Write the modified content back to the file
        with open(file_path, 'w', encoding='UTF-8') as file:
            file.writelines(modified_lines)

        print(f"Updated file: {file_path}")

    except Exception as e:
        print(f"Error processing file {file_path}: {e}")

def process_files(directory_path):
    """
    Enumerates through the files/folders in the directory path
    and replaces the version number with the specified file
    extensions
    """

    exclude = set(['.github', '.venv', '.vscode', 'build', 'scubagoggles.egg-info'])
    # pylint: disable=unused-variable
    for root, dirs, files in os.walk(directory_path):
        dirs[:] = [d for d in dirs if d not in exclude]
        for file in files:
            if any(file.lower().endswith(ext) for ext in FILES_TO_PROCESS):
                file_path = os.path.join(root, file)
                replace_version_number(file_path)

# Process the directory
process_files(PATH_TO_FILES)
