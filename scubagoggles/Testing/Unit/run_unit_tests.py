"""
run_unit_tests.py runs the rego unit tests

Currently runs non-verbosely
"""
import os
import subprocess
import argparse

from scubagoggles.config import UserConfig

from pathlib import Path
from sys import platform

# pylint: skip-file

# The location of the Rego directory is where this script is located.
# The location of the Rego code is one level up.

test_dir = Path(__file__).parent
rego_dir = test_dir.parent.parent / 'rego'

gws_baselines = [
    "gmail",
    "gemini",
    "assuredcontrols",
    "calendar",
    "groups",
    "chat",
    "drive",
    "meet",
    "sites",
    "commoncontrols",
    'classroom'
]

EXAMPLE_TEXT = '''example:

 python RunUnitTests.py
 python RunUnitTests.py -b gmail calendar
 python RunUnitTests.py -b gmail -c 1 2
 python RunUnitTests.py -b gmail -c 1 2 -v'''

# parser arguments
parser = argparse.ArgumentParser(epilog=EXAMPLE_TEXT,
formatter_class=argparse.RawDescriptionHelpFormatter)

parser.add_argument('-b', '--baselines', type = str, nargs="+",
default=gws_baselines, help="Space-separated list of baselines to test. By default all are run.")

parser.add_argument('-c', '--controls', type = str, nargs="+",
default=[], help="Space-separated list of control group numbers to test within a specific baseline."
"Can only be used when a single baseline is specified. By default all are run.")

# obtain the default OPA executable location from UserSetup()
opa_dir = UserConfig().opa_dir or "../../.." 
parser.add_argument('-o', '--opapath', type=str, default=opa_dir, metavar='',
help='The relative path to the directory containing the OPA executable. ' +
    'Defaults to the default location of the opa executable from UserConfig.')

parser.add_argument('-v', action='store_true',
help='Verbose flag, passed to opa, increases output.')
args = parser.parse_args()


if len(args.baselines) > 1 and len(args.controls) > 0:
    print('WARNING: "--controls" specified, '
    'but multiple products are being tested. Ignoring "--controls" option.')
    args.controls = []

# These aren't constants but the linter is complaining
V_FLAG = ""
if args.v:
    V_FLAG = "-v"

#Get OPA Path from command line args
opa_path = args.opapath
OPA_EXE = ""
command = []
if platform == 'win32':
    OPA_EXE = f'{opa_path}/opa_windows_amd64.exe'
elif platform == 'darwin':
    OPA_EXE = f'{opa_path}/opa_darwin_amd64'
elif platform in ('linux', 'linux2'):
    OPA_EXE = f'{opa_path}opa_linux_amd64_static'

if not OPA_EXE or not Path(OPA_EXE).exists():
    OPA_EXE = f'{opa_path}/opa'

if not Path(OPA_EXE).exists():
    raise FileNotFoundError(f'? {OPA_EXE}: OPA executable not found')

for b in args.baselines:
    b = b.lower()
    if len(args.controls) > 0:
        for c in args.controls:
            print(f"\n==== Testing {b} control {c} ====")
            c = c.zfill(2)
            command = f'{OPA_EXE}\" test\" {rego_dir}\"'
            command += f'{test_dir}/Rego/{b}/{b}{c}_test.rego'
            # only append if V_FLAG is set
            if V_FLAG:
                command += f'\"{V_FLAG}'
            command_list = [s.strip() for s in command.split("\"")]
            
            # for the sake of displaying the command
            command_display = ""
            for c in command_list: command_display += f'\"{c}\" '
            print(command_display)

            subprocess.run(command_list, check=False)
    else:
        print(f"\n==== Testing {b} ====")
        command = f'{OPA_EXE}\" test\" {rego_dir}\" {test_dir}/Rego/{b}'
        # only append if V_FLAG is set
        if V_FLAG:
            command += f'\"{V_FLAG}'
        command_list = [s.strip() for s in command.split("\"")]

        # for the sake of displaying the command
        command_display = ""
        for c in command_list: command_display += f'\"{c}\" '
        print(command_display)

        subprocess.run(command_list, check=False)
