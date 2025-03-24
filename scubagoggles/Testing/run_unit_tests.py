"""
run_unit_tests.py runs the rego unit tests

Currently runs non-verbosely
"""
import subprocess
import argparse

from pathlib import Path
from sys import platform

# pylint: skip-file

# The location of the RegoTests directory is where this script is located.
# The location of the Rego code is one level up.

test_dir = Path(__file__).parent
rego_dir = test_dir.parent / 'rego'

gws_baselines = [
    "gmail",
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

parser.add_argument('-o', '--opapath', type=str, default='../..', metavar='',
help='The relative path to the directory containing the OPA executable. ' +
    'Defaults to "../.." the current executing directory.')

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
            command = (f'{OPA_EXE} test {rego_dir} '
                       f'{test_dir}/RegoTests/{b}/{b}{c}_test.rego {V_FLAG}')
            print(command)
            subprocess.run(command.split(), check=False)
    else:
        print(f"\n==== Testing {b} ====")
        command = f'{OPA_EXE} test {rego_dir} {test_dir}/RegoTests/{b} {V_FLAG}'
        print(command)
        subprocess.run(command.split(), check=False)
