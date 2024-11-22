# Getting started

> [!IMPORTANT]
> Use of this tool requires access to an internet browser for initial setup and to view the html report output.

Setting up to run ScubaGoggles for the first time involves the following steps:

1. Install [Python 3](https://www.python.org/) on your system.
2. (Optional) Create and activate a Python virtual environment.
3. Install ScubaGoggles and dependencies into the Python environment.
4. Run ScubaGoggles setup to specify the output directory, the location of the
   OPA executable, and the credentials file.
5. Download the Open Policy Agent (OPA) executable.
6. Create a Google OAuth credential file, unless you'll be using a Google
   service account.

## Install Python 3
Running ScubaGoggles requires Python 3.9 or higher.  If Python is not installed
in your environment, please visit the [Python website](https://www.python.org/)
for instructions on how to download and install Python.

Depending on the operating system, the command to invoke Python from the command
line is either `python` (Windows) or `python3` (linux & macOS, for backward
compatibilty with Python version 2).  You will need access to a command line,
via the command window or a PowerShell window for Windows, or a terminal window
in linux & macOS.

## Installing in a Python Virtual Environment

A Python virtual environment dedicated to ScubaGoggles isn't strictly
necessary, but it is recommended because it will allow you to isolate
ScubaGoggles and its dependencies from other Python tools you may have running
on your system.  With a virtual environment, you create it only once, but you
will need to "activate" it in a new window (i.e., process) prior to running
ScubaGoggles.  A virtual environment remains activated until the window is
closed (unless you explicitly deactivate the virtual environment).

The following commands are used to set up a python virtual environment using
the `venv` Python module.  Create a window where you may enter commands on your
system.

Use the `cd` (change directory) command to set the current working directory to
the location where you want to create the virtual environment directory.  In
this example, the directory that will be created is called `scuba-env`, but
you may use a different name.

The following examples show both the command to create the virtual environment,
followed by the command that activates the virtual environment in your current
session.  The commands differ slightly depending on the operating system and
type of command window.

**Note** the command that activates the virtual environment.  You will need this
command whenever you create a new session (i.e., terminal) where you will be
running ScubaGoggles.

### Windows

#### Windows Command

```
python -m venv scuba-env
scuba-env\Scripts\activate.bat
```

#### Windows PowerShell
```
python -m venv scuba-env
scuba-env\Scripts\activate.ps1
```

#### Windows Git Bash
```
python -m venv scuba-env
source scuba-env/Scripts/activate
```

### linux and macOS
```
python3 -m venv scuba-env
source scuba-env/bin/activate
```

## Downloading the Latest ScubaGoggles Release
To download ScubaGoggles, click [here](https://github.com/cisagov/ScubaGoggles/releases)
to display the download site in a browser.  For installing ScubaGoggles as a
user (and not a developer), you should download the file with the name ending
in `.whl` (known as a Python "wheel" file), for example
`scubagoggles-1.0.0-py3-none-any.whl`.

If you are a developer, you may alternatively download the "gzipped tar" file
(file ending with `.tar.gz`), or zip file (file ending with `.zip`).  You may
also clone the GitHub repository.  The instructions that follow focus on the
installation for the general user.

### Installing ScubaGoggles
ScubaGoggles is installed as a Python package, whether you are using a virtual
environment or the system's Python environment (if you have write access to it).

Install ScubaGoggles using Python's `pip` utility.  If you are using a virtual
environment, make sure your current session has activated the virtual
environment.  Normally, the command you use is `pip` or `pip3`.

```
pip install scubagoggles-1.0.0-py3-none-any.whl
```
where you will replace `scubagoggles-1.0.0-py3-none-any.whl` in the above
command with the location and/or name of the ScubaGoggles wheel file you
downloaded.

This command will install ScubaGoggles and all its dependencies.  The system on
which ScubaGoggles is installed must be able to access the internet so the
dependencies may be downloaded.

## Creating the ScubaGoggles Output Directory
ScubaGoggles produces "Secure Baseline Conformance Reports", which are written
to a directory on your system.  In addition, ScubaGoggles requires the OPA
executable and the Google credentials file.  It is recommended that you create
a directory that will contain these required files and serve as a location
for the reports.  You will run the ScubaGoggles setup utility to indicate the
location of the output directory.

## ScubaGoggles Setup Utility
The ScubaGoggles setup utility lets you configure the data directory location,
as well as the locations of the OPA executable and the Google credentials file.
It is perfectly fine to locate the OPA executable and credentials files in the
output directory you create.

When you run the setup utility, it will create a configuration file in your
top-level user directory called `.scubagoggles` (**Note** the leading dot (.)
in the file name, which indicates a "hidden" file on linux and macOS operating
systems).

The configuration file contains the following values used by ScubaGoggles when
running the conformance assessments:

| Name        | Description                                       |
|-------------|---------------------------------------------------|
| credentials | Location and name of the Google credentials file. |
| opa_dir     | Location of the OPA executable.                   |
| output_dir  | Location of the ScubaGoggles output directory.    |

Run the setup utility with this command:

```shell
scubagoggles setup
```

You will be prompted to enter the output directory, location of the OPA
executable, and the location and name of the Google credentials file.  You
do not have to download the OPA executable, and you do not have to create the
Google credentials file before running setup.  If either do not exist, you
will see a warning indicating one or both is missing.  You will need to have
both the OPA executable and credentials files before running the conformance
assessment.

These are sample outputs from running the setup utility before the required files
are available.  Warnings are shown, but the `.scubagoggles` configuration file
is still created.

### Windows Example

```lang-none
> scubagoggles setup
Setup: output directory
Scubagoggles output directory [C:\Users\userID\scubagoggles]?
Create directory C:\Users\userID\scubagoggles [Yes/no]?
  C:\Users\userID\scubagoggles
Setup: OPA executable directory
(WARNING): OPA executable not found in PATH
Location of OPA executable [C:\Users\userID\scubagoggles]?
(WARNING): OPA executable not found in C:\Users\userID\scubagoggles
Setup: Google API credentials file
Google credentials (JSON) file [C:\Users\userID\scubagoggles\credentials.json]?
(WARNING): Google credentials file not found in C:\Users\userID\scubagoggles\credentials.json
```

### Linux Example

```lang-none
$ scubagoggles setup
Setup: output directory
Scubagoggles output directory [/home/userID/scubagoggles]?
  /home/userID/scubagoggles
Setup: OPA executable directory
(WARNING): OPA executable not found in PATH
Location of OPA executable [/home/userID/scubagoggles]?
(WARNING): OPA executable not found in /home/userID/scubagoggles
Setup: Google API credentials file
Google credentials (JSON) file [/home/userID/scubagoggles/credentials.json]?
(WARNING): Google credentials file not found in /home/userID/scubagoggles/credentials.json
```

## Navigation
- Continue to [Download the OPA executable](OPA.md)
- Return to [Documentation Home](/README.md)
