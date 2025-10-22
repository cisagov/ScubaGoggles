# Getting started

> [!IMPORTANT]
> Use of this tool requires access to an internet browser for initial setup
> and to view the html report output.

Setting up to run ScubaGoggles as a user for the first time involves the following steps:
1. Installing [Python 3](https://www.python.org/) on your system.
2. (Optional) Creating and activating a Python virtual environment.
3. Downloading the latest release.
4. Installing ScubaGoggles and dependencies into the Python environment.
5. Running `scubagoggles setup` to specify the output directory, the location of the
   OPA executable, and the credentials file.  By default, the setup will
   download the Open Policy Agent (OPA) executable for you.
6. Creating a Google OAuth credential file, unless you'll be using a Google
   service account.

Each of the above steps is detailed in the following sections.

## Installing Python 3

Running ScubaGoggles requires Python 3.9 or higher.  If Python is not installed
in your environment, please visit the [Python website](https://www.python.org/)
for instructions on how to download and install Python.

A 64-bit operating system is required.  While Python will run in a 32-bit
environment, the Open Policy Agent (OPA) required for ScubaGoggles is only
available on 64-bit platforms.

Depending on the operating system, the command to invoke Python from the command
line is either `python` (Windows) or `python3` (linux & macOS, for backward
compatibilty with Python version 2).  You will need access to a command line,
via the command window or a PowerShell window for Windows, or a terminal window
in linux & macOS.

## Creating and Activating a Python Virtual Environment

A Python virtual environment dedicated to ScubaGoggles isn't strictly
necessary, but it is recommended because it will allow you to isolate
ScubaGoggles and its dependencies from other Python tools you may have running
on your system.  With a virtual environment, you create it only once, but you
will need to "activate" it in a new window (i.e., process) prior to running
ScubaGoggles.  A virtual environment remains activated until the window is
closed (unless you explicitly deactivate the virtual environment).

The following steps are used to set up a python virtual environment using
the `venv` Python module.

1. Open a window where you may enter commands on your system (e.g., PowerShell or bash)
2. Use the `cd` (change directory) command to navigate to the location where you want
   to create the virtual environment directory.
3. Create the virtual environment using the appropriate command from the following table.
   In this example, the directory that will be
   created is called `scuba-env`, but you may use a different name.


| OS              | Command                     |
| ----------------- | ----------------------------- |
| Windows         | `python -m venv scuba-env`  |
| Linux and macOS | `python3 -m venv scuba-env` |

4. Activate the virtual environment using the appropriate command from the following table:


| Environment                             | Command                             |
| ----------------------------------------- | ------------------------------------- |
| Windows (Command prompt and PowerShell) | `scuba-env\Scripts\activate`        |
| Windows (Git Bash)                      | `source scuba-env/Scripts/activate` |
| Linux and macOS                         | `source scuba-env/bin/activate`     |

Make note of the command used to activate the virtual environment.  You will need this
command whenever you create a new session (i.e., terminal) where you will be
running ScubaGoggles.

## Installing the Latest ScubaGoggles Release
> [!NOTE]
> If you are interested in contributing to ScubaGoggles or for any reason need to install the latest development code, please see the [Development Guide](../development/DEVELOPMENTGUIDE.md) for instructions on setting up ScubaGoggles for development. Otherwise, continue with the instructions below.
>`pip` is not installed by default on LinuxOS. If pip is not installed in your environment, please visit [PiP website](https://pip.pypa.io/en/stable/installation/) for instructions on how to download and install pip.

To install ScubaGoggles:
1. If you are using a virtual environment, ensure your environment is activated by running the appropriate command from the previous section.
2. Next, run the following command. Depending on your system, you may also need to substitute `pip` with `pip3`.
```
pip install scubagoggles
```

At this point, ScubaGoggles will be installed, but additional setup
steps are necessary before it can be used. Continue to [Download the OPA executable](OPA.md)
for the next steps.

## Navigation

- Continue to [Download the OPA executable](OPA.md)
- Return to [Documentation Home](/README.md)
