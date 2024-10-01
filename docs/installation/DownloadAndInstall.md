# Download and Python Install
> [!NOTE]
> Previously installed a different version of ScubaGoggles? See [Upgrading ScubaGoggles](/docs/upgrading/Upgrading.md#upgrading-scubagoggles).

## Downloading the Latest Release
To download ScubaGoggles:

1. Click [here](https://github.com/cisagov/ScubaGoggles/releases) to see the latest release.
2. Click scubagoggles-[latest-version].zip to download the release.
3. Extract the folder in the zip file.

## Installing Python Dependencies
As of ScubaGoggles v0.3.0, the minimum required Python version to run the tool is `3.10.x`. While it's possible that ScubaGoggles may work with different versions of Python, 3.10 is the version we've tested and ensured works with the versions of the modules listed in ScubaGoggles' [dependencies](requirements.txt).

### Installing in a Virtual Environment
The following commands are used to set up a python virtual environment (venv) to install the needed python dependencies.
Inside the release or repo folder, open up a terminal and run the following commands based on your OS.

> [!NOTE]
> Depending on the Python installation and operating system, it might be necessary to use `pip3` and `python3` instead of `pip` and `python`.

#### Windows
```
pip install virtualenv
python -m venv .venv
.venv\Scripts\activate
```

#### macOS
```
pip install virtualenv
virtualenv -p python .venv
source .venv/bin/activate
```

Users can run the tool via the `scuba.py` script as a developer or by installing the `scubagoggles` package in a python venv.
Choose either of these next steps to install the needed python dependencies in the `venv`.

#### Installing dependencies for running scubagoggles directly
In the root directory of the release/repo, install the `scubagoggles` package and dependencies with the following command.
```
python -m pip install .
```

#### Installing dependencies for running via scuba.py script
In the root directory of the release/repo, install the the required dependencies with the following command.
```
pip install -r requirements.txt
```

> [!IMPORTANT]
> Users will need to rerun the `activate` script from the OS specific directions above in each new terminal session to reactivate the `venv` containing the dependencies.

## Navigation
- Continue to [Download the OPA executable](/docs/installation/OPA.md)
- Return to [Documentation Home](/README.md)
