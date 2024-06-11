
### Install Python dependencies
Minimum required Python version to run the tool is `3.7.16`.

### Installing in a Virtual Environment
The following commands are used to set up a python virtual environment (venv) to install the needed python dependencies.
Inside the release or repo folder, open up a terminal and run the following commands based on your OS.

#### Windows
```
pip3 install virtualenv
python -m venv .venv
.venv\Scripts\activate
```

#### macOS
```
pip3 install virtualenv
virtualenv -p python3 .venv
source .venv/bin/activate
```

Users can run the tool via the `scuba.py` script as a developer or by installing the `scubagoggles` package in a python venv.
Choose either of these next steps to install the needed python dependencies in the `venv`.

#### Installing dependencies for running scubagoggles directly
In the root directory of the release/repo, install the `scubagoggles` package and dependencies with the following command.
```
python3 -m pip install .
```

#### Installing dependencies for running via scuba.py script
In the root directory of the release/repo, install the the required dependencies with the following command.
```
pip3 install -r requirements.txt
```

> [!IMPORTANT]
> Users will need to rerun the `activate` script from the OS specific directions above in each new terminal session to reactivate the `venv` containing the dependencies.

<!-- TODO segway into OPA>