"""
run_rego.py takes the opa executable and runs the provider JSON against the rego files

This module will differentiate between windows and mac OPA executables when running.
"""
from sys import platform, stderr
import subprocess
import json
import logging

def opa_eval(
    product_name:str, input_file:str, opa_path:str, rego_path:str,
    omit_sudo:bool, debug:bool):
    """
    Runs the rego scripts and outputs a json to out_path

    :param product_name: which product to run
    :param input_file: which file to look at
    :param opa_path: path to opa
    :param rego_path: path to the rego file to run
    :param debug: to print debug statements or not
    """

    #print(opa_path)
    #print(type(opa_path))
    opa_exe = ""
    rego_file = product_name.capitalize()
    command = []
    windows_os = False

    if platform == 'win32':
        opa_exe = (opa_path / "./opa_windows_amd64.exe").resolve()
        windows_os = True
    elif platform == 'darwin':
        opa_exe = (opa_path / "./opa_darwin_amd64").resolve()
    elif platform in ('linux', 'linux2'):
        opa_exe = (opa_path / "./opa_linux_amd64_static").resolve()
    else:
        opa_exe = (opa_path / "./opa").resolve()
    #print(opa_exe)
    #print(type(opa_exe))

    if windows_os or omit_sudo:
        command.extend([f"{opa_exe}"])
    else:
        command.extend(["sudo", f"{opa_exe}"])

    rego_file = (rego_path / f"./{rego_file}.rego").resolve()
    utils_rego = (rego_path / "./Utils.rego").resolve()
    command.extend(
        ["eval",
        "-i", input_file,
        "-d", rego_file,
        "-d", utils_rego,
        f"data.{product_name}.tests",
        "-f", "values"
        ])
    try:
        output = subprocess.run(command, capture_output=True, check=True)
        if debug:
            logging.basicConfig(stream=stderr, level=logging.DEBUG)
            opa_err = "\n--- Rego debug output ---\n" + output.stderr.decode()
            logging.debug(opa_err)
        str_output = output.stdout.decode()
        ret_tests = json.loads(str_output)
        return ret_tests
    except subprocess.CalledProcessError as cpe:
        logging.error("\n--- OPA failed to execute from process error ---\n %s", cpe.output)
        return {"opa_error": "process_error"}
    except Exception as exc:
        logging.error("\n--- OPA failed to execute from unknown error ---\n %s",exc)
        return {"opa_error": "general_error"}
