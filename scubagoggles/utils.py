"""
utils.py is for functions that could be used in more than one place

"""
import os

from pathlib import Path
from importlib.metadata import version, PackageNotFoundError


def create_subset_inverted_dict(dictionary: dict, keys: list) -> dict:
    """
    Creates a subset of a dictionary of lists with the list of keys specified.
    Then inverts keys and values of the dictionary.

    :param dictionary: a dictionary of lists
    :param keys: a list of strings of the keys we want to pull from the dictionary
    with the keys and values inverted
    """
    subset_dict = {key: dictionary[key] for key in keys if key in dictionary}
    inverted_dict = {}
    for key, values in subset_dict.items():
        for value in values:
            inverted_dict.setdefault(value, []).append(key)
    return inverted_dict


def create_key_to_list(keys: list) -> dict:
    """
    Creates a dictionary of keys -> to empty lists

    :param keys: a string list of keys we want to create a dictionary of empty lists from
    """
    dictionary = {}
    for key in keys:
        dictionary[key] = []
    return dictionary


def merge_dicts(dict1: dict, dict2: dict) -> dict:
    """
    Combines two dictionaries of lists that may or may not have the same keys

    :param dict1: the first dict of lists we want to merge
    :param dict2: the second dict of lists we want to me
    """
    for key, values in dict2.items():
        dict1.setdefault(key, []).extend(values)
    return dict1


def rel_abs_path(file_path: str, rel_path) -> str:
    """
    Gets the absolute path combination of the current directory
    where file is located and the path relative to the file

    :param file_path: the path of the current file: usually __file__
    :param rel_path: the relative path for the current directory
    """
    current_dir = Path(file_path).resolve().parent
    return (current_dir / rel_path).resolve()


def get_package_version(package: str) -> str:
    """
    Get the current version for a package
    """
    try:
        package_version = version(package)
        return package_version
    except PackageNotFoundError as e:
        raise PackageNotFoundError("Package was not found") from e


def path_parser(value) -> Path:

    """Given a string value, this function returns an absolute Path.  The
    value may contain a leading "~" to indicate the user's home directory,
    and may use environment variables (e.g., $HOME).

    :param str value: directory or file specification

    :return: absolute Path
    """

    path_value = Path(os.path.expandvars(value)).expanduser().absolute()

    return path_value


def prompt_boolean(prompt: str, default: bool = True) -> bool:

    """Asks the user for a Yes/No answer to a given prompt.

    :param str prompt: the question/confirmation to ask the user.

    :param bool default: [optional] the default response if the user presses
        "enter" ("return").  It defaults to Yes (True).

    :return: True if user responds Yes; False otherwise.
    """

    suffix = '[Yes/no]? ' if default else '[yes/No]? '

    # This handles when the user enters EOF (which is ^Z in Windows or ^D
    # in other OS environments).  It's assumed that this response is
    # equivalent to ^C (user abort).

    try:
        answer = input(f'{prompt} {suffix}').strip()

    except EOFError as e:
        raise KeyboardInterrupt() from e

    return (not answer and default) or (answer and strtobool(answer))


def strtobool(value: str) -> bool:

    """Convert a string representation of truth to a boolean (True/False).

    True values are 'y', 'yes', 't', 'true', 'on', and '1'; false values
    are 'n', 'no', 'f', 'false', 'off', and '0'.  Raises ValueError if
    'value' is anything else.

    :param str value: string representing a boolean value.

    :return: True if string indicates "true"; False if string indicates
        "false".
    """

    value = value.strip().lower()

    if value in {'y', 'yes', 't', 'true', 'on', '1'}:
        return True
    if value in {'n', 'no', 'f', 'false', 'off', '0'}:
        return False

    raise ValueError(f'strtobool("{value}"): invalid truth value')
