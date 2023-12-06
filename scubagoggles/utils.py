"""
utils.py is for functions that could be used in more than one place

"""

from pathlib import Path

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
