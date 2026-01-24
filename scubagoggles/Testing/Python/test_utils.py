import pytest
from pathlib import Path
import os
from scubagoggles import utils
from importlib.metadata import version, PackageNotFoundError

class TestUtils:
    @pytest.mark.parametrize(
        "dictionary, keys, expected",
        [
            ({1:['a','b','c'], 2:['a','d'], 3:['b','c','d']}, 
             [1], {'a':[1], 'b':[1], 'c':[1]}),
            ({1:['a','b'], 2:['a','c','d'], 3:['b','e'], 4:['a','e']}, 
             [1,3,4], {'a':[1, 4], 'b':[1, 3], 'e':[3, 4]}),
            ({1:['a','b'], 2:['a','c','d'], 3:['b','e'], 4:['a','e']}, 
             [], {}),
            ({1:['a','b','c'],2:['d','e']}, 
             [], {}),
            ({1:['a','b','c'],2:[],3:['a','b','c','d'],4:['a','e']}, 
             [1,2], {'a':[1], 'b':[1], 'c':[1]}),
            ({1:['a','b','c'],2:[],3:['a','b','c','d'],4:['a','e']}, 
             [1,2,3], {'a':[1,3], 'b':[1,3], 'c':[1,3], 'd':[3]}),
            ({1:[],2:[],3:[],4:[]}, 
             [1,3], {})
        ],
    )
    def test_create_subset_inverted_dict(self, dictionary, keys, expected):
        assert utils.create_subset_inverted_dict(dictionary, keys) == expected


    @pytest.mark.parametrize(
        "keys, expected",
        [
            ([1,2,3],{1:[], 2:[], 3:[]}),
            ([1,2],{1:[], 2:[]}),
            ([1],{1:[]}),
            ([],{})
        ],
    )
    def test_create_key_to_list(self,keys,expected):
        assert utils.create_key_to_list(keys) == expected


    @pytest.mark.parametrize(
        "dict1, dict2, expected",
        [
            ({'a':[1], 'b':[2]}, 
             {'b':[3], 'c':[1]}, 
             {'a':[1], 'b':[2,3], 'c':[1]}),
            ({'a':[1], 'b':[2]}, 
             {'b':[2], 'c':[1]}, 
             {'a':[1], 'b':[2,2], 'c':[1]}),
            ({'a':[1], 'b':[2], 'c':[3]},
             {'a':[2], 'b':[2], 'd':[1,2,3]},
             {'a':[1,2], 'b':[2,2], 'c':[3], 'd':[1,2,3]}),
            ({'a':[], 'b':[1,2], 'c':[1]},
             {'b':[3], 'c':[]},
             {'a':[], 'b':[1,2,3], 'c':[1]}),
            ({'a':[], 'b':[1,2], 'c':[1]},
             {'a':[], 'b':[3], 'c':[], 'd':[]},
             {'a':[], 'b':[1,2,3], 'c':[1], 'd':[]})
        ]
    )
    def test_merge_dicts(self, dict1, dict2, expected):
        assert utils.merge_dicts(dict1, dict2) == expected


    @pytest.mark.parametrize(
        "base_filename, rel_segments",
        [
            ("plain_file.txt",
            ["Testing", "Python", "testing_directory", "plain_file.txt"]),
            ("non_existent_file.txt",
            ["Testing", "Python", "testing_directory", "plain_file.txt"]),
            ("requirements.txt",
            ["requirements.txt"]),
            ("plain_file_2.txt",
            ["Testing", "Python", "testing_directory", "secondary_directory", "plain_file_2.txt"]),
        ]
    )
    def test_rel_abs_path(self, base_filename, rel_segments):
        # build relative path
        rel_path = os.path.join(*rel_segments)
        cwd_path = Path.cwd()
        full_path = cwd_path / rel_path
        # assert expected result
        assert utils.rel_abs_path(base_filename, rel_path) == full_path


    @pytest.mark.parametrize(
        "package, included",
        [
            ("pyyaml", True),
            ("requests", True),
            ("tqdm", True),
            ("polars", False)
        ]
    )
    def test_get_package_version(self, package, included):
        if included:
            v = version(package)
            assert v == utils.get_package_version(package)
        else:
            with pytest.raises(PackageNotFoundError):
                utils.get_package_version(package)


    @pytest.mark.parametrize(
        "path",
        [
            "requirements.txt",
            "Testing/Python/testing_directory",
            "Testing/Python/testing_directory/plainfile.txt",
            ".",            # special case: use an absolute path
            "~",
            "$CWD/subdir",
            "$HOME/tmp",
        ]
    )
    def test_path_parser(self, path):
        home_dir = Path.home()
        os.environ["HOME"] = str(home_dir)
        os.environ["CWD"] = str(home_dir)
        expanded = os.path.expandvars(path)
        expanded = os.path.expanduser(expanded)
        abs_path = Path(os.path.abspath(expanded))
        assert abs_path == utils.path_parser(path)

    @pytest.mark.parametrize(
        "prompt,user_input,default,expected",
        [
            ("Do you wish to continue?", "y", True, True),
            ("Do you wish to continue?", "n", True, False),
            ("Do you wish to continue?", "false", False, False),
            ("Do you wish to continue?", "", True, True),   # default used
            ("Do you wish to continue?", "", False, False) # default used
        ],
    )
    def test_prompt_boolean(self, monkeypatch, prompt, user_input, default, expected):  # pylint: disable=too-many-positional-arguments
        monkeypatch.setattr("builtins.input", lambda _: user_input)
        assert utils.prompt_boolean(prompt, default=default) == expected

    @pytest.mark.parametrize(
        "strval, expected, included",
        [
            ("y", True, True),
            ("1", True, True),
            ("TRUE", True, True),
            ("no", False, True),
            ("off", False, True),
            ("red", None, False)
        ]
    )
    def test_strtobool(self, strval, expected, included):
        if included:
            assert utils.strtobool(strval) == expected
        else:
            with pytest.raises(ValueError):
                utils.strtobool(strval)
