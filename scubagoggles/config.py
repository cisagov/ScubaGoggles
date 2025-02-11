"""ScubaGoggles User Configuration - The UserConfig class implementation
manages the default values for the output location, the credentials file
location, and the OPA executable location.
"""

import os

from typing import Iterable, Union
from pathlib import Path

from yaml import dump, Dumper, load, Loader
import logging

class UserConfig:

    """Implementation of user configuration for ScubaGoggles.  Certain
    settings, specifically the directory for ScubaGoggles output,
    location of the Google API credentials file, and the location of
    the OPA executable, are managed by this class.
    """

    # FWIW, this was originally implemented using TOML (Tom's Obvious Minimal
    # Language) (hence the reference to "_doc"), but was converted to use YAML
    # for compatibilty with the other user configuration.  For ScubaGoggles,
    # the configuration file is stored at ~/.scubagoggles/userdefaults.yaml.

    _defaults = {'scubagoggles': {'opa_dir': '~/.scubagoggles',
                                    'output_dir': './'}}

    # This is the main key (TOML: table) in the configuration
    _main = _defaults['scubagoggles']

    _default_config_file = Path('~/.scubagoggles/userdefaults.yaml').expanduser()

    def __init__(self, config_file: Union[str, os.PathLike] = None):

        """UserConfig class initialization - this initializes the user
        configuration stored in the class.

        :param Path config_file: [optional] user configuration file.  By
            default, this is ~/.scubagoggles/userdefaults.yaml
        """

        self._config_file = (Path(os.path.expandvars(config_file))
                             if config_file else self._default_config_file)

        self._config_file = self._config_file.expanduser()

        self._check = True

        if self._config_file.exists() and self._config_file.is_file():
            with self._config_file.open(encoding = 'utf-8') as in_stream:
                self._doc = load(in_stream, Loader)
            self._validate()
            self._file_exists = True
        else:
            self._doc = dict(self._defaults)
            self._file_exists = False

    @property
    def file_exists(self) -> bool:

        """Returns True if the user's defaults file exists, False otherwise.
        This property is being used to determine if a user has used the setup
        utility.
        """

        return self._file_exists

    def _get_path_config(self, name: str) -> Union[Path, None]:

        """Returns a Path value corresponding to the given configuration
        variable name.

        :param str name: name of the configuration value.

        :return: configuration value as a Path.
        """

        # Return None if the variable wasn't defined in the user defaults
        # file
        value = (self._doc['scubagoggles'][name]
                 if name in self._doc['scubagoggles'] else None)

        if value:
            value = Path(os.path.expandvars(value)).expanduser()

        return value

    @property
    def credentials_file(self) -> Union[Path, None]:

        """Returns the Path to the Google API credentials file.
        """

        credentials = self._get_path_config('credentials')

        # If we're in check mode and the credentials path was defined in
        # user defaults file, raise an exception if the creds path doesn't
        # exist or isn't a file.
        if self._check and credentials and (not credentials.exists()
                                            or not credentials.is_file()):
            raise FileNotFoundError(f'? {credentials} - credentials not found')
        return credentials

    @credentials_file.setter
    def credentials_file(self, value: Union[str, os.PathLike]):

        """Sets the location of the Google API credentials file.

        :param value: location of the credentials file.
        """

        self._doc['scubagoggles']['credentials'] = str(value)

    @property
    def opa_dir(self) -> Union[Path, None]:

        """Returns the directory containing the OPA executable file.
        """

        directory = self._get_path_config('opa_dir')

        # If we're in check mode and the OPA path was defined in the user
        # defaults file, raise an exception if the OPA path doesn't exist,
        # or isn't a folder.
        if self._check and directory and not directory.exists():
            raise FileNotFoundError(f'? {directory} - OPA directory not found')
        if self._check and directory and not directory.is_dir():
            raise NotADirectoryError(f'? {directory} - is not a folder')
        return directory

    @opa_dir.setter
    def opa_dir(self, value: Union[str, os.PathLike]):

        """Sets the directory containing the OPA executable file.

        :param value: location of the OPA executable file.
        """

        self._doc['scubagoggles']['opa_dir'] = str(value)

    @property
    def output_dir(self) -> Union[Path, None]:

        """Returns the user's directory used for ScubaGoggles output.
        """

        directory = self._get_path_config('output_dir')

        # If we're in check mode and the output path was defined in the user
        # defaults file, raise an exception if it doesn't exist or isn't a
        # folder.
        if self._check and directory and not directory.exists():
            raise FileNotFoundError(f'? {directory} - directory not found')
        if self._check and directory and not directory.is_dir():
            raise NotADirectoryError(f'? {directory} - is not a folder')

        return self._get_path_config('output_dir')

    @output_dir.setter
    def output_dir(self, value: Union[str, os.PathLike]):

        """Sets the user's ScubaGoggles output directory.

        :param value: location of the output directory.
        """

        self._doc['scubagoggles']['output_dir'] = str(value)

    def path_check(self, check: bool) -> None:

        """Setter property that alters path checking behavior.

        :param bool check: check valid paths and raise exceptions
            if True.  Should only be False during initial configuration when
            directories/files may not yet exist.
        """

        self._check = check

    path_check = property(fset = path_check)

    def write(self):

        """Writes the configuration document in YAML format.
        """

        # Since the default location for the config is
        # ~/.scubagoggles/scubadefaults.yaml, the .scubagoggles
        # folder may need to be created first
        if not self._config_file.parent.exists():
            self._config_file.parent.mkdir()

        # ScubaGoggles v0.4 stored the config file in text file called
        # ~/.scubagoggles. ~/.scubagoggles is now expected to be a folder.
        # Users who have .scubagoggles as text file instead of a folder
        # will need to move that file first.
        if not self._config_file.parent.is_dir():
            raise NotADirectoryError(f"Cannot save user defaults to {self._config_file} "\
                f"because {self._config_file.parent} is not a directory. Please move "\
                    f"the existing {self._config_file.parent} file then try again.")

        with self._config_file.open('w', encoding = 'utf-8') as out_stream:
            dump(self._doc, out_stream, Dumper)

        self._file_exists = True

    def _validate(self, keys: Iterable = None) -> Union[list, None]:

        """Validates the current configuration by checking the dictionary
        keys to make sure they match the keys in the default configuration.
        This is a recursive method, initially called without arguments.

        :return: list of bad key names or None if configuration keys are
            correct.
        """

        bad_keys = []

        if not keys:
            for key in self._doc:
                bad_keys += self._validate((key,))
            if bad_keys:
                raise KeyError(f'? {", ".join(bad_keys)} key(s) not '
                               'recognized')
            return None

        current_defaults = self._defaults

        current_doc = self._doc

        for key in keys:
            current_defaults = current_defaults[key]
            current_doc = current_doc[key]

        if isinstance(current_doc, dict):
            for key in current_doc:
                bad_keys += self._validate([*keys, key])

        return bad_keys
