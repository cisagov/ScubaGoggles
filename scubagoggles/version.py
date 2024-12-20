"""Module that handles the ScubaGoggles version number.
"""

import argparse
import csv
import logging
import re

from pathlib import Path

from scubagoggles import __version__

log = logging.getLogger(__name__)


class Version:

    """ScubaGoggles version number implementation.

    The OFFICIAL version number for ScubaGoggles is defined in the package's
    __init__.py file.  All references to the ScubaGoggles version number are
    derived from this value.

    Instantiation of this class is not necessary, as all methods are either
    class and/or static methods.
    """

    # See the comments in the initialize() method for the content of the
    # following class variables.

    current = None

    name = 'ScubaGoggles'

    number = None

    with_name = None

    major, minor, build = (None, None, None)

    suffix = None

    _code_root = Path(__file__).parent

    # The following regular expression is used to locate the policy ID (with
    # version suffix) within a string.  It separates the policy ID from the
    # suffix, so it can be replaced when the version number is updated.

    _version_regex = r'(?P<policy_id>GWS\.\w+\.\d+\.\d+)(?P<sfx>v\d+\.\d+)'

    version_re = re.compile(_version_regex, re.IGNORECASE)

    @classmethod
    def initialize(cls, version = __version__):

        """Initialize class variables containing version number information.

        This method is called during the one-time initialization of this
        module (when it is first imported).  This is also used when the
        version number changes.

        :param str version: [optional] Version number string in
            '<major>.<minor>.<build>' format.  By default, the current version
            number is used.  A different version is specified only when
            updating the version number.
        """

        # The following attributes are meant for public access.
        # 'current' is the version number with 'v' as a prefix (e.g., 'v1.0.0').
        # 'number' is the version number without the 'v' (e.g., '1.0.0').
        # 'with_name' contains the tool name, ScubaGoggles, with the version.
        # 'major', 'minor', and 'build' are the separate integer components of
        # the version number.

        cls.current = f'v{version}'

        cls.number = version

        cls.with_name = f'{cls.name} {cls.current}'

        cls.major, cls.minor, cls.build = [int(v) for v in version.split('.')]

        # This is the version suffix used at the end of policy IDs
        # (e.g., 'GWS.CHAT.1.0.v1.0', where 'v1.0' is the version suffix).

        cls.suffix = f'v{cls.major}.{cls.minor}'

    @classmethod
    def command_dispatch(cls, arguments: argparse.Namespace):

        """Dispatch method for the ScubaGoggles 'version' subcommand.  With
        no options, this displays the current version number to the user.

        For developers, the 'check' option validates that the version numbering
        is consistent throughout the code base.  The 'upgrade' option will
        modify all files to replace the version number with the one provided
        on the command line.

        See the comments for this class regarding the ScubaGoggles version
        number.

        :param arguments: arguments collected by the ArgumentParser.
        """

        if arguments.check:
            print('ScubaGoggles version check')
            cls.check_versions()
        elif arguments.upgrade:
            print(f'ScubaGoggles version upgrade ({arguments.upgrade})')
            cls.set(arguments.upgrade)
        else:
            print(cls.with_name)

    @classmethod
    def check_versions(cls, update: bool = False) -> bool:

        """Checks the versions throughout the ScubaGoggles files to ensure
        that all version number occurrences are consistent with the current
        official version number.

        :param bool update: update the versions in all files in the code base
            if True; otherwise, check the versions all files to make sure
            they match the current version (default).
        :return: True if at least 1 file was modified (update is True) or a
            version inconsistency was found.
        """

        # The meaning of 'modified' is dependent on the value of 'update'.
        # For update True, it'll mean at least 1 file was modified; for
        # False, it means a version inconsistency was found.

        modified = cls.check_or_update_readme(update)

        for md_file in cls._code_root.glob('**/*.md'):
            modified |= cls.check_or_update_md(md_file, update)

        # The drift rules CSV files are not part of the code content, and
        # exist in the directory above the code root.

        drift_rules_dir = cls._code_root.parent / 'drift-rules'

        if not drift_rules_dir.is_dir():
            raise NotADirectoryError(f'{drift_rules_dir} - drift rules '
                                     'directory missing')

        for csv_file in drift_rules_dir.glob('*.csv'):
            modified |= cls.check_or_update_csv(csv_file, update)

        return modified

    @classmethod
    def check_or_update_csv(cls, drift_csv: Path, update: bool = False) -> bool:

        """Validates the ScubaGoggles version number embedded in the given
        drift monitoring rules CSV file.

        :param Path drift_csv: file specification for a drift CSV file.
        :param bool update: update the versions in the file if True; otherwise,
            check the versions in the file to make sure they match the current
            version (default).
        :return:  True if file was modified (update) or version(s) in the
            file do NOT match the current version; False if the file is
            consistent with the current version.
        """

        log.debug(str(drift_csv))

        with drift_csv.open(encoding = 'utf-8') as csvfile:

            reader = csv.DictReader(csvfile)

            field_names = reader.fieldnames

            contents = list(reader)

        logger = log.debug if update else log.error

        modified = False

        for index, row in enumerate(contents):
            policy_id = cls.version_re.sub(f'\\g<policy_id>{cls.suffix}',
                                           row['PolicyId'])

            if policy_id != row['PolicyId']:
                if update:
                    row['PolicyId'] = policy_id

                if not modified:
                    logger('%s:', str(drift_csv))
                    modified = True

                logger('  %3d) {"PolicyId": %s}', index + 2, row['PolicyId'])

        if modified and update:
            with drift_csv.open(mode = 'w', encoding = 'utf-8') as csvfile:
                writer = csv.DictWriter(csvfile,
                                        field_names,
                                        lineterminator = '\n')
                writer.writeheader()
                for row in contents:
                    writer.writerow(row)

        return modified

    @classmethod
    def check_or_update_md(cls, md_file: Path, update: bool = False) -> bool:

        """Validates the ScubaGoggles version number embedded in the given
        Markdown file.

        :param Path md_file: file specification for a Markdown file.
        :param bool update: update the versions in the file if True; otherwise,
            check the versions in the file to make sure they match the current
            version (default).
        :return:  True if file was modified (update) or version(s) in the
            file do NOT match the current version; False if the file is
            consistent with the current version.
        """

        log.debug(str(md_file))

        contents = md_file.read_text(encoding = 'utf-8').splitlines()

        logger = log.debug if update else log.error

        modified = False

        for index, line in enumerate(contents):
            new_line = cls.version_re.sub(f'\\g<policy_id>{cls.suffix}', line)

            if line != new_line:
                if update:
                    contents[index] = new_line

                if not modified:
                    logger('%s:', str(md_file))
                    modified = True

                logger('  %3d) %s',
                       index + 1,
                       (new_line if update else line).strip())

        if modified and update:
            md_file.write_text('\n'.join(contents) + '\n', encoding = 'utf-8')

        return modified

    @classmethod
    def check_or_update_readme(cls, update: bool = False) -> bool:

        """Validates the ScubaGoggles version number embedded in the top-level
        README Markdown file.  There are a couple version number references
        in URLs located in the file.

        :param bool update: update the versions in the file if True; otherwise,
            check the versions in the file to make sure they match the current
            version (default).
        :return:  True if file was modified (update) or version(s) in the
            file do NOT match the current version; False if the file is
            consistent with the current version.
        """

        readme_file = cls._code_root.parent / 'README.md'

        if not readme_file.exists():
            return False

        log.debug(str(readme_file))

        contents = readme_file.read_text(encoding = 'utf-8').splitlines()

        logger = log.debug if update else log.error

        modified = False

        # The top-level README file has two places where the version is
        # hardcoded.  Both references are embedded in a URL.

        tool_regex = f'(?P<prefix>{cls.name}-)' + r'v\d+(?:\.\d+){2}'
        tool_version_re = re.compile(tool_regex)

        scb_re = re.compile(r'(?P<prefix>GWS_SCB-)v\d+\.\d+')

        for index, line in enumerate(contents):
            new_line = tool_version_re.sub(f'\\g<prefix>{cls.current}', line)

            new_line = scb_re.sub(f'\\g<prefix>{cls.suffix}', new_line)

            if line != new_line:
                if update:
                    contents[index] = new_line

                if not modified:
                    logger('%s:', str(readme_file))
                    modified = True

                logger('  %3d) %s',
                       index + 1,
                       (new_line if update else line).strip())

        if modified and update:
            readme_file.write_text('\n'.join(contents) + '\n',
                                   encoding = 'utf-8')

        return modified

    @classmethod
    def set(cls, version: str):

        """Sets the ScubaGoggles OFFICIAL version number and updates version
        number references throughout the code base.  This is done because
        unfortunately certain files (CSV, Markdown) can't reference the
        version number in Python code and must hardcode the version.

        :param str version: version number in '<major>.<minor>.<build>' format.
        """

        match = re.match(r'(?P<major>\d+)\.(?P<minor>\d+)\.(?P<build>\d+)$',
                         version)
        if not match:
            raise ValueError(f'? "{version}" - version number must conform to '
                             '<major>.<minor>.<build> format')

        # Change the OFFICIAL version number in the module's __init__.py file.

        init_file = cls._code_root / '__init__.py'
        if not init_file.exists():
            raise FileNotFoundError(f'{init_file} - ScubaGoggles module file '
                                    'missing')

        contents = init_file.read_text()

        version_defn_regexp = r'__version__\s*=\s*["\']\d+\.\d+\.\d+["\']'
        new_contents = re.sub(version_defn_regexp,
                              f"__version__ = '{version}'",
                              contents)

        if contents == new_contents:
            log.error('? ScubaGoggles version set - no changes made')
            return

        log.info('changing ScubaGoggles version to %s', version)
        init_file.write_text(new_contents, encoding = 'utf-8')

        # Initialize the class variables using the new version number, and
        # update the versions in the files.

        cls.initialize(version)
        cls.check_versions(True)


# This initializes the class variables during module load.  The initialization
# is done this way because re-initialization is necessary when the version
# number is changed, so using a method avoids duplicate code.

Version.initialize()
