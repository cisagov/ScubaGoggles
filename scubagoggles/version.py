"""Module that handles the ScubaGoggles version number.
"""

import argparse
import csv
import logging
import re

from collections import defaultdict
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

    _suffix_regex = r'v(?P<major>\d+)\.?(?P<minor>\d*)'

    suffix_re = re.compile(_suffix_regex, re.IGNORECASE)

    # The following regular expression is used to locate the policy ID (with
    # version suffix) within a string.  It separates the policy ID from the
    # suffix.

    _version_regex = r'(?P<policy_id>GWS\.\w+\.\d+\.\d+)(?P<sfx>v\d+\.?\d*)'

    version_re = re.compile(_version_regex, re.IGNORECASE)

    _baseline_version_map = {}

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

        # This is the version suffix used at the end of policy IDs (e.g.,
        # 'GWS.CHAT.1.0.v1', where 'v1' is the version suffix). For a new
        # release 2 (e.g, '2.0'), the suffix is 'v2'.  These are manually
        # changed for each policy ID.

        cls.suffix = f'v{cls.major}'

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
    def check_version(cls, data: str) ->  tuple[bool, dict]:

        """Given a data string with zero or more policy identifiers, this
        function checks that the baseline version suffix(es) is/are correct
        and consistent.

        :param str data: string which may contain policy identifiers.
        :return: a tuple, where the first element is a boolean indicating
        whether the version check succeeded for the given string.  The second
        element is an empty dictionary if the check succeeded; otherwise, it
        is a dictionary with the policy id as key and the value is a list
        with the expected version suffix, followed by the invalid suffix(es)
        found in the input string.
        """

        # This is part of the data returned.  For each policy identifier
        # that has an incorrect version suffix, the value in the dictionary
        # (keyed by policy id) is a list with the expected version suffix
        # along with one or more encountered suffixes that don't match the
        # expected value.

        suffix_errors = defaultdict(list)

        # In most cases, there will be only one policy identifier in the
        # given string.

        # This check only determines whether the version suffixes are
        # consistent and "reasonable" for a given policy ID.  A version
        # suffix is reasonable if it corresponds to the current ScubaGoggles
        # version or a prior version.  The '_baseline_version_map' is
        # used for check for consistent suffixes for policy IDs.

        for current_match in cls.version_re.finditer(data):

            policy_id = current_match['policy_id']

            version_sfx = current_match['sfx']

            expected_sfx = cls._baseline_version_map.get(policy_id)

            if not expected_sfx:

                if cls.is_valid_suffix(version_sfx):
                    cls._baseline_version_map[policy_id] = version_sfx
                    continue

                # The policy's suffix isn't valid, so we set the expected
                # suffix to the current version suffix.  It will fail the
                # next comparison and an error will be created for it.  NOTE
                # that the way the versioning is done makes it unlikely
                # that this condition will occur (mistakenly using "v0"
                # is one case).

                expected_sfx = cls.suffix

            if version_sfx != expected_sfx:

                entry = suffix_errors[policy_id]

                if not entry:
                    entry.append(expected_sfx)

                entry.append(version_sfx)

        return len(suffix_errors) == 0, suffix_errors

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

        cls._baseline_version_map = {}

        # The meaning of 'modified' is dependent on the value of 'update'.
        # For update True, it'll mean at least 1 file was modified; for
        # False, it means a version inconsistency was found.

        modified = cls.check_or_update_readme(update)

        for md_file in cls._code_root.glob('**/*.md'):
            cls.check_md(md_file)

        # The drift rules CSV files are not part of the code content, and
        # exist in the directory above the code root.

        drift_rules_dir = cls._code_root.parent / 'drift-rules'

        if not drift_rules_dir.is_dir():
            raise NotADirectoryError(f'{drift_rules_dir} - drift rules '
                                     'directory missing')

        for csv_file in drift_rules_dir.glob('*.csv'):
            cls.check_csv(csv_file)

        return modified

    @classmethod
    def check_csv(cls, drift_csv: Path) -> bool:

        """Validates the ScubaGoggles version number embedded in the given
        drift monitoring rules CSV file.

        :param Path drift_csv: file specification for a drift CSV file.
        :return:  True if the versions of the policy IDs found in the file
            are reasonable and consistent with the current version; False
            otherwise.
        """

        log.debug(str(drift_csv))

        with drift_csv.open(encoding = 'utf-8') as csvfile:

            reader = csv.DictReader(csvfile)

            contents = list(reader)

        error_found = False

        for index, row in enumerate(contents):

            # These CSV files have a field for the policy ID, so it must
            # exist.  In addition to the version suffix, we also check the
            # format of the policy ID itself.

            match = cls.version_re.match(row['PolicyId'])

            sfx_ok = errors = None

            if match:
                sfx_ok, errors = cls.check_version(row['PolicyId'])

            if not sfx_ok:

                if not error_found:
                    log.error('%s:', str(drift_csv))
                    error_found = True

                if not match:
                    log.error('  %3d) Invalid PolicyId: "%s"',
                              index + 2,
                              row['PolicyId'])
                else:
                    cls.log_version_errors(index + 2, errors)

        return not error_found

    @classmethod
    def check_md(cls, md_file: Path) -> bool:

        """Validates the ScubaGoggles version number embedded in the given
        Markdown file.

        :param Path md_file: file specification for a Markdown file.
        :return:  True if the versions of the policy IDs found in the file
            are reasonable and consistent with the current version; False
            otherwise.
        """

        log.debug(str(md_file))

        contents = md_file.read_text(encoding = 'utf-8').splitlines()

        error_found = False

        for index, line in enumerate(contents):

            sfx_ok, errors = cls.check_version(line)

            if not sfx_ok:

                if not error_found:
                    log.error('%s:', str(md_file))
                    error_found = True

                cls.log_version_errors(index + 1, errors)

        return not error_found

    @classmethod
    def check_or_update_readme(cls, update: bool = False) -> bool:

        """Validates the ScubaGoggles version number embedded in the top-level
        README Markdown file.  There may be a couple version number references
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

        # The top-level README file has one place where the version is
        # hardcoded.  The reference is embedded in a URL.

        tool_regex = f'(?P<prefix>{cls.name}-)' + r'v\d+(?:\.\d+){2}'
        tool_version_re = re.compile(tool_regex)

        for index, line in enumerate(contents):
            new_line = tool_version_re.sub(f'\\g<prefix>{cls.current}', line)

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

    @classmethod
    def is_valid_suffix(cls, version_sfx: str) -> bool:

        """Determines if a given policy version suffix is in the correct
        format and value.

        :param str version_sfx: string containing a policy ID version suffix.
        :return: True if the given version suffix is valid; False otherwise.
        """

        match = cls.suffix_re.match(version_sfx)

        return bool(match)

    @staticmethod
    def log_version_errors(line_number: int, errors: dict) -> None:

        """Logs version suffix errors returned by check_version().

        :param int line_number: the line number in the file where the error(s)
            were found.
        :param dict errors: version suffix errors, by policy ID.  See the
            description for the return value in check_version().
        """

        for policy_id, versions in errors.items():

            log.error('  %3d) %s: expected %s, got %s',
                      line_number,
                      policy_id,
                      versions[0],
                      ', '.join(versions[1:]))


# This initializes the class variables during module load.  The initialization
# is done this way because re-initialization is necessary when the version
# number is changed, so using a method avoids duplicate code.

Version.initialize()
