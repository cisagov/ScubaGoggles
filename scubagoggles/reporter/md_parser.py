"""Markdown document parsing.
"""

import re

from collections import defaultdict
from pathlib import Path
from typing import Iterable, Union

from scubagoggles.version import Version


class MarkdownParserError(RuntimeError):

    """An exception related to Markdown processing errors.  This can be used
    to catch the exception for omitting the traceback, which really isn't
    much use in this case.
    """


class MarkdownParser:

    """The MarkdownParser is responsible for parsing the baseline Markdown
    files to extract the policy baseline information.
    """

    # Regular expressions used in parsing the Markdown text.  Note that these
    # are intended to be used with match() and NOT search() (for search, the
    # expressions need the start of string (^)).

    _above4_re = re.compile(r'#{1,3}[^#]')

    _group_re = re.compile(r'##\s*(?P<id>\d+)\.?\s+(?P<name>.+)$')

    _level2_re = re.compile(r'##[^#]')

    _policies_re = re.compile(r'(?i)###\s*Policies$')

    _baseline_re = re.compile(r'####\s*(?P<baseline>GWS\.(?P<product>[^.]+)'
                              r'\.(?P<id>\d+)\.(?P<item>\d+)'
                              r'(?P<version>v\d+\.?\d*))$')

    # This handles the single exception case where the combined drive
    # and docs product has a product name of "drive", but the baseline
    # identifiers are "drivedocs" (e.g., GWS.DRIVEDOCS.1.8). Arggh.

    _baseline_id_map = {'drive': 'drivedocs'}

    def __init__(self, baseline_dir: Union[Path, str]):

        """Initializer for the MarkdownParser class.

        :param baseline_dir: directory containing the baseline Markdown
            files.
        :type baseline_dir: Path or str
        """

        self._baseline_dir = Path(baseline_dir)
        if not self._baseline_dir.is_dir():
            raise NotADirectoryError(f'{self._baseline_dir}')

        self._default_version = None

        self._version_policy_map = defaultdict(set)

        self._policy_version_map = {}

    @classmethod
    def baseline_identifier(cls, product: str) -> str:

        """Return the identifier string used in the baselines for the
        given product.

        :param str product: product name.
        :return: the baseline identifier, in only lowercase characters.
        """

        return cls._baseline_id_map.get(product, product).lower()

    @property
    def default_version(self):

        """Returns the default policy id version suffix.  This is the suffix
        to use for any policy id which is not present in the "version policy
        map".
        """

        return self._default_version

    @property
    def policy_version_map(self):

        """Returns a dictionary where the policy identifier is the key and
        the value is its baseline suffix.  Policies will only be present in
        this map if the suffix is different from the default.
        """

        return self._policy_version_map

    def parse_baselines(self, products: Iterable[str]) -> dict:

        """Given a list of baseline product names (e.g., "gmail", "meet"),
        this method parses the corresponding Markdown files and returns
        the baseline data.

        :param Iterable[str] products: list of baseline product names.
        :return: dictionary of baseline data, where the keys are the given
            product names and the values are the product data.  See the
            _parse() method for the format of the returned data.
        """

        result = {}

        for product in products:
            product_result = self._parse(product)
            result.update(product_result)

        self._create_policy_version_map()

        return result

    def _parse(self, file_name: str, product: str = None) -> dict:

        """Parse the given Markdown file and return a dictionary containing
        baseline policy information.

        The dictionary returned has the following format:

        { <product>: [<baseline-group>, ...] }

        where <product> is the product name (e.g., "gmail"), and
        <baseline-group> is a dictionary:

        { 'GroupName': <name>,
          'GroupNumber': <id>,
          'Controls': [<control>, ...] }

        where <name> is a description of the group, <number> is the group
        identifier, and <control> is a dictionary for each baseline:

        { 'Id': <identifier>, 'Value': <description> }

        where <identifier> is the baseline identifier (e.g., 'GWS.GMAIL.1.1'),
        and <description> is the description of the baseline requirement.

        :param str file_name: name of the Markdown file.  It's also used as
            the product name, unless one is explicitly given.
        :param str product: name of the GWS product.  This is used instead of
            the file name (in the normal case, the file name is the same as
            the product name).
        :return: baseline data parsed from the Markdown file
        :rtype: dict
        """

        result = defaultdict(list)

        eof_message = 'unexpected end of file encountered'
        product = product if product else file_name
        baseline_id = self.baseline_identifier(product)
        md_file = self._baseline_dir / f'{file_name}.md'

        content = [line.strip() for line
                   in md_file.read_text(encoding = 'utf-8').splitlines()]

        total_lines = len(content)
        skip_lines = 0

        # This is the main loop of the parser.  It locates the start of a
        # policy group.  Once found, the inner loops read the section
        # related to the current policy group, first looking for the
        # "Policies" section, and then the individual policies.  These
        # inner loops keep track of the additional lines processed using
        # the 'skip_lines' count.  When a policy group has been completely
        # parsed, the outer loop regains control and will advance to the
        # next unprocessed line based on this count.

        for line_number, line in enumerate(content, start = 1):

            if skip_lines:
                skip_lines -= 1
                continue

            if not line:
                continue

            # Find the next policy group.

            match = self._group_re.match(line)

            if not match:
                continue

            group_id = match['id']
            group_name = match['name']

            group = {'GroupNumber': group_id,
                     'GroupName': group_name,
                     'Controls': []}

            if line_number == total_lines:
                self._parser_error(md_file, eof_message, group_id, group_name)

            # We're in the start of the policy group, so next look for the
            # "Policies" section, which contains the baseline definitions.

            for next_line in content[line_number:]:

                skip_lines += 1

                match = self._policies_re.match(next_line)
                if match or self._level2_re.match(next_line):
                    break

            if not match:
                message = '"Policies" section missing'
                self._parser_error(md_file, message, group_id, group_name)

            if (line_number + skip_lines) == total_lines:
                self._parser_error(md_file, eof_message, group_id, group_name)

            baseline_content = content[line_number + skip_lines:]
            skip_lines += self._parse_baselines(baseline_content,
                                                md_file,
                                                baseline_id,
                                                group)

            # All baseline items in the current group have been parsed.
            # The group is added to the result dictionary.

            result[product].append(group)

        return result

    def _parse_baselines(self,
                         baseline_content: list,
                         md_file: Path,
                         baseline_id: str,
                         group: dict) -> int:

        """This method parses the "Policies" sections of the baseline
        Markdown files.

        The "controls" section of the given group is filled in, with each
        element in the list containing information about one baseline.

        :param list baseline_content: lines from the Markdown content following
            the "Policies" section.
        :param Path md_file: file specification of the Markdown file for
            error reporting.
        :param str baseline_id: baseline identifier for the current file
            (e.g., "gmail").
        :param dict group: group data that will contain the controls parsed in
            this method.  NOTE that the group is passed by reference, so all
            additions made to it are essentially passed back to the caller.
        :return:
        """

        group_id = group['GroupNumber']
        group_name = group['GroupName']

        # We're in the section where the baselines are defined.  The
        # following two loops parse the baseline sections.  The outer
        # loop handles the transition from one baseline section to the
        # next, while the inner loop locates the next baseline and
        # parses it.

        next_line = ''
        prev_item = 0
        lines_seen = 0
        total_lines = len(baseline_content)

        while (lines_seen < total_lines
               and not self._above4_re.match(next_line)):

            for next_line in baseline_content[lines_seen:]:

                if self._above4_re.match(next_line):
                    break

                lines_seen += 1

                # Find the next baseline section.

                match = self._baseline_re.match(next_line)
                if not match:
                    continue

                # We've found a baseline section.  Check the baseline
                # identifier to make sure it's expected (this is mainly
                # to catch cut/paste errors and unintentional omissions).

                current_baseline_id = match['product'].lower()

                if current_baseline_id != baseline_id:
                    message = ('different product encountered '
                               f'{current_baseline_id} != {baseline_id}')
                    self._parser_error(md_file,
                                       message,
                                       group_id,
                                       group_name)

                baseline = match['baseline']
                ident = match['id']
                item = int(match['item'])
                version = match['version']

                if ident != group_id:
                    message = f'mismatching group number ({ident})'
                    self._parser_error(md_file,
                                       message,
                                       group_id,
                                       group_name)

                if  not Version.is_valid_suffix(version):
                    message = f'invalid baseline version ({version})'
                    self._parser_error(md_file,
                                       message,
                                       group_id,
                                       group_name)

                if item != (prev_item + 1):
                    message = (f'expected baseline item {prev_item + 1}, '
                               f'got item {item}')
                    self._parser_error(md_file,
                                       message,
                                       group_id,
                                       group_name)

                prev_item = item
                value_lines = []

                for value_line in baseline_content[lines_seen:]:

                    lines_seen += 1

                    if not value_line:
                        if not value_lines:
                            continue
                        break

                    value_lines.append(value_line)

                value = ' '.join(value_lines)

                if not value:
                    message = ('missing description for baseline item '
                               f'{item}')
                    self._parser_error(md_file,
                                       message,
                                       group_id,
                                       group_name)

                control = {'Id': baseline, 'Value': value}
                group['Controls'].append(control)

                policy_id = baseline.removesuffix(version)
                self._version_policy_map[version].add(policy_id)

                # Break out of this inner loop, and as long as we're not
                # at the end of the file, the outer loop will re-enter
                # the inner loop to locate the next baseline section.

                break

        return lines_seen

    def _create_policy_version_map(self):

        """Creates the policy version map from the existing version policy map,
        which is a reverse mapping.  It also determines the "default" version
        suffix based on the version with the most policies.
        """

        if not self._version_policy_map:
            return

        # The version having the most policies is the default, and all other
        # policies will be mapped to their version suffixes.

        sorted_versions = sorted(self._version_policy_map.keys(),
                                 key = lambda k: len(self._version_policy_map[k]),
                                 reverse = True)

        self._default_version = sorted_versions[0]

        self._policy_version_map = {p: v for v in sorted_versions[1:]
                                    for p in self._version_policy_map[v]}

    @staticmethod
    def _parser_error(md_file: Path,
                      message: str,
                      group_id: str = None,
                      group_name: str = None):

        """Constructs an error message and raises a MarkdownParserError
        exception.

        :param Path md_file: Markdown file specification.
        :param str message: error-specific message.
        :param str group_id: [optional] identifier of the group - if this is
            given, the group_name is also required.
        :param str group_name: [optional] name of the policy group.
        """

        message = f'{md_file}: {message}'
        if group_id:
            message += f' for group id {group_id} ({group_name})'

        raise MarkdownParserError(message)
