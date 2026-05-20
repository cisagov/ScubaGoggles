"""Markdown document parsing.
"""

import re

from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Iterable, Union
from urllib.parse import urlparse, urlunparse

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

    # Regular expressions used in parsing the Markdown text.  Note that most of
    # these are intended to be used with match() and NOT search() (for search,
    # the expressions need the start of string (^) in the expressions - for
    # match() the "^" is implied).

    _group_re = re.compile(r'##\s*(?P<id>\d+)\.?\s+(?P<name>.+)$')

    _policies_re = re.compile(r'(?i)###\s*Policies$')

    _baseline_re = re.compile(r'####\s*(?P<baseline>GWS\.(?P<product>[^.]+)'
                              r'\.(?P<id>\d+)\.(?P<item>\d+)'
                              r'(?P<version>[a-zA-Z]\S*))$')

    _color_re = re.compile(r'(?i)-(?P<color>[a-f0-9]+)$')

    _indicator_re = re.compile(r'\[!\[(?P<name>[^\]]+)\]\((?P<url>[^)]+)\)\]')

    _valid_indicators = {'Automated Check',
                         'Configurable',
                         'Log-Based Check',
                         'Manual'}

    _normalized_indicators = {i.lower().replace(' ', ''): i
                              for i in _valid_indicators}

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

        # _baseline - contains the full policy identifier for the
        #             currently parsed baseline (e.g., GWS.CHAT.1.2v1).
        #
        # _baseline_id - product name (e.g., chat) in lowercase for
        #                the currently parsed baseline.
        #
        # _default_version - version suffix that occurs most often
        #                    in the parsed baselines.
        #
        # _group - current group being parsed (dict).  This is part of
        #
        # _item - integer baseline item number (e.g., if the current policy
        #         identifier is GWS.CHAT.1.2v1, the item number is 2).
        #
        # _md_file - Path for the current Markdown file being parsed.
        #
        # _version_policy_map - mapping of version suffix to list of policies
        #                       having that version.  It's used to determine
        #                       the default version and for generating the
        #                       policy version map.
        #
        # _policy_version_map - mapping of policies to their version suffixes,
        #                       excluding policies having the default version.
        #                       Along with the default version, this mapping
        #                       is input for Rego.

        self._baseline = None

        self._baseline_id = None

        self._default_version = None

        self._group = {}

        self._item = None

        self._md_file = None

        self._version_policy_map = None

        self._policy_version_map = None

    @classmethod
    def baseline_identifier(cls, product: str) -> str:

        """Return the identifier string used in the baselines for the
        given product.

        :param str product: product name.
        :return: the baseline identifier, in only lowercase characters.
        """

        return cls._baseline_id_map.get(product, product).lower()

    @property
    def default_version(self) -> str:

        """Returns the default policy id version suffix.  This is the suffix
        to use for any policy id which is not present in the "version policy
        map".
        """

        return self._default_version

    @property
    def policy_version_map(self) -> dict:

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

        self._default_version = None

        self._policy_version_map = {}

        self._version_policy_map = defaultdict(set)

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

        { 'Id': <identifier>,
          'Indicators': [<indicator>, ...],
          'Value': <description> }

        where <identifier> is the baseline identifier (e.g., 'GWS.GMAIL.1.1'),
        and <description> is the description of the baseline requirement.

        If one or more indicators are present, the "Indicators" list will
        contain and entry for each iterator:

        { 'name': <name>,
          'color': <hex-color>,
          'link': <url> }

        where <name> is one of the valid indicator names (defined above),
        the <hex-color> is the hexadecimal HTML color code that's always
        included as a suffix of the URL path.  The <url> is the link for
        the indicator.

        :param str file_name: name of the Markdown file.  It's also used as
            the product name, unless one is explicitly given.
        :param str product: name of the GWS product.  This is used instead of
            the file name (in the normal case, the file name is the same as
            the product name).

        :return: baseline data parsed from the Markdown file
        :rtype: dict
        """

        result = defaultdict(list)

        product = product if product else file_name
        self._baseline_id = self.baseline_identifier(product)
        self._md_file = self._baseline_dir / f'{file_name}.md'

        content = [line.strip() for line
                   in self._md_file.read_text(encoding = 'utf-8').splitlines()]

        # Parse the baselines one group at a time.

        for group_content in self._next_group(content):

            self._parse_baselines(group_content)

            result[product].append(self._group)

        return result

    def _parse_baselines(self, group_content: list[str]) -> None:

        """This method parses the "Policies" sections of the baseline
        Markdown files.

        The "controls" section of the current group is filled in, with each
        element in the list containing information about one baseline.

        :param list group_content: lines from the Markdown content following
            the "Policies" section to the end of the baseline group.
        """

        for baseline_content in self._next_baseline(group_content):

            description = self._parse_description(baseline_content)

            indicators = self._parse_indicators(baseline_content)

            control = {'Id': self._baseline,
                       'Indicators': indicators,
                       'Value': description}

            self._group['Controls'].append(control)

    def _parse_description(self, baseline_content: list[str]) -> str:

        """Given the baseline content, this method returns the concatenation
        of one or more lines that make up the baseline's description.

        :param list baseline_content: lines from the Markdown content that
            begin with the line immediately following the baseline
            identifier, which should be the first line of the description.

        :return: description string.
        :rtype: str
        """

        # Look for the end of the description line(s).  The description normally
        # ends with a blank line, but an indicator (link), list, header, or end
        # of the section will terminate the description.

        total_lines = len(baseline_content)
        end_found = False
        end_index = line = None

        for end_index in range(total_lines):

            line = baseline_content[end_index].strip()

            if not line or line[0] in ('-', '#', '['):
                end_found = True
                break

        if not end_found or not end_index:

            # One of the ending delimiters wasn't found, and/or we've reached
            # the end of the baseline content.  This isn't typical, but as long
            # as we've got at least one line of description it's OK.

            if end_index is None or end_index == 0 and not line:
                message = f'missing description for baseline item {self._item}'
                self._parser_error(message)

            end_index += 1

        # Multiple description lines are joined together with a single space
        # between lines.

        return ' '.join(baseline_content[:end_index])

    def _parse_indicators(self, baseline_content: list[str]) -> list[dict]:

        """Parses the indicators for the current baseline.  They are defined
        as links immediately following the policy description and before the
        "rationale" section.  The link title contains and image link itself,
        which is the indicator.  Multiple indicator links must be specified
        consecutively.

        This method finds any indicators in the given baseline content and
        returns the name, color, and URL for each indicator.

        :param list baseline_content: lines from the Markdown content that
            begin with the line immediately following the baseline
            identifier, which should be the first line of the description.

        :return: list of dictionaries, one for each indicator found,
            which contains the name, color, and URL.
        :rtype: list
        """

        indicators = []

        indicator_found = False

        for line in baseline_content:

            line = line.strip()

            match = self._indicator_re.match(line)

            if not match:

                # Indicators for a baseline are grouped together, so we're done
                # if one has already been found and the current line is empty or
                # is a header or list item.

                if indicator_found and (not line or line[0] in ('-', '#')):
                    break

                continue

            indicator_found = True

            # Normalize the extracted name and get the name from the set of
            # valid indicator names.

            name = match['name'].lower().replace(' ', '')
            name = self._normalized_indicators.get(name)

            if not name:
                self._parser_error(f'"{match["name"]}" - unrecognized indicator')

            url = urlparse(match['url'])

            match = self._color_re.search(url.path)

            if not match:
                self._parser_error(f'"{url.path}" - color suffix missing')

            indicator = {'name': name,
                         'color': f'#{match["color"].upper()}',
                         'link': urlunparse(url)}

            indicators.append(indicator)

        return indicators

    def _create_policy_version_map(self) -> None:

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

    def _parser_error(self, message: str) -> None:

        """Constructs an error message and raises a MarkdownParserError
        exception.

        :param str message: error-specific message.
        """

        message = f'{self._md_file}: {message}'
        if 'GroupNumber' in self._group:
            message += (f' for group id {self._group["GroupNumber"]} '
                        f'({self._group["GroupName"]})')

        raise MarkdownParserError(message)

    def _next_group(self, content: list[str]) -> Iterator[list[str]]:

        """Returns a generator that produces the content (lines) from the
        given Markdown file content for each baseline group.

        :param list group_content: lines from the Markdown content at the
            beginning of the file or following a previously parsed baseline.

        :yield: list of strings comprising the group content.
        :rtype: list
        """

        # Each group section starts with a "level 2" heading giving the group
        # number and the group name (e.g., "## 10. Google Workspace Sync").

        total_lines = len(content)
        found = False
        next_index = 0

        while next_index < total_lines:

            line = content[next_index]

            next_index += 1

            if not line:
                continue

            # Find the next policy group.

            match = self._group_re.match(line)

            if not match:
                continue

            found = True

            group_id = match['id']
            group_name = match['name']

            self._group = {'GroupNumber': group_id,
                           'GroupName': group_name,
                           'Controls': []}

            group_index = next_index

            # The end of the current group is either when we encounter the
            # next group or the end of the file.

            while (next_index < total_lines
                   and not self._group_re.match(content[next_index])):
                next_index += 1

            yield content[group_index:next_index]

        if not found:
            self._parser_error('no valid group headings found')

    def _next_baseline(self, group_content: list[str]) -> Iterator[list[str]]:

        """Returns a generator that produces the content (lines) from the
        given group for each baseline.

        :param list group_content: lines from the Markdown content following
            the heading that marks the start of the baseline group.

        :yield: list of strings comprising the baseline content.
        :rtype: list
        """

        total_lines = next_index = len(group_content)
        found = False

        # First locate the "Policies" section - this will contain all the
        # baseline definitions.

        for next_index, line in enumerate(group_content):

            if self._policies_re.match(line):
                found = True
                break

        if not found:
            self._parser_error('"Policies" section missing')

        # Find each baseline by looking for the starting baseline identifier.
        # As each baseline is found, the contents of the baseline definition
        # is returned to the caller.

        found = False
        prev_item = 0

        while next_index < total_lines:

            line = group_content[next_index]

            next_index += 1

            if not line:
                continue

            match = self._baseline_re.match(line)

            if not match:
                continue

            # Check the baseline just found to make sure it's consistent
            # with the expected product and already parsed baselines.

            found = True

            self._baseline = match['baseline']
            baseline_id = match['product'].lower()
            ident = match['id']
            self._item = item = int(match['item'])
            version = match['version']

            self._check_baseline(baseline_id, ident, version, prev_item)

            policy_id = self._baseline.removesuffix(version)

            self._version_policy_map[version].add(policy_id)

            baseline_index = next_index

            # The end of the current baseline is either when we encounter the
            # next baseline or the end of the file.

            while (next_index < total_lines
                and not group_content[next_index].strip().startswith('#')):
                next_index += 1

            yield group_content[baseline_index:next_index]

            prev_item = item

        if not found:
            self._parser_error('no baselines found in "Policies" section')

    def _check_baseline(self,
                        baseline_id: str,
                        ident: str,
                        version: str,
                        prev_item: int) -> None:

        """Performs checks on a newly parsed baseline.  Any checks that
        don't pass results in a MarkdownParserError being raised.  This
        is intended to catch typical cut/paste errors in baseline files
        when they're being modified.

        :param str baseline_id: baseline id (product name).
        :param str ident: baseline group number.
        :param str version: baseline version.
        :param int prev_item: item number of the previous baseline.
        """

        # All baselines in the same group must be associated with the same
        # product (e.g., "gmail").

        if baseline_id.lower() != self._baseline_id:
            message = ('different product encountered '
                        f'{baseline_id} != {self._baseline_id}')
            self._parser_error(message)

        # The baseline must have the same group number found at the start of
        # the group section.

        if ident != self._group['GroupNumber']:
            message = f'mismatching group number ({ident})'
            self._parser_error(message)

        # Checking the version number itself is a bit tricky, but at least we
        # can make sure the version has the correct format.

        if not Version.is_valid_suffix(version):
            message = f'invalid baseline version ({version})'
            self._parser_error(message)

        # Baselines in the same group must be in sequence, so if the current
        # item is 3, the previous baseline item must be 2.

        if self._item != (prev_item + 1):
            message = (f'expected baseline item {prev_item + 1}, '
                        f'got item {self._item}')
            self._parser_error(message)

    @staticmethod
    def controls_by_product(baselines: dict, normalize: bool = False) -> dict:

        """Given the parsed baselines structure returned by parse_baselines(),
        this method returns a dictionary of product names to baseline
        identifiers (e.g., 'GWS.GMAIL.1.1') with the corresponding descriptions.
        This flattened data structure is possible because product names and
        baseline identifiers are unique.

        :param dict baselines: dictionary with product name keys and list
            of groups as values.  This is the data structure returned by
            parse_baselines()
        :param bool normalize: in the returned dictionary, convert all product
            names to lowercase if this is set to True; otherwise, the product
            names are unaltered from the input.

        :return: product name to baseline identifier mapping, with descriptions
            ({<product>: {<baseline-1>: <description1>, ...}}).
        :rtype: dict
        """

        products = {product.lower() if normalize else product:
                    {ctrl['Id']: ctrl['Value'] for group in groups
                              for ctrl in group['Controls']}
                    for product, groups in baselines.items()}

        return products
