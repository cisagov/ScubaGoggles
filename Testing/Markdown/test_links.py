"""
test_links.py provides the functionality to valide the links within the
markdown files.
"""

import os
import re
from pprint import pprint
from collections import defaultdict
import requests

# Regex for identifying strings with markdown links, e.g., [some text](url)
# Interpretation:
# (.*\[.+\]\()
# Example match: "leading chars [link display text]("
#
# ([\w#./=&?%\-+:;$@,]+)
# Example match: "https://the.actual.url.example.com:443#here?a=b"
#
# (\).*)
# Example match: ") trailing characters"
link_re = re.compile(r"(.*\[.+\]\()([\w#./=&?%\-+:;$@,]+)(\).*)")

class MarkdownParser:
    '''
    Class for extracting all links from the provided markdown files and
    validating relative links within them.
    '''

    @staticmethod
    def abs_path(path : str) -> str:
        '''
        Function to ensure paths are always referred to consistently.
        '''
        path = path.split(':')[0]
        path = path.split('#')[0]
        return os.path.abspath(path).replace('\\', '/')

    def __init__(self, home, locations : list):
        self.links = []
        self.anchors = defaultdict(set)
        self.home = home.replace('\\', '/') + '/'
        self.parse_markdowns(locations)

    def parse_markdowns(self, locations : list) -> None:
        '''
        Trigger recursive evaluation to identify all the links within
        the provided locations.
        :param locations: List of locations to check, relative to the
            provided home location.
        '''
        for loc in locations:
            self.parse_recursive(loc)

    def parse_recursive(self, path : str):
        '''
        Recursively identify all the links within the provided location.
        :param path: The location to check, relative to the
            provided home location.
        '''
        if os.path.isdir(self.home + path):
            for subfile in os.listdir(self.home + path):
                self.parse_recursive(os.path.join(path, subfile))
        else:
            if not path.endswith('.md'):
                return
            with open(self.home + path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            for i, line in enumerate(lines):
                if line.startswith('#'):
                    # Convert the header into a anchor tag
                    tag = ' '.join(line.split()[1:]) # remove the leading "#"s
                    tag = re.sub(r'[^a-zA-Z0-9_\-\s]+', '', tag)
                    tag = tag.strip().lower()
                    tag = re.sub(r'\s+', '-', tag)
                    full_name = MarkdownParser.abs_path(self.home + path)
                    if tag in self.anchors[full_name]:
                        # Handle the case where there are multiple headers
                        # with the same name. GitHub appends "-{n}" to
                        # each repeat in this case.
                        i = 1
                        while True:
                            if f"{tag}-{i}" in self.anchors[full_name]:
                                i += 1
                            else:
                                self.anchors[full_name].add(f"{tag}-{i}")
                                break
                    else:
                        self.anchors[full_name].add(tag)
                match = link_re.match(line)
                if match:
                    link = match.groups()[1]
                    path = path.replace('\\', '/')
                    self.links.append({
                        'url': link,
                        'location': f"{path}:{i+1}"
                    })

    def check_anchor(self, link : dict) -> bool:
        '''
        Check to see if the provided link contains an anchor and if the
        anchor references an actual header in the markdown files. Returns
        True if the link is valid.
        :param link: Dict with both the url and the location within the
            markdown files where the url is used.
        '''
        url = link['url']
        location = link['location']
        if '#' not in url:
            return True
        if url.startswith('#'):
            fname = location.split(':')[0].replace('\\', '/')
            return url[1:] in self.anchors[MarkdownParser.abs_path(self.home + fname)]
        fname = url.split('#')[0]
        anchor = url.split('#')[1]
        file_dir = os.path.dirname(link['location'])
        url = self.home + os.path.join(file_dir, fname)
        return anchor in self.anchors[MarkdownParser.abs_path(self.home + url)]

    def test_relative_link(self, link : dict) -> bool:
        '''
        Check to see if the provided link references a valid local markdown
        file. Returns True if the link is valid.
        :param link: Dict with both the url and the location within the
            markdown files where the url is used.
        '''
        if link['url'].startswith('/'):
            # path relative to directory home
            if not os.path.exists(self.home + link['url'][1:].split('#')[0]):
                return False
            return self.check_anchor(link)
        # path relative to the file that contains it
        file_dir = os.path.dirname(link['location'])
        url = self.home + os.path.join(file_dir, link['url'].split('#')[0])
        if not os.path.exists(url):
            return False
        return self.check_anchor(link)

# pylint: disable-next=too-few-public-methods
class WebLinkChecker:
    '''
    Class for validating web links.
    '''
    def __init__(self):
        # Sets for preventing duplicate web requests
        self.previously_checked = set()
        self.known_bad = set()

    def test_url(self, url : str) -> bool:
        '''
        Test the provided url, return True if the url is valid.
        :param link: The URL to test
        '''
        try:
            if url not in self.previously_checked:
                self.previously_checked.add(url)
                if requests.get(url, timeout=10).status_code != 200:
                    self.known_bad.add(url)
                    return False
            return url not in self.known_bad
        # pylint: disable-next=bare-except
        except:
            self.previously_checked.add(url)
            self.known_bad.add(url)
            return False

def test_links(repo_home : str, locations : list):
    '''
    The actual test function. Throws an exception if any links are invalid.
    :param repo_home: The location of the repo directory.
    :param locations: List of strings, the locations (files or folders) of
        markdown files to validate. Should be the location relative to the
        repo top-level folder, e.g., '/docs'.
    '''

    md_parser = MarkdownParser(repo_home, locations)
    web_checker = WebLinkChecker()
    bad_links = []

    for l in md_parser.links:
        if l['url'].startswith('http'):
            if not web_checker.test_url(l['url']):
                bad_links.append(l)
        else:
            if not md_parser.test_relative_link(l):
                bad_links.append(l)

    if len(bad_links) > 0:
        print("Broken links:")
        pprint(bad_links)

    assert len(bad_links) == 0
