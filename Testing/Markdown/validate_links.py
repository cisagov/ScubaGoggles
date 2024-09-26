import pip_system_certs.wrapt_requests

import os
import re
import requests
from collections import defaultdict
from tqdm import tqdm
import argparse
import pytest
from pprint import pprint

SCRIPT_LOCATION = os.path.dirname(os.path.realpath(__file__))
REPO_HOME = SCRIPT_LOCATION + '/../..'

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
    def __init__(home, locations : list):
        self.links = []
        self.anchors = defaultdict(set)
        self.HOME = home
        parse_markdowns(locations)

    def parse_markdowns(locations : list) -> None:
        for loc in locations:
            self.parse_recursive(loc)

    def parse_recursive(self, path : str):
        if os.path.isdir(self.HOME + path):
            for subfile in os.listdir(self.HOME + path):
                parse_recursive(os.path.join(path, subfile))
        else:
            if not path.endswith('.md'):
                return
            with open(self.HOME + path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            for i, line in enumerate(lines):
                if line.startswith('#'):
                    # Convert the header into a anchor tag
                    tag = ' '.join(line.split()[1:]) # remove the leading "#"s
                    tag = tag.replace('.', '').replace(',', '')
                    tag = tag.replace(' ', '-').lower()
                    self.anchors[path.replace('\\', '/')].add(tag)
                match = link_re.match(line)
                if match:
                    link = match.groups()[1]
                    self.links.append({
                        'link': link,
                        'location': f"{path}:{i+1}"
                    })

    def check_anchor(self, link : dict) -> bool:
        url = link['link']
        location = link['location']
        if '#' not in url:
            return False
        elif url.startswith('#'):
            fname = location.split(':')[0].replace('\\', '/')
            return url[1:] not in self.anchors[fname]
        else:
            fname = url.split('#')[0]
            anchor = url.split('#')[1]
            return anchor not in self.anchors[fname]

def test_links(locations):
    md_parser = MarkdownParser(REPO_HOME, locations)

    all_web_links = set()
    all_bad_web_links = set()
    bad_links = []

    for l in tqdm(md_parser.links):
        if l['link'].startswith('http'):
            if l['link'] not in all_web_links:
                # We haven't tested this link yet
                all_web_links.add(l['link'])
                if requests.get(l['link']).status_code != 200:
                    all_bad_web_links.add(l['link'])
                    bad_links.append(l)
            else:
                # We've tested this link before, no need to request it again
                if l['link'] in all_bad_web_links:
                    # This link was bad, add it again to save this new location
                    bad_links.append(l)
        else:
            if l['link'].startswith('/'):
                # path relative to directory home
                if not os.path.exists(REPO_HOME + l['link'].split('#')[0]):
                    bad_links.append(l)
                else:
                    if md_parser.check_anchor(l):
                        bad_links.append(l)
            else:
                # path relative to the file that contains it
                file_dir = os.path.dirname(l['location'])
                link = REPO_HOME + os.path.join(file_dir, l['link'].split('#')[0])
                if not os.path.exists(link):
                    bad_links.append(l)
                else:
                    if md_parser.check_anchor(l):
                        bad_links.append(l)

    if len(bad_links > 0):
        pprint(bad_links)

    assert len(bad_links) == 0

parser = argparse.ArgumentParser()
parser.add_argument("-l", '--locations', nargs="+",
    help='The locations (files or folders) of markdown files to validate. ' +
    "Should be the location relative to the repo top-level folder, e.g., '/docs'.")
args = parser.parse_args()


