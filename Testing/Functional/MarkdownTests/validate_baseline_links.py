import pip_system_certs.wrapt_requests # Needed if behind a proxy

import os
import re
import sys
import requests
from tqdm import tqdm
from collections import defaultdict

LEGAL_URL_CHARS = r'[\w#./=&?%\-+:;$@,]'
link_regex = re.compile(r'(\[.*\]\()(' + LEGAL_URL_CHARS + r'*)(\))')

BASELINE_FOLDER = "../../../baselines/"
REPO_HOME = "../../../"

web_links = defaultdict(lambda: [])
relative_paths = []
broken_web_links = set()
broken_relative_links = []

for subfile in os.listdir(BASELINE_FOLDER):
    if subfile=='images':
        continue
    with open(os.path.join(BASELINE_FOLDER, subfile), encoding='utf-8') as f:
        line_number = 1
        for line in f:
            links = [link[1] for link in link_regex.findall(line)]
            for link in links:
                if link.startswith('http://') or link.startswith('https://'):
                    web_links[link].append({
                        'file': subfile,
                        'line_number': line_number
                    })
                else:
                    relative_paths.append({
                        'link': link,
                        'file': subfile,
                        'line_number': line_number
                    })
            line_number += 1

for link in tqdm(web_links):
    status_code = requests.get(link).status_code
    if status_code != 200:
        broken_web_links.add(link)

for link in tqdm(relative_paths):
    if link['link'].startswith('/'):
        path = os.path.join(REPO_HOME, link['link'])
        if not os.path.isfile(path):
            broken_relative_links.append(link)
    elif link['link'].startswith('#'):
        # TODO
        continue
    elif link['link'].startswith('..'):
        # TODO
        continue
    else:
        # Not validating relative links right now
        continue

from pprint import pprint
pprint(broken_web_links)