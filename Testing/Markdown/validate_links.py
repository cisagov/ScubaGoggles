import os
import re
import requests
from collections import defaultdict
from tqdm import tqdm
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-l", '--locations', nargs="+",
    help='The locations (files or folders) of markdown files to validate. ' +
    "Should be the location relative to the repo top-level folder, e.g., '/docs'.")
args = parser.parse_args()

PROXIED = True
if PROXIED:
    # https://medium.com/@gevezex/python-ssl-tls-errors-behind-corporate-proxies-3229b8a2ab43
    import pip_system_certs.wrapt_requests

# folders = ['/docs', '/README.md', '/baselines']

# (.*\[.+\]\()
# Example match: "leading chars [link display text]("
#
# ([\w#./=&?%\-+:;$@,]+)
# Example match: "https://the.actual.url.example.com:443#here?a=b"
#
# (\).*)
# Example match: ") trailing characters"
link_re = re.compile(r"(.*\[.+\]\()([\w#./=&?%\-+:;$@,]+)(\).*)")

SCRIPT_LOCATION = os.path.dirname(os.path.realpath(__file__))
REPO_HOME = SCRIPT_LOCATION + '/../..'

# Map file name to its set of headers
anchors = defaultdict(set)

def collect_links(path : str):
    if os.path.isdir(REPO_HOME + path):
        links = []
        for subfile in os.listdir(REPO_HOME + path):
            links.extend(collect_links(os.path.join(path, subfile)))
        return links
    else:
        if not path.endswith('.md'):
            return []
        with open(REPO_HOME + path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        links = []
        for i, line in enumerate(lines):
            if line.startswith('#'):
                # Convert the header into a anchor tag
                tag = ' '.join(line.split()[1:]) # remove the leading "#"s
                tag = tag.replace('.', '').replace(',', '')
                tag = tag.replace(' ', '-').lower()
                anchors[path.replace('\\', '/')].add(tag)
            match = link_re.match(line)
            if match:
                link = match.groups()[1]
                links.append({
                    'link': link,
                    'location': f"{path}:{i+1}"
                })
        return links

all_links = []
for f in args.locations:
    all_links.extend(collect_links(f))


all_web_links = set()
all_bad_web_links = set()

def check_anchor(link : dict) -> bool:
    url = link['link']
    location = link['location']
    if '#' not in url:
        return False
    elif url.startswith('#'):
        fname = location.split(':')[0].replace('\\', '/')
        return url[1:] not in anchors[fname]
    else:
        fname = url.split('#')[0]
        anchor = url.split('#')[1]
        return anchor not in anchors[fname]

bad_links = []
for l in tqdm(all_links):
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
                if check_anchor(l):
                    bad_links.append(l)
        else:
            # path relative to the file that contains it
            file_dir = os.path.dirname(l['location'])
            link = REPO_HOME + os.path.join(file_dir, l['link'].split('#')[0])
            if not os.path.exists(link):
                bad_links.append(l)
            else:
                if check_anchor(l):
                    bad_links.append(l)

for l in bad_links:
    print(l)