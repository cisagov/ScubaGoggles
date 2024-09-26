import os
import re

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