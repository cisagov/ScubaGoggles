"""
This modules contains functions petaining to the baseline markdown documents.

"""

import re
import pathlib
from html import escape

def read_baseline_docs(baseline_path:pathlib.Path, prod_to_fullname:dict):
    """
    This function parses the secure baseline via each product markdown
    document to align policy with the software baseline.

    """

    baseline_md = [
        filename.stem for filename in baseline_path.glob('*.md')
    ]

    # map baseline short name i.e gmail to markdown file name
    # assumes the product fullname is in the markdown file name
    prod_to_baselinemd = {}
    for product in prod_to_fullname.keys():
        for baseline in baseline_md:
            if product in baseline:
                prod_to_baselinemd[product] = baseline

    # create a dict containing Policy Group and Individual policies
    baseline_output = {}
    for product, baselinemd in prod_to_baselinemd.items():
        baseline_output[product] = []
        baselinemd_path = baseline_path / f"{baselinemd}.md"
        with baselinemd_path.open(mode='r',encoding='UTF-8') as baseline_f:
            md_lines = baseline_f.readlines()

        # Select the policy group number via "## Number." regex
        # example line this would match on: ## 1. PolicyGroup
        line_numbers = [
            i
            for i, line in enumerate(md_lines)
            if re.search(r"^## [0-9]+\.", line)
        ]
        groups = [md_lines[line_number] for line_number in line_numbers]

        for group_name in groups:
            group = {}
            group_number = group_name.split(".")[0][3:]
            group_name = group_name.split(".")[1].strip()
            group["GroupNumber"] = group_number
            group["GroupName"] = group_name
            group["Controls"] = []

            # Search for the line number of all individual Policy Group Ids
            # There is an assumption here that Policy id is the uppercase version
            # of the product short name i.e meet => MEET
            product_upper = 'DRIVEDOCS' if product == 'drive' else product.upper()

            id_regex = rf"#### [A-Za-z]+\.{product_upper}\.{group_number}\.\d+v\d+\.*\d*\s*$"
            line_numbers = [
            i
            for i, line in enumerate(md_lines)
            if re.search(id_regex, line)
            ]

            # Read all lines of the individual policy
            for line_number in line_numbers:
                line_advance = 1
                value = md_lines[line_number + line_advance].strip()

                # We're done getting the policy text as soon as we encounter
                # a blank line.
                while md_lines[line_number + line_advance + 1].strip():
                    line_advance += 1
                    value += " " + md_lines[line_number + line_advance].strip()

                value = escape(value)
                line = md_lines[line_number].strip()[5:]

                # Check if policy has been deleted
                deleted = False
                if line.endswith("X"):
                    deleted = True
                    line = line[:-1]
                    value = "[DELETED] " + value

                group["Controls"].append({"Id": line, "Value": value, "Deleted": deleted})

            baseline_output[product].append(group)
    return baseline_output
