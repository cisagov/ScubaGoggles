"""Utility functions for automating OPA version dependency management.

Used by the run_update_opa GitHub Actions workflow to check for new OPA
releases, update the pinned version in scuba_constants.py, and create a
pull request with the change.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCUBA_CONSTANTS_PATH = REPO_ROOT / "scubagoggles" / "scuba_constants.py"
OPA_RELEASES_API = "https://api.github.com/repos/open-policy-agent/opa/releases/latest"
OPA_VERSION_PATTERN = re.compile(r"^OPA_VERSION\s*=\s*['\"]v([\d.]+)['\"]", re.MULTILINE)


def get_current_opa_version() -> str:
    """Read the current OPA_VERSION from scuba_constants.py.

    :return: current OPA version string without the 'v' prefix (e.g. '1.13.1')
    """
    contents = SCUBA_CONSTANTS_PATH.read_text(encoding="utf-8")
    match = OPA_VERSION_PATTERN.search(contents)
    if not match:
        raise RuntimeError(
            f"Could not find OPA_VERSION in {SCUBA_CONSTANTS_PATH}"
        )
    return match.group(1)


def get_latest_opa_version() -> str:
    """Query the OPA GitHub releases API for the latest version.

    :return: latest OPA version string without the 'v' prefix (e.g. '1.14.0')
    """
    request = Request(OPA_RELEASES_API)
    request.add_header("Accept", "application/vnd.github+json")
    with urlopen(request) as response:
        data = json.loads(response.read().decode("utf-8"))
    tag = data["tag_name"]
    return tag.lstrip("v")


def check_branch_exists(branch_name: str) -> bool:
    """Check whether a remote branch already exists.

    :param branch_name: the branch name to check
    :return: True if the remote branch exists
    """
    result = subprocess.run(
        ["git", "ls-remote", "--exit-code", "--heads", "origin", branch_name],
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def confirm_update_required() -> dict:
    """Determine whether an OPA version bump is needed.

    :return: dict with keys 'update_required', 'current_version',
             'latest_version', and 'branch_name'
    """
    current = get_current_opa_version()
    latest = get_latest_opa_version()
    branch_name = f"opa-version-bump-{latest}"

    current_parts = tuple(int(x) for x in current.split("."))
    latest_parts = tuple(int(x) for x in latest.split("."))

    update_required = False
    summary = ""

    if latest_parts > current_parts:
        if not check_branch_exists(branch_name):
            update_required = True
            summary = "OPA version update required."
        else:
            summary = (
                f"Update branch ({branch_name}) already exists; "
                "no update required."
            )
    else:
        summary = "OPA version is already up to date; no update required."

    print(summary)
    return {
        "update_required": update_required,
        "current_version": current,
        "latest_version": latest,
        "branch_name": branch_name,
    }


def update_opa_version(current_version: str, latest_version: str) -> None:
    """Update OPA_VERSION in scuba_constants.py.

    :param current_version: the old version string (without 'v' prefix)
    :param latest_version: the new version string (without 'v' prefix)
    """
    contents = SCUBA_CONSTANTS_PATH.read_text(encoding="utf-8")
    old_value = f"OPA_VERSION = 'v{current_version}'"
    new_value = f"OPA_VERSION = 'v{latest_version}'"

    if old_value not in contents:
        raise RuntimeError(
            f"Could not find '{old_value}' in {SCUBA_CONSTANTS_PATH}"
        )

    updated = contents.replace(old_value, new_value, 1)
    SCUBA_CONSTANTS_PATH.write_text(updated, encoding="utf-8")
    print(f"Updated OPA_VERSION from v{current_version} to v{latest_version}")


def update_opa_docs(latest_version: str) -> None:
    """Update OPA version references in documentation files.

    :param latest_version: the new version string (without 'v' prefix)
    """
    docs_path = REPO_ROOT / "docs" / "installation" / "OPA.md"
    if not docs_path.exists():
        print(f"Warning: {docs_path} not found, skipping docs update")
        return

    contents = docs_path.read_text(encoding="utf-8")
    version_re = re.compile(r"v\d+\.\d+\.\d+")
    updated = version_re.sub(f"v{latest_version}", contents)
    docs_path.write_text(updated, encoding="utf-8")
    print(f"Updated OPA version references in {docs_path}")


def _parse_test_summary(output: str) -> str:
    """Parse OPA verbose test output into a per-baseline summary.

    Expects lines like ``data.<package>.<test_name>: PASS (1.234ms)``.

    :param output: raw stdout from ``opa test -v``
    :return: formatted summary string
    """
    result_re = re.compile(r"data\.(\w+)\.[^:]+:\s+(PASS|FAIL)")
    counts: dict[str, dict[str, int]] = {}

    for match in result_re.finditer(output):
        package = match.group(1).capitalize()
        status = match.group(2)
        if package not in counts:
            counts[package] = {"PASS": 0, "FAIL": 0}
        counts[package][status] += 1

    if not counts:
        return "No test results parsed."

    lines = []
    total_pass = 0
    total_fail = 0
    for package in sorted(counts):
        passed = counts[package]["PASS"]
        failed = counts[package]["FAIL"]
        total = passed + failed
        total_pass += passed
        total_fail += failed
        status = "PASS" if failed == 0 else "FAIL"
        lines.append(
            f"======== Testing {package} ======== {status}: {passed}/{total}"
        )

    overall = f"Total: {total_pass}/{total_pass + total_fail} passed"
    if total_fail:
        overall += f", {total_fail} failed"
    lines.append(overall)
    return "\n".join(lines)


def run_rego_unit_tests() -> str:
    """Run the OPA Rego unit tests, exiting non-zero on failure.

    Uses `opa test` directly (requires OPA on PATH, e.g. via
    open-policy-agent/setup-opa).

    :return: formatted test summary string
    """
    rego_dir = REPO_ROOT / "scubagoggles" / "rego"
    test_dir = REPO_ROOT / "scubagoggles" / "Testing" / "Unit" / "Rego"

    rego_files = list(rego_dir.glob("*.rego"))
    test_files = list(test_dir.rglob("*.rego"))

    cmd = ["opa", "test", "-v"] + [str(f) for f in rego_files + test_files]
    print(f"Running: opa test -v ({len(rego_files)} rego + {len(test_files)} test files)")

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if result.returncode != 0:
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        print(f"OPA unit tests failed (exit code {result.returncode})")
        sys.exit(result.returncode)

    summary = _parse_test_summary(result.stdout)
    print(summary)
    return summary


def set_github_output(name: str, value: str) -> None:
    """Append a key=value pair to $GITHUB_OUTPUT for use in subsequent steps.

    Handles multiline values using the heredoc delimiter syntax.

    :param name: output variable name
    :param value: output variable value
    """
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as f:
            if "\n" in value:
                f.write(f"{name}<<EOFMARKER\n{value}\nEOFMARKER\n")
            else:
                f.write(f"{name}={value}\n")
    else:
        print(f"  (local) {name}={value}")


def main():
    """Parse arguments and dispatch to the appropriate subcommand."""
    parser = argparse.ArgumentParser(
        description="OPA version dependency management helpers"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "check",
        help="Check if an OPA version update is required",
    )

    update_parser = subparsers.add_parser(
        "update",
        help="Update OPA_VERSION in scuba_constants.py",
    )
    update_parser.add_argument("--current", required=True)
    update_parser.add_argument("--latest", required=True)

    update_docs_parser = subparsers.add_parser(
        "update-docs",
        help="Update OPA version references in docs",
    )
    update_docs_parser.add_argument("--latest", required=True)

    subparsers.add_parser(
        "test",
        help="Run OPA Rego unit tests",
    )

    args = parser.parse_args()

    if args.command == "check":
        result = confirm_update_required()
        set_github_output("update_required", str(result["update_required"]).lower())
        set_github_output("current_version", result["current_version"])
        set_github_output("latest_version", result["latest_version"])
        set_github_output("branch_name", result["branch_name"])

    elif args.command == "update":
        update_opa_version(args.current, args.latest)

    elif args.command == "update-docs":
        update_opa_docs(args.latest)

    elif args.command == "test":
        summary = run_rego_unit_tests()
        set_github_output("test_summary", summary)


if __name__ == "__main__":
    main()
