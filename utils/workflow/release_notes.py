"""Build categorized release notes for the run_release workflow.

The Build Draft Release workflow calls this module instead of embedding
JavaScript in the workflow file, so the logic can be linted and unit tested.
"""

import argparse
import os
import re
from pathlib import Path
from urllib.parse import quote

import requests

VERSION_PATTERN = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?$", re.IGNORECASE)
BUMP_TITLE_PATTERN = re.compile(r"^Bump ", re.IGNORECASE)
URI_COMPONENT_SAFE = "-_.!~*'()"
COMPARISON_PAGE_SIZE = 100
REQUEST_TIMEOUT_SECONDS = 60

EXCLUDED_LABELS = frozenset({
    "epic",
    "testing",
    "hands-on-prototyping",
    "blocked",
    "duplicate",
    "wontfix",
})
DEPENDENCY_AUTHORS = frozenset({
    "github-actions[bot]",
    "dependabot[bot]",
})
SECTION_ORDER = (
    "Major Changes",
    "Bugs Fixed",
    "Baselines",
    "Documentation",
    "Dependencies",
    "Uncategorized changes",
)
SECTION_FOOTERS = {
    "Major Changes": (
        "enhancements",
        "is:issue is:closed label:enhancement -label:baseline-document "
        "-label:documentation -label:testing -label:hands-on-prototyping "
        "-label:epic",
    ),
    "Bugs Fixed": (
        "bug fixes",
        "is:issue is:closed label:bug -label:baseline-document "
        "-label:testing -label:documentation -label:epic",
    ),
    "Documentation": (
        "documentation updates",
        "state:closed label:documentation",
    ),
}
BASELINE_ISSUES_QUERY = (
    "is:issue is:closed label:baseline-document -label:testing "
    "-label:documentation -label:epic"
)
DEPENDENCY_ISSUES_QUERY = 'is:pr is:merged label:"version bump"'
BOD_CONFIGURATIONS_URL = (
    "https://www.cisa.gov/resources-tools/services/"
    "bod-25-01-implementing-secure-practices-cloud-services-required-configurations"
)
CLOSING_ISSUES_QUERY = """
query ($owner: String!, $repo: String!, $number: Int!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      closingIssuesReferences(first: 20) {
        nodes {
          number
          labels(first: 20) {
            nodes { name }
          }
        }
      }
    }
  }
}
"""


class WorkflowError(Exception):
    """Raised when a release step cannot continue."""


class GitHubRequestError(Exception):
    """Raised when the GitHub API returns an error response."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def parse_version(tag_name: str) -> tuple[int, int, int] | None:
    """Parse a release tag into numeric major, minor, and patch parts.

    :param tag_name: tag such as ``v1.2.3`` or ``1.2``
    :return: version parts, or None when the tag is not a release version
    """
    match = VERSION_PATTERN.fullmatch(tag_name)
    if not match:
        return None
    patch = int(match.group(3) or 0)
    return int(match.group(1)), int(match.group(2)), patch


def compare_versions(
    left: tuple[int, int, int],
    right: tuple[int, int, int],
) -> int:
    """Compare two numeric versions.

    :param left: first version parts
    :param right: second version parts
    :return: negative when left is older, positive when left is newer
    """
    for index in range(3):
        if left[index] != right[index]:
            return left[index] - right[index]
    return 0


def select_previous_release(releases: list[dict], release_version: str) -> dict:
    """Choose the newest published release older than the version being built.

    :param releases: release objects from the GitHub releases API
    :param release_version: version being released, without a leading ``v``
    :return: the selected release object
    :raises WorkflowError: when the version or an older release cannot be found
    """
    current_tag = f"v{release_version}"
    current_version = parse_version(current_tag)
    if current_version is None:
        raise WorkflowError(
            f"Unable to parse release version from tag {current_tag}."
        )

    candidates = []
    for release in releases:
        if release.get("draft") or release.get("prerelease"):
            continue
        tag_name = release.get("tag_name") or ""
        if tag_name.lower() == current_tag.lower():
            continue
        version = parse_version(tag_name)
        if version is None:
            continue
        if compare_versions(version, current_version) < 0:
            candidates.append((version, release))

    candidates.sort(key=lambda item: item[0], reverse=True)
    if not candidates:
        raise WorkflowError(
            f"Unable to find a published release older than {current_tag}."
        )

    selected = candidates[0][1]
    _info(
        f"Using previous tag {selected['tag_name']} "
        f"(published {selected.get('published_at')}) for release notes."
    )
    return selected


def is_dependency_pull_request(pull_request: dict) -> bool:
    """Return whether a pull request is a dependency update.

    :param pull_request: pull request object from the GitHub API
    :return: True for bot authors and titles that start with ``Bump``
    """
    user = pull_request.get("user") or {}
    title = pull_request.get("title") or ""
    return (
        user.get("login") in DEPENDENCY_AUTHORS
        or BUMP_TITLE_PATTERN.match(title) is not None
    )


def pull_request_label_names(pull_request: dict) -> list[str]:
    """Return label names attached directly to a pull request.

    :param pull_request: pull request object from the GitHub API
    :return: label names in API order
    """
    labels = pull_request.get("labels") or []
    return [label["name"] for label in labels]


def has_excluded_label(names: list[str]) -> bool:
    """Return whether any label should omit a pull request from the notes.

    :param names: label names to inspect
    :return: True when an excluded label is present
    """
    return any(name in EXCLUDED_LABELS for name in names)


def section_from_label_names(names: list[str]) -> str | None:
    """Map categorizing labels to a release-note section.

    :param names: label names in priority order
    :return: section title, or None when no categorizing label is present
    """
    if "baseline-document" in names:
        return "Baselines"
    if "documentation" in names:
        return "Documentation"
    if "bug" in names:
        return "Bugs Fixed"
    if "enhancement" in names:
        return "Major Changes"
    return None


def closing_issue_labels_from_response(data: dict) -> tuple[list[int], list[str]]:
    """Read closing-issue numbers and label names from a GraphQL payload.

    :param data: ``data`` object returned by the closing-issues query
    :return: issue numbers and de-duplicated label names in encounter order
    """
    nodes = (
        data["repository"]["pullRequest"]["closingIssuesReferences"]["nodes"]
        or []
    )
    numbers = []
    names = {}
    for issue in nodes:
        numbers.append(issue["number"])
        for label in issue["labels"]["nodes"] or []:
            names.setdefault(label["name"], None)
    return numbers, list(names)


def categorize(client, pull_request: dict) -> str | None:
    """Assign a pull request to a release-note section.

    :param client: GitHub client used to read closing-issue labels
    :param pull_request: merged pull request object
    :return: section title, or None when the pull request is excluded
    """
    number = pull_request["number"]
    data = client.graphql(
        CLOSING_ISSUES_QUERY,
        {
            "owner": client.owner,
            "repo": client.repo,
            "number": number,
        },
    )
    issue_numbers, issue_label_names = closing_issue_labels_from_response(data)
    pull_request_labels = pull_request_label_names(pull_request)
    label_names = issue_label_names
    label_source = "closing issues"

    if len(issue_numbers) == 0:
        label_names = pull_request_labels
        label_source = "pull request"
        if len(pull_request_labels) > 0:
            _info(
                f"PR #{number} has no closing issues; using PR labels "
                f"({', '.join(label_names)})."
            )

    if has_excluded_label(label_names):
        _info(
            f"PR #{number} excluded via {label_source} labels "
            f"({', '.join(label_names)})."
        )
        return None

    if is_dependency_pull_request(pull_request):
        return "Dependencies"

    section = section_from_label_names(label_names)
    if (
        section is None
        and len(issue_numbers) > 0
        and len(pull_request_labels) > 0
        and not has_excluded_label(pull_request_labels)
    ):
        section = section_from_label_names(pull_request_labels)
        if section:
            _info(
                f"PR #{number} categorized from PR labels after closing "
                "issues lacked categorizing labels."
            )

    if section is None:
        joined = ", ".join(label_names) or "none"
        _warning(
            f"PR #{number} could not be categorized from {label_source} "
            f"labels ({joined}); including in Uncategorized changes."
        )
        return "Uncategorized changes"
    return section


def format_pull_request(pull_request: dict) -> str:
    """Format one pull request as a release-note bullet.

    :param pull_request: pull request object from the GitHub API
    :return: markdown bullet
    """
    login = pull_request["user"]["login"]
    title = pull_request["title"]
    number = pull_request["number"]
    return f"* {title} by @{login} in #{number}"


def build_issues_url(owner: str, repo: str, query: str) -> str:
    """Build a GitHub issue-search URL for a release-note footer.

    :param owner: repository owner
    :param repo: repository name
    :param query: issue search query
    :return: encoded issues URL
    """
    encoded = quote(query, safe=URI_COMPONENT_SAFE)
    return f"https://github.com/{owner}/{repo}/issues?q={encoded}"


def _crlf(lines: list[str]) -> str:
    """Join lines with CRLF and include a trailing CRLF."""
    return "\r\n".join(lines) + "\r\n"


def format_section(owner: str, repo: str, title: str, items: list[str]) -> str:
    """Format a standard release-note section.

    :param owner: repository owner
    :param repo: repository name
    :param title: section title
    :param items: formatted pull-request bullets
    :return: section markdown
    """
    lines = [f"## {title}", "", *items]
    footer = SECTION_FOOTERS.get(title)
    if footer:
        link_label, query = footer
        url = build_issues_url(owner, repo, query)
        lines.append(f"* See full list of {link_label} [here]({url})")
    return _crlf(lines)


def format_baselines_section(owner: str, repo: str, items: list[str]) -> str:
    """Format the Baselines section, including BOD 25-01 placeholders.

    :param owner: repository owner
    :param repo: repository name
    :param items: formatted baseline pull-request bullets
    :return: section markdown
    """
    baseline_url = build_issues_url(owner, repo, BASELINE_ISSUES_QUERY)
    intro = (
        "This section lists baseline policy changes that affect current "
        f"[BOD 25-01 Required Configurations]({BOD_CONFIGURATIONS_URL})."
    )
    lines = [
        "## Baselines",
        "",
        "### BOD 25-01 required configuration policy changes",
        "",
        intro,
        "",
        "#### Additions",
        "",
        "No new required configuration policies added in this release.",
        "",
        "#### Removals",
        "",
        "_Move BOD 25-01 policy removals here before publishing._",
        "",
        "#### Updates",
        "",
        "_Move BOD 25-01 policy version updates here before publishing._",
        "",
        "### Other baseline changes",
        "",
    ]
    if items:
        lines.extend(items)
    else:
        lines.append("No baseline updates included in this release.")
    lines.append(f"* See full list of baseline updates [here]({baseline_url})")
    return _crlf(lines)


def format_dependencies_section(owner: str, repo: str, items: list[str]) -> str:
    """Format the Dependencies section.

    :param owner: repository owner
    :param repo: repository name
    :param items: formatted dependency pull-request bullets
    :return: section markdown
    """
    dependency_url = build_issues_url(owner, repo, DEPENDENCY_ISSUES_QUERY)
    lines = ["## Dependencies", ""]
    if items:
        lines.extend(items)
    else:
        lines.append("No dependency updates included in this release.")
    lines.append(
        f"* See full list of dependency updates [here]({dependency_url})"
    )
    return _crlf(lines)


def format_uncategorized_section(items: list[str]) -> str:
    """Format pull requests that could not be categorized.

    :param items: formatted pull-request bullets
    :return: section markdown
    """
    intro = (
        "The following merged pull requests could not be categorized "
        "automatically. Review and move them to the appropriate section "
        "before publishing."
    )
    lines = ["## Uncategorized changes", "", intro, "", *items]
    return _crlf(lines)


def render_section(owner: str, repo: str, title: str, items: list[str]) -> str:
    """Render one release-note section by title.

    :param owner: repository owner
    :param repo: repository name
    :param title: section title
    :param items: formatted pull-request bullets
    :return: section markdown
    """
    if title == "Baselines":
        return format_baselines_section(owner, repo, items)
    if title == "Dependencies":
        return format_dependencies_section(owner, repo, items)
    if title == "Uncategorized changes":
        return format_uncategorized_section(items)
    return format_section(owner, repo, title, items)


def list_comparison_commits(
    client,
    basehead: str,
    per_page: int = COMPARISON_PAGE_SIZE,
) -> tuple[list[dict], bool]:
    """Collect commits from a GitHub compare range.

    :param client: GitHub client
    :param basehead: ``base...head`` comparison range
    :param per_page: page size passed to the compare API
    :return: commits and whether pagination collected fewer than reported
    """
    commits = []
    page = 1
    total_commits = None
    while True:
        comparison = client.compare_commits(basehead, page, per_page)
        if page == 1:
            total_commits = comparison.get("total_commits")
            status = comparison.get("status")
            _info(
                f"Comparing {basehead}: {total_commits} total commits "
                f"(status: {status})."
            )
        page_commits = comparison.get("commits") or []
        commits.extend(page_commits)
        if len(page_commits) < per_page:
            break
        page += 1

    incomplete = (
        isinstance(total_commits, int) and len(commits) < total_commits
    )
    if incomplete:
        _error(
            f"Comparison pagination collected {len(commits)} of "
            f"{total_commits} commits for {basehead}; release notes would "
            "be incomplete."
        )
    _info(
        f"Collected {len(commits)} commits across {page} comparison page(s)."
    )
    return commits, incomplete


def resolve_tag_commit_sha(client, tag_name: str) -> str:
    """Resolve a tag name to the commit SHA it points at.

    :param client: GitHub client
    :param tag_name: tag name without the ``tags/`` prefix
    :return: commit SHA
    """
    ref = client.get_tag_ref(tag_name)
    tagged = ref["object"]
    if tagged["type"] == "commit":
        return tagged["sha"]
    tag = client.get_annotated_tag(tagged["sha"])
    return tag["object"]["sha"]


def resolve_compare_head_ref(
    client,
    current_tag: str,
    compare_head_ref: str,
    sha: str,
) -> str:
    """Choose the head ref used to collect release pull requests.

    :param client: GitHub client
    :param current_tag: tag being released, including the leading ``v``
    :param compare_head_ref: caller-supplied head ref; may be empty
    :param sha: commit SHA of the workflow run
    :return: head ref used in the compare range
    """
    supplied = (compare_head_ref or "").strip()
    if supplied:
        return supplied

    try:
        resolve_tag_commit_sha(client, current_tag)
    except GitHubRequestError as error:
        if error.status != 404:
            raise
    else:
        _info(
            f"Tag {current_tag} already exists; using it as the compare head "
            "for release notes."
        )
        return current_tag

    if not sha:
        raise WorkflowError(
            "GITHUB_SHA is required when the release tag does not exist."
        )
    _info(
        f"Tag {current_tag} does not exist yet (expected before publish). "
        f"Using commit {sha} as the compare head."
    )
    return sha


def list_merged_pull_requests(
    client,
    previous_tag: str,
    current_tag: str,
    compare_head_ref: str,
    sha: str,
) -> tuple[list[dict], str, bool]:
    """List merged pull requests in the release comparison range.

    :param client: GitHub client
    :param previous_tag: tag of the previous published release
    :param current_tag: tag being released
    :param compare_head_ref: optional caller-supplied compare head
    :param sha: commit SHA of the workflow run
    :return: merged pull requests, comparison range, and pagination failure
    """
    head_ref = resolve_compare_head_ref(
        client, current_tag, compare_head_ref, sha
    )
    basehead = f"{previous_tag}...{head_ref}"
    commits, incomplete = list_comparison_commits(client, basehead)
    pull_requests = {}
    for commit in commits:
        for pull_request in client.list_pulls_for_commit(commit["sha"]):
            if pull_request.get("merged_at"):
                pull_requests.setdefault(pull_request["number"], pull_request)

    _info(
        f"Found {len(pull_requests)} pull requests associated with "
        f"commits in {basehead}."
    )
    return list(pull_requests.values()), basehead, incomplete


def build_release_body(
    client,
    *,
    sha: str,
    server_url: str,
    release_version: str,
    previous_tag: str,
    compare_head_ref: str,
) -> tuple[str, bool]:
    """Build the release-note markdown body.

    :param client: GitHub client
    :param sha: commit SHA of the workflow run
    :param server_url: GitHub server URL used in the changelog link
    :param release_version: version being released, without a leading ``v``
    :param previous_tag: previous published release tag
    :param compare_head_ref: optional compare head ref
    :return: markdown body and whether commit pagination was incomplete
    """
    current_tag = f"v{release_version}"
    pull_requests, basehead, incomplete = list_merged_pull_requests(
        client,
        previous_tag,
        current_tag,
        compare_head_ref,
        sha,
    )
    grouped = {title: [] for title in SECTION_ORDER}
    categorized_count = 0
    excluded_count = 0
    for pull_request in pull_requests:
        section = categorize(client, pull_request)
        if section:
            grouped[section].append(format_pull_request(pull_request))
            categorized_count += 1
        else:
            excluded_count += 1

    sections = []
    for title in SECTION_ORDER:
        if title not in ("Baselines", "Dependencies") and not grouped[title]:
            continue
        sections.append(
            render_section(client.owner, client.repo, title, grouped[title])
        )

    compare_url = (
        f"{server_url}/{client.owner}/{client.repo}/compare/{basehead}"
    )
    body = "\r\n".join(sections) + f"\r\n**Full Changelog**: {compare_url}\r\n"

    dependency_count = len(grouped["Dependencies"])
    uncategorized_count = len(grouped["Uncategorized changes"])
    _info(
        f"Release notes include {categorized_count} categorized pull requests "
        f"({dependency_count} in Dependencies, {uncategorized_count} "
        f"uncategorized, {excluded_count} excluded)."
    )
    if uncategorized_count > 0:
        _warning(
            f"{uncategorized_count} pull request(s) were placed in "
            "Uncategorized changes; review and move them before publishing."
        )
    if dependency_count == 0:
        _warning(
            f"No dependency pull requests were linked to commits in "
            f"{basehead}. Cherry-picked changes may need to be added manually."
        )
    return body, incomplete


def write_release_body(body: str, path: Path | None = None) -> Path:
    """Write release notes without changing CRLF line endings.

    :param body: release-note markdown
    :param path: destination file; defaults to ``release-body.md`` in the cwd
    :return: path written
    """
    output = path or Path.cwd() / "release-body.md"
    with output.open("w", encoding="utf-8", newline="") as handle:
        handle.write(body)
    return output


def set_github_output(name: str, value: str) -> None:
    """Append a key=value pair to ``$GITHUB_OUTPUT``.

    Multiline values use the heredoc delimiter syntax. When the variable is
    unset, the value is printed for local runs.

    :param name: output variable name
    :param value: output variable value
    """
    github_output = os.environ.get("GITHUB_OUTPUT")
    if not github_output:
        print(f"  (local) {name}={value}")
        return
    with open(github_output, "a", encoding="utf-8", newline="") as handle:
        if "\n" in value:
            handle.write(f"{name}<<EOFMARKER\n{value}\nEOFMARKER\n")
        else:
            handle.write(f"{name}={value}\n")


class RequestsGitHubClient:
    """GitHub REST and GraphQL client used by the release workflow."""

    def __init__(self, token: str, owner: str, repo: str, api_url: str):
        self.owner = owner
        self.repo = repo
        self.api_url = api_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ScubaGoggles-release-notes",
        })

    @classmethod
    def from_environment(cls):
        """Build a client from GitHub Actions environment variables.

        :return: configured client
        :raises WorkflowError: when the token or repository is missing
        """
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if not token:
            raise WorkflowError(
                "Missing required environment variable GITHUB_TOKEN."
            )
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        owner, separator, repo = repository.partition("/")
        if not separator or not owner or not repo:
            raise WorkflowError("GITHUB_REPOSITORY must be set to owner/repo.")
        api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")
        return cls(token, owner, repo, api_url)

    def list_releases(self) -> list[dict]:
        """Return every release, following GitHub pagination links.

        :return: release objects
        """
        url = f"{self.api_url}/repos/{self.owner}/{self.repo}/releases"
        params = {"per_page": 100}
        releases = []
        while url:
            payload, response = self._request("GET", url, params=params)
            if not isinstance(payload, list):
                raise GitHubRequestError(
                    response.status_code,
                    "GitHub releases API did not return a list.",
                )
            releases.extend(payload)
            url = _next_link(response)
            params = None
        return releases

    def graphql(self, query: str, variables: dict) -> dict:
        """Run a GraphQL query and return its data object.

        :param query: GraphQL query document
        :param variables: query variables
        :return: GraphQL ``data`` object
        """
        payload, _response = self._request(
            "POST",
            f"{self.api_url}/graphql",
            json={"query": query, "variables": variables},
        )
        errors = payload.get("errors") if isinstance(payload, dict) else None
        if errors:
            raise GitHubRequestError(200, f"GitHub GraphQL error: {errors}")
        if not isinstance(payload, dict) or "data" not in payload:
            raise GitHubRequestError(
                200, "GitHub GraphQL response did not include data."
            )
        return payload["data"]

    def compare_commits(self, basehead: str, page: int, per_page: int) -> dict:
        """Compare two refs.

        :param basehead: ``base...head`` comparison range
        :param page: 1-based page number
        :param per_page: number of commits per page
        :return: compare API response
        """
        if "..." not in basehead:
            raise WorkflowError(f"Invalid comparison range {basehead}.")
        base, head = basehead.split("...", 1)
        encoded = (
            f"{quote(base, safe=URI_COMPONENT_SAFE)}..."
            f"{quote(head, safe=URI_COMPONENT_SAFE)}"
        )
        url = (
            f"{self.api_url}/repos/{self.owner}/{self.repo}/compare/{encoded}"
        )
        payload, _response = self._request(
            "GET",
            url,
            params={"page": page, "per_page": per_page},
        )
        if not isinstance(payload, dict):
            raise GitHubRequestError(
                200, "GitHub compare API did not return an object."
            )
        return payload

    def list_pulls_for_commit(self, commit_sha: str) -> list[dict]:
        """Return pull requests associated with a commit.

        :param commit_sha: commit SHA
        :return: pull request objects
        """
        encoded = quote(commit_sha, safe=URI_COMPONENT_SAFE)
        url = (
            f"{self.api_url}/repos/{self.owner}/{self.repo}/commits/"
            f"{encoded}/pulls"
        )
        payload, _response = self._request("GET", url)
        if not isinstance(payload, list):
            raise GitHubRequestError(
                200,
                "GitHub commit pull requests API did not return a list.",
            )
        return payload

    def get_tag_ref(self, tag_name: str) -> dict:
        """Return the git ref for a tag.

        :param tag_name: tag name without the ``tags/`` prefix
        :return: git ref object
        """
        encoded = quote(tag_name, safe=URI_COMPONENT_SAFE)
        url = (
            f"{self.api_url}/repos/{self.owner}/{self.repo}/git/ref/tags/"
            f"{encoded}"
        )
        payload, _response = self._request("GET", url)
        if not isinstance(payload, dict):
            raise GitHubRequestError(200, "GitHub ref API did not return an object.")
        return payload

    def get_annotated_tag(self, tag_sha: str) -> dict:
        """Return an annotated tag object.

        :param tag_sha: tag object SHA
        :return: annotated tag object
        """
        encoded = quote(tag_sha, safe=URI_COMPONENT_SAFE)
        url = (
            f"{self.api_url}/repos/{self.owner}/{self.repo}/git/tags/{encoded}"
        )
        payload, _response = self._request("GET", url)
        if not isinstance(payload, dict):
            raise GitHubRequestError(200, "GitHub tag API did not return an object.")
        return payload

    def _request(self, method: str, url: str, **kwargs):
        """Perform an HTTP request and return the JSON payload and response.

        :param method: HTTP method
        :param url: request URL
        :return: parsed JSON payload and the response
        """
        response = self.session.request(
            method,
            url,
            timeout=REQUEST_TIMEOUT_SECONDS,
            **kwargs,
        )
        if response.status_code >= 400:
            detail = response.text.strip().replace("\n", " ")
            if len(detail) > 300:
                detail = detail[:300] + "..."
            raise GitHubRequestError(
                response.status_code,
                f"GitHub API {method} {url} failed with "
                f"{response.status_code}: {detail}",
            )
        if not response.content:
            return None, response
        try:
            payload = response.json()
        except ValueError as error:
            raise GitHubRequestError(
                response.status_code,
                "GitHub API returned a non-JSON response.",
            ) from error
        return payload, response


def _next_link(response) -> str | None:
    """Return the ``rel=next`` URL from a GitHub Link header."""
    link_header = response.headers.get("Link")
    if not link_header:
        return None
    for part in link_header.split(","):
        section, _, relation = part.partition(";")
        if 'rel="next"' in relation:
            return section.strip().strip("<>").strip()
    return None


def _escape_workflow_message(message: str) -> str:
    """Escape characters that break GitHub workflow commands."""
    return (
        message.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


def _info(message: str) -> None:
    """Print a workflow log line."""
    print(message)


def _warning(message: str) -> None:
    """Print a GitHub Actions warning annotation."""
    print(f"::warning::{_escape_workflow_message(message)}")


def _error(message: str) -> None:
    """Print a GitHub Actions error annotation."""
    print(f"::error::{_escape_workflow_message(message)}")


def _require_env(name: str) -> str:
    """Return an environment variable or raise WorkflowError."""
    value = os.environ.get(name)
    if value is None or value == "":
        raise WorkflowError(f"Missing required environment variable {name}.")
    return value


def _server_url() -> str:
    """Return the GitHub server URL, without a trailing slash."""
    return os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")


def main(argv: list[str] | None = None, client=None) -> int:
    """Run a release-note subcommand.

    :param argv: argument list; defaults to the process arguments
    :param client: GitHub client; defaults to one built from the environment
    :return: process exit code
    """
    parser = argparse.ArgumentParser(
        description="Release note helpers for the run_release workflow."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "previous-tag",
        help="Write the previous published release tag to GITHUB_OUTPUT.",
    )
    subparsers.add_parser(
        "generate",
        help="Write categorized release notes to release-body.md.",
    )
    args = parser.parse_args(argv)

    try:
        active_client = client or RequestsGitHubClient.from_environment()
        if args.command == "previous-tag":
            release_version = _require_env("RELEASE_VERSION")
            selected = select_previous_release(
                active_client.list_releases(),
                release_version,
            )
            set_github_output("tag", selected["tag_name"])
            return 0

        release_version = _require_env("RELEASE_VERSION")
        previous_tag = _require_env("PREVIOUS_RELEASE_TAG")
        body, incomplete = build_release_body(
            active_client,
            sha=os.environ.get("GITHUB_SHA", ""),
            server_url=_server_url(),
            release_version=release_version,
            previous_tag=previous_tag,
            compare_head_ref=os.environ.get("COMPARE_HEAD_REF", ""),
        )
        write_release_body(body)
        return 1 if incomplete else 0
    except (WorkflowError, GitHubRequestError) as error:
        _error(str(error))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
