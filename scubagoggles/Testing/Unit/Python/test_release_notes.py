"""Unit tests for release note generation used by the run_release workflow."""

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = REPO_ROOT / "utils" / "workflow" / "release_notes.py"
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "run_release.yml"


def _load_release_notes():
    """Load the workflow helper, which is not part of the installable package."""
    spec = importlib.util.spec_from_file_location("release_notes", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release_notes = _load_release_notes()


def _crlf(lines):
    """Join lines the same way the release notes do."""
    return "\r\n".join(lines) + "\r\n"


def _pull_request(number, title, login, labels, merged="2026-01-01T00:00:00Z"):
    """Build a pull request object with the fields the generator reads."""
    return {
        "number": number,
        "title": title,
        "user": {"login": login},
        "labels": [{"name": name} for name in labels],
        "merged_at": merged,
    }


class FakeGitHub:
    """In-memory GitHub client for release-note tests."""

    def __init__(self):
        self.owner = "cisagov"
        self.repo = "ScubaGoggles"
        self.releases = []
        self.closing_issues = {}
        self.pulls_by_sha = {}
        self.comparison = {
            "total_commits": 0,
            "status": "identical",
            "commits": [],
        }
        self.comparison_pages = None
        self.refs = {}
        self.annotated = {}

    def list_releases(self):
        """Return the configured releases."""
        return self.releases

    def graphql(self, _query, variables):
        """Return closing issues configured for a pull request."""
        issues = self.closing_issues.get(variables["number"], [])
        nodes = [
            {
                "number": issue["number"],
                "labels": {
                    "nodes": [{"name": name} for name in issue["labels"]],
                },
            }
            for issue in issues
        ]
        return {
            "repository": {
                "pullRequest": {
                    "closingIssuesReferences": {"nodes": nodes},
                },
            },
        }

    def compare_commits(self, _basehead, page, _per_page):
        """Return one compare page."""
        if self.comparison_pages is not None:
            return self.comparison_pages[page]
        return self.comparison

    def list_pulls_for_commit(self, commit_sha):
        """Return pull requests configured for a commit."""
        return self.pulls_by_sha.get(commit_sha, [])

    def get_tag_ref(self, tag_name):
        """Return a configured tag ref, or a 404 error."""
        if tag_name not in self.refs:
            raise release_notes.GitHubRequestError(404, "missing")
        value = self.refs[tag_name]
        if isinstance(value, Exception):
            raise value
        return value

    def get_annotated_tag(self, tag_sha):
        """Return a configured annotated tag object."""
        return self.annotated[tag_sha]


def _response(mocker, status, payload, headers=None, text=""):
    """Build a mocked requests response."""
    response = mocker.Mock()
    response.status_code = status
    response.content = b"" if payload is None else b"{}"
    response.headers = headers or {}
    response.text = text
    response.json.return_value = payload
    return response


def test_parse_version_accepts_release_tags():
    """Release tags parse to numeric parts, with a missing patch treated as zero."""
    assert release_notes.parse_version("v1.2.3") == (1, 2, 3)
    assert release_notes.parse_version("V1.02.03") == (1, 2, 3)
    assert release_notes.parse_version("1.2") == (1, 2, 0)
    assert release_notes.parse_version("v1") is None
    assert release_notes.parse_version("v1.2.3-rc1") is None
    assert release_notes.parse_version("nightly") is None


def test_compare_versions_is_numeric():
    """Minor version 10 sorts after minor version 9."""
    assert release_notes.compare_versions((1, 10, 0), (1, 9, 0)) > 0
    assert release_notes.compare_versions((1, 2, 0), (1, 2, 0)) == 0
    assert release_notes.compare_versions((1, 2, 3), (1, 2, 10)) < 0


def test_select_previous_release_skips_unpublished_and_newer_tags():
    """The previous tag is the newest published release older than the current one."""
    releases = [
        {"tag_name": "v1.11.0", "draft": False, "prerelease": False,
         "published_at": "2026-06-01"},
        {"tag_name": "v1.10.0", "draft": False, "prerelease": False,
         "published_at": "2026-05-01"},
        {"tag_name": "V1.10.0", "draft": False, "prerelease": False,
         "published_at": "2026-05-01"},
        {"tag_name": "v1.9.0", "draft": False, "prerelease": False,
         "published_at": "2026-04-01"},
        {"tag_name": "v1.2.0", "draft": False, "prerelease": False,
         "published_at": "2026-01-01"},
        {"tag_name": "v1.8.0", "draft": True, "prerelease": False,
         "published_at": None},
        {"tag_name": "v1.7.0", "draft": False, "prerelease": True,
         "published_at": "2026-03-01"},
        {"tag_name": "nightly", "draft": False, "prerelease": False,
         "published_at": "2026-02-01"},
    ]

    selected = release_notes.select_previous_release(releases, "1.10.0")

    assert selected["tag_name"] == "v1.9.0"


def test_select_previous_release_keeps_api_order_for_equal_versions():
    """Equal numeric versions stay in the order the API returned them."""
    releases = [
        {"tag_name": "v1.9", "draft": False, "prerelease": False,
         "published_at": "first"},
        {"tag_name": "v1.9.0", "draft": False, "prerelease": False,
         "published_at": "second"},
    ]

    selected = release_notes.select_previous_release(releases, "1.10.0")

    assert selected["tag_name"] == "v1.9"


def test_select_previous_release_reports_missing_inputs():
    """Missing versions and missing older releases fail the step."""
    with pytest.raises(release_notes.WorkflowError, match="Unable to parse"):
        release_notes.select_previous_release([], "nope")
    with pytest.raises(release_notes.WorkflowError, match="older than v1.2.0"):
        release_notes.select_previous_release([], "1.2.0")


def test_section_priority_prefers_baseline_over_bug():
    """Baseline labels take priority over other categorizing labels."""
    names = ["bug", "baseline-document", "enhancement"]
    assert release_notes.section_from_label_names(names) == "Baselines"
    assert release_notes.section_from_label_names(
        ["documentation", "enhancement"]
    ) == "Documentation"


def test_build_issues_url_matches_encode_uri_component():
    """Issue footer queries use the same encoding as the previous workflow."""
    owner = "cisagov"
    repo = "ScubaGoggles"
    documentation = release_notes.build_issues_url(
        owner,
        repo,
        "state:closed label:documentation",
    )
    dependency = release_notes.build_issues_url(
        owner,
        repo,
        'is:pr is:merged label:"version bump"',
    )

    assert documentation.endswith(
        "issues?q=state%3Aclosed%20label%3Adocumentation"
    )
    assert dependency.endswith(
        "issues?q=is%3Apr%20is%3Amerged%20label%3A%22version%20bump%22"
    )


def test_categorize_uses_closing_issue_labels_and_exclusions():
    """Closing-issue labels categorize a pull request and can exclude it."""
    client = FakeGitHub()
    client.closing_issues[10] = [{"number": 100, "labels": ["enhancement"]}]
    client.closing_issues[16] = [{"number": 160, "labels": ["duplicate"]}]
    enhancement = _pull_request(10, "Add the widget", "alice", ["bug"])
    excluded = _pull_request(16, "Duplicate work", "gina", ["enhancement"])

    assert release_notes.categorize(client, enhancement) == "Major Changes"
    assert release_notes.categorize(client, excluded) is None


def test_categorize_dependency_wins_over_feature_labels():
    """Dependency authors are listed under Dependencies even with other labels."""
    client = FakeGitHub()
    client.closing_issues[13] = [{"number": 130, "labels": ["enhancement"]}]
    pull_request = _pull_request(
        13, "Update lockfile", "dependabot[bot]", ["enhancement"]
    )

    assert release_notes.categorize(client, pull_request) == "Dependencies"


def test_categorize_falls_back_to_pull_request_labels():
    """Pull request labels are used when there is no closing issue."""
    client = FakeGitHub()
    pull_request = _pull_request(11, "Fix the crash", "bob", ["bug"])

    assert release_notes.categorize(client, pull_request) == "Bugs Fixed"


def test_categorize_uses_pull_request_labels_when_issues_are_unclear(capsys):
    """Uncategorized closing issues fall back to pull request labels."""
    client = FakeGitHub()
    client.closing_issues[20] = [{"number": 200, "labels": ["question"]}]
    pull_request = _pull_request(20, "Fix the crash", "bob", ["bug"])

    assert release_notes.categorize(client, pull_request) == "Bugs Fixed"

    output = capsys.readouterr().out
    assert "categorized from PR labels" in output


def test_categorize_excluded_pull_request_labels_do_not_fall_back(capsys):
    """Excluded pull request labels do not override unclear closing issues."""
    client = FakeGitHub()
    client.closing_issues[21] = [{"number": 210, "labels": ["question"]}]
    pull_request = _pull_request(21, "Prototype", "bob", ["testing"])

    assert release_notes.categorize(client, pull_request) == (
        "Uncategorized changes"
    )

    output = capsys.readouterr().out
    assert "labels (question)" in output
    assert "pull request" not in output.split("could not be categorized")[0]


def test_resolve_compare_head_ref_prefers_an_explicit_ref():
    """A caller-supplied compare head is trimmed and used as-is."""
    client = FakeGitHub()

    head = release_notes.resolve_compare_head_ref(
        client, "v1.2.0", "  release/1.2.0  ", "abcdef"
    )

    assert head == "release/1.2.0"


def test_resolve_compare_head_ref_uses_existing_annotated_tag():
    """An existing annotated tag is used as the compare head."""
    client = FakeGitHub()
    client.refs["v1.2.0"] = {"object": {"type": "tag", "sha": "tagsha"}}
    client.annotated["tagsha"] = {"object": {"sha": "commitsha"}}

    head = release_notes.resolve_compare_head_ref(client, "v1.2.0", "", "abcdef")

    assert head == "v1.2.0"


def test_resolve_compare_head_ref_uses_commit_sha_when_tag_is_missing():
    """A tag that has not been published yet falls back to the workflow SHA."""
    client = FakeGitHub()

    head = release_notes.resolve_compare_head_ref(
        client, "v1.2.0", "", "abcdef"
    )

    assert head == "abcdef"


def test_resolve_compare_head_ref_requires_sha_when_tag_is_missing():
    """The SHA fallback fails clearly when the workflow SHA is missing."""
    client = FakeGitHub()

    with pytest.raises(release_notes.WorkflowError, match="GITHUB_SHA"):
        release_notes.resolve_compare_head_ref(client, "v1.2.0", "", "")


def test_resolve_compare_head_ref_reraises_non_404(capsys):
    """Errors other than a missing tag are not treated as 'not published yet'."""
    client = FakeGitHub()
    client.refs["v1.2.0"] = release_notes.GitHubRequestError(500, "boom")

    with pytest.raises(release_notes.GitHubRequestError) as caught:
        release_notes.resolve_compare_head_ref(client, "v1.2.0", "", "abcdef")

    assert caught.value.status == 500
    capsys.readouterr()


def test_list_comparison_commits_stops_after_a_short_page():
    """Comparison pages are followed until a short page, including an empty one."""
    client = FakeGitHub()
    client.comparison_pages = {
        1: {
            "total_commits": 2,
            "status": "ahead",
            "commits": [{"sha": "c1"}],
        },
        2: {
            "total_commits": 2,
            "status": "ahead",
            "commits": [{"sha": "c2"}],
        },
        3: {
            "total_commits": 2,
            "status": "ahead",
            "commits": [],
        },
    }

    commits, incomplete = release_notes.list_comparison_commits(
        client, "v1.1.0...abcdef", per_page=1
    )

    assert [commit["sha"] for commit in commits] == ["c1", "c2"]
    assert incomplete is False


def test_list_comparison_commits_flags_a_short_collection():
    """A compare response that omits commits fails the step after collecting."""
    client = FakeGitHub()
    client.comparison = {
        "total_commits": 5,
        "status": "ahead",
        "commits": [{"sha": "c1"}],
    }

    commits, incomplete = release_notes.list_comparison_commits(
        client, "v1.1.0...abcdef"
    )

    assert len(commits) == 1
    assert incomplete is True


def test_build_release_body_categorizes_merged_pull_requests():
    """Merged pull requests are grouped, de-duplicated, and written as CRLF."""
    client = FakeGitHub()
    client.comparison = {
        "total_commits": 2,
        "status": "ahead",
        "commits": [{"sha": "c1"}, {"sha": "c2"}],
    }
    client.pulls_by_sha["c1"] = [
        _pull_request(10, "Add the widget", "alice", ["enhancement"]),
        _pull_request(11, "Fix the crash", "bob", ["bug"]),
        _pull_request(12, "Update baseline doc", "cara", []),
        _pull_request(13, "Bump wheel from 1 to 2", "dave", []),
        _pull_request(14, "Ignored draft", "eve", ["enhancement"], merged=None),
        _pull_request(15, "Mystery change", "frank", []),
        _pull_request(16, "Duplicate work", "gina", ["enhancement"]),
    ]
    client.pulls_by_sha["c2"] = [
        _pull_request(10, "Add the widget", "alice", ["enhancement"]),
    ]
    client.closing_issues[10] = [{"number": 100, "labels": ["enhancement"]}]
    client.closing_issues[12] = [{"number": 120, "labels": ["baseline-document"]}]
    client.closing_issues[15] = [{"number": 150, "labels": ["question"]}]
    client.closing_issues[16] = [{"number": 160, "labels": ["duplicate"]}]

    body, incomplete = release_notes.build_release_body(
        client,
        sha="abcdef1234567890",
        server_url="https://github.com",
        release_version="1.2.0",
        previous_tag="v1.1.0",
        compare_head_ref="",
    )

    owner = "cisagov"
    repo = "ScubaGoggles"
    enhancement_url = release_notes.build_issues_url(
        owner, repo, release_notes.SECTION_FOOTERS["Major Changes"][1]
    )
    bug_url = release_notes.build_issues_url(
        owner, repo, release_notes.SECTION_FOOTERS["Bugs Fixed"][1]
    )
    baseline_url = release_notes.build_issues_url(
        owner, repo, release_notes.BASELINE_ISSUES_QUERY
    )
    dependency_url = release_notes.build_issues_url(
        owner, repo, release_notes.DEPENDENCY_ISSUES_QUERY
    )
    expected = "\r\n".join([
        _crlf([
            "## Major Changes",
            "",
            "* Add the widget by @alice in #10",
            f"* See full list of enhancements [here]({enhancement_url})",
        ]),
        _crlf([
            "## Bugs Fixed",
            "",
            "* Fix the crash by @bob in #11",
            f"* See full list of bug fixes [here]({bug_url})",
        ]),
        _crlf([
            "## Baselines",
            "",
            "### BOD 25-01 required configuration policy changes",
            "",
            "This section lists baseline policy changes that affect current "
            "[BOD 25-01 Required Configurations]"
            f"({release_notes.BOD_CONFIGURATIONS_URL}).",
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
            "* Update baseline doc by @cara in #12",
            f"* See full list of baseline updates [here]({baseline_url})",
        ]),
        _crlf([
            "## Dependencies",
            "",
            "* Bump wheel from 1 to 2 by @dave in #13",
            f"* See full list of dependency updates [here]({dependency_url})",
        ]),
        _crlf([
            "## Uncategorized changes",
            "",
            "The following merged pull requests could not be categorized "
            "automatically. Review and move them to the appropriate section "
            "before publishing.",
            "",
            "* Mystery change by @frank in #15",
        ]),
    ]) + (
        "\r\n**Full Changelog**: https://github.com/cisagov/ScubaGoggles/"
        "compare/v1.1.0...abcdef1234567890\r\n"
    )

    assert incomplete is False
    assert body == expected
    assert "Ignored draft" not in body
    assert body.count("Add the widget") == 1


def test_generate_command_writes_release_body(tmp_path, monkeypatch):
    """The generate command writes release-body.md and returns zero on success."""
    client = FakeGitHub()
    client.refs["v1.2.0"] = {"object": {"type": "commit", "sha": "abc"}}
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RELEASE_VERSION", "1.2.0")
    monkeypatch.setenv("PREVIOUS_RELEASE_TAG", "v1.1.0")
    monkeypatch.setenv("COMPARE_HEAD_REF", "main")
    monkeypatch.setenv("GITHUB_SHA", "abcdef")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")

    exit_code = release_notes.main(["generate"], client=client)

    body = (tmp_path / "release-body.md").read_bytes()
    assert exit_code == 0
    assert b"\r\n" in body
    assert b"\r\r\n" not in body
    changelog = (
        b"**Full Changelog**: https://github.com/cisagov/ScubaGoggles/"
        b"compare/v1.1.0...main\r\n"
    )
    assert changelog in body
    assert b"## Baselines\r\n" in body
    assert b"## Dependencies\r\n" in body


def test_generate_command_fails_when_pagination_is_incomplete(tmp_path, monkeypatch):
    """Incomplete commit pagination still writes notes and fails the step."""
    client = FakeGitHub()
    client.comparison = {
        "total_commits": 5,
        "status": "ahead",
        "commits": [{"sha": "c1"}],
    }
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RELEASE_VERSION", "1.2.0")
    monkeypatch.setenv("PREVIOUS_RELEASE_TAG", "v1.1.0")
    monkeypatch.setenv("COMPARE_HEAD_REF", "main")

    exit_code = release_notes.main(["generate"], client=client)

    assert exit_code == 1
    assert (tmp_path / "release-body.md").exists()


def test_previous_tag_command_writes_github_output(tmp_path, monkeypatch):
    """The previous-tag command publishes the selected tag for later steps."""
    client = FakeGitHub()
    client.releases = [
        {"tag_name": "v1.1.0", "draft": False, "prerelease": False,
         "published_at": "2026-04-01"},
        {"tag_name": "v1.0.0", "draft": False, "prerelease": False,
         "published_at": "2026-01-01"},
    ]
    output = tmp_path / "github-output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("RELEASE_VERSION", "1.2.0")

    exit_code = release_notes.main(["previous-tag"], client=client)

    assert exit_code == 0
    assert output.read_text(encoding="utf-8") == "tag=v1.1.0\n"


def test_missing_token_fails_without_calling_github(monkeypatch, capsys):
    """A missing token fails the step before any API call."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    exit_code = release_notes.main(["previous-tag"])

    assert exit_code == 1
    assert "GITHUB_TOKEN" in capsys.readouterr().out


def test_requests_client_paginates_releases(mocker):
    """Release listing follows the GitHub Link header."""
    client = release_notes.RequestsGitHubClient(
        "token", "cisagov", "ScubaGoggles", "https://api.github.com"
    )
    first = _response(
        mocker,
        200,
        [{"tag_name": "v1.0.0"}],
        headers={
            "Link": '<https://api.github.com/repos/cisagov/ScubaGoggles/'
                    'releases?page=2>; rel="next"',
        },
    )
    second = _response(mocker, 200, [{"tag_name": "v0.9.0"}])
    request = mocker.patch.object(
        client.session, "request", side_effect=[first, second]
    )

    assert client.list_releases() == [
        {"tag_name": "v1.0.0"},
        {"tag_name": "v0.9.0"},
    ]
    assert request.call_args_list[1].args[1].endswith("releases?page=2")


def test_requests_client_encodes_compare_refs(mocker):
    """Compare URLs encode each ref and keep the three-dot separator."""
    client = release_notes.RequestsGitHubClient(
        "token", "cisagov", "ScubaGoggles", "https://api.github.com"
    )
    response = _response(mocker, 200, {"commits": [], "total_commits": 0})
    request = mocker.patch.object(client.session, "request", return_value=response)

    client.compare_commits("v1.0.0...release/1.2.0", 2, 100)

    url = request.call_args.args[1]
    assert url.endswith("/compare/v1.0.0...release%2F1.2.0")
    assert request.call_args.kwargs["params"] == {"page": 2, "per_page": 100}


def test_requests_client_raises_status_and_graphql_errors(mocker):
    """HTTP and GraphQL errors surface as GitHubRequestError."""
    client = release_notes.RequestsGitHubClient(
        "token", "cisagov", "ScubaGoggles", "https://api.github.com"
    )
    missing = _response(mocker, 404, {"message": "Not Found"}, text="Not Found")
    mocker.patch.object(client.session, "request", return_value=missing)
    with pytest.raises(release_notes.GitHubRequestError) as caught:
        client.get_tag_ref("v9.9.9")
    assert caught.value.status == 404

    graphql = _response(mocker, 200, {"errors": [{"message": "nope"}]})
    mocker.patch.object(client.session, "request", return_value=graphql)
    with pytest.raises(release_notes.GitHubRequestError, match="GraphQL"):
        client.graphql("query { viewer { login } }", {})


def test_run_release_workflow_calls_script_instead_of_inline_javascript():
    """The release workflow delegates note generation to the linted helper."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "python utils/workflow/release_notes.py previous-tag" in workflow
    assert "python utils/workflow/release_notes.py generate" in workflow
    assert "actions/github-script" not in workflow
