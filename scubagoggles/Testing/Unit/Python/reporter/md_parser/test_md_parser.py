"""
test_md_parser.py tests the MarkdownParser class.
"""
from pathlib import Path
import re
import pytest

import scubagoggles as scubagoggles_pkg
from scubagoggles.reporter.md_parser import MarkdownParser, MarkdownParserError

class TestMarkdownParser:
    """Unit tests for the MarkdownParser class."""
    def _baselines_directory(self) -> Path:
        return Path(scubagoggles_pkg.__file__).resolve().parent / "baselines"

    def _snippets_directory(self) -> Path:
        return Path(__file__).parent / "snippets"

    def _parser(self, base_dir: Path) -> MarkdownParser:
        return MarkdownParser(base_dir)

    def test_parse_baselines_returns_correct_format(self):
        """
        Tests the MarkdownParser.parse_baselines() public method for expected output structure.
        """
        parser = self._parser(self._baselines_directory())
        result = parser.parse_baselines(["gmail"])

        assert isinstance(result, dict)
        assert "gmail" in result

        groups = result["gmail"]
        assert isinstance(groups, list)
        assert len(groups) >= 1

        id_pattern = re.compile(r"^GWS\.GMAIL\.\d+\.\d+v\d+(?:\.\d+)*$")

        for group in groups:
            assert { "GroupNumber", "GroupName", "Controls" }.issubset(group.keys())
            assert isinstance(group["GroupNumber"], str) and group["GroupNumber"].strip() != ""
            assert isinstance(group["GroupName"], str)

            controls = group["Controls"]
            assert isinstance(controls, list)
            assert len(controls) >= 1

            for control in controls:
                assert { "Id", "Value"}.issubset(control.keys())
                assert isinstance(control["Id"], str)
                assert isinstance(control["Value"], str)

                # Check against empty values
                assert control["Id"].strip() != ""
                assert control["Value"].strip() != ""

                # Confirm policy ID format
                assert id_pattern.match(control["Id"]), f"Invalid Policy ID format: {control['Id']}"

    @pytest.mark.parametrize(
        ("snippet_name", "expected_fragment"),
        [
            (
                "missing_policies_section",
                '"Policies" section missing for group id 1 (Mail Delegation)'
            ),
            (
                "product_mismatch",
                (
                    "different product encountered calendar != product_mismatch "
                    "for group id 1 (External Sharing Options)"
                )
            ),
            (
                "group_mismatch",
                "mismatching group number (2) for group id 1 (External Sharing Options)"
            ),
            (
                "duplicate_policy_id",
                "expected baseline item 2, got item 1 for group id 1 (Example Group)"
            ),
            (
                "duplicate_policy_id_nonconsecutive",
                "expected baseline item 3, got item 2 for group id 1 (Example Group)"
            ),
        ],
    )
    def test_parse_baselines_raises_parser_error(
        self,
        snippet_name: str,
        expected_fragment: str,
    ):
        """
        Tests if MarkdownParser.parse_baselines() handles these cases:
            - raises a MarkdownParserError for missing policies section
            - raises a MarkdownParserError for product mismatch
            - raises a MarkdownParserError for group mismatch
            - duplicate policy IDs
        """
        parser = self._parser(self._snippets_directory())

        with pytest.raises(MarkdownParserError) as exception_info:
            parser.parse_baselines([snippet_name])

        msg = str(exception_info.value)
        assert expected_fragment in msg

    @staticmethod
    def _render_invalid_suffix(tmp_path: Path, suffix: str) -> Path:
        md_file = Path(__file__).parent / "snippets" / "invalid_policyid_version.md"
        md_content = md_file.read_text(encoding = "utf-8").replace("__SUFFIX__", suffix)
        out = tmp_path / "invalid_policyid_version.md"
        out.write_text(md_content, encoding = "utf-8")
        return tmp_path

    @pytest.mark.parametrize(
        ("suffix", "expect_error"),
        [
            ("v1.0", False),
            ("v2", False),
            ("version1", True),
            ("v1.0.0.0", True),
            ("vabc", True),
            ("v", True),
            ("v1.a", True),
        ]
    )
    def test_parse_baselines_raises_parser_error_for_invalid_policyid_versions(
        self,
        tmp_path: Path,
        suffix: str,
        expect_error: bool
    ):
        """
        Tests if the MarkdownParser.parse_baselines() public method
        raises a MarkdownParserError for invalid policy ID versions.
        """
        base_dir = self._render_invalid_suffix(tmp_path, suffix)
        parser = MarkdownParser(base_dir)

        if expect_error:
            with pytest.raises(MarkdownParserError) as exception_info:
                parser.parse_baselines(["invalid_policyid_version"])

            msg = str(exception_info.value)
            # md_parser.py will raise:
            assert f"invalid baseline version ({suffix})" in msg
        else:
            result = parser.parse_baselines(["invalid_policyid_version"])
            assert "invalid_policyid_version" in result

    def test_parse_baselines_raises_parser_error_for_missing_policy_description(self):
        """
        Tests if the MarkdownParser.parse_baselines() public method
        raises a MarkdownParserError for missing policy description.
        """
        parser = self._parser(self._snippets_directory())

        with pytest.raises(MarkdownParserError) as exception_info:
            parser.parse_baselines(["missing_policy_description"])

        msg = str(exception_info.value)
        # md_parser.py will raise:
        assert "missing description for baseline item 1 for group id 1 (Example Group)" in msg
