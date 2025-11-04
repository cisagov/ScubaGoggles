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

    @staticmethod
    def _baselines_directory() -> Path:
        return Path(scubagoggles_pkg.__file__).resolve().parent / "baselines"

    def test_parse_baselines_returns_correct_format(self):
        """
        Tests the MarkdownParser.parse_baselines() public method for expected output structure.
        """
        parser = MarkdownParser(self._baselines_directory())
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

    def test_parse_baselines_raises_parser_error_for_missing_policies_section(self):
        """
        Tests if the MarkdownParser.parse_baselines() public method 
        raises a MarkdownParserError for missing policies section.
        """
        snippets_dir = Path(__file__).parent / "snippets"
        parser = MarkdownParser(snippets_dir)

        with pytest.raises(MarkdownParserError):
            parser.parse_baselines(["missing_policies_section"])

    def test_parse_baselines_raises_parser_error_for_product_mismatch(self):
        """
        Tests if the MarkdownParser.parse_baselines() public method
        raises a MarkdownParserError for product mismatch.
        """
        snippets_dir = Path(__file__).parent / "snippets"
        parser = MarkdownParser(snippets_dir)

        with pytest.raises(MarkdownParserError) as exception_info:
            parser.parse_baselines(["product_mismatch"])

        msg = str(exception_info.value)
        # md_parser.py will raise:
        assert "different product encountered calendar != product_mismatch" in msg

    def test_parse_baselines_raises_parser_error_for_group_mismatch(self):
        """
        Tests if the MarkdownParser.parse_baselines() public method
        raises a MarkdownParserError for group mismatch.
        """
        snippets_dir = Path(__file__).parent / "snippets"
        parser = MarkdownParser(snippets_dir)

        with pytest.raises(MarkdownParserError) as exception_info:
            parser.parse_baselines(["group_mismatch"])

        msg = str(exception_info.value)
        # md_parser.py will raise:
        assert "mismatching group number (2) for group id 1 (External Sharing Options)" in msg

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
        snippets_dir = Path(__file__).parent / "snippets"
        parser = MarkdownParser(snippets_dir)

        with pytest.raises(MarkdownParserError) as exception_info:
            parser.parse_baselines(["missing_policy_description"])

        msg = str(exception_info.value)
        # md_parser.py will raise:
        assert "missing description for baseline item 1 for group id 1 (Example Group)" in msg
