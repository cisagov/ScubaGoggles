from pathlib import Path
import re
import pytest

import scubagoggles as scubagoggles_pkg
from scubagoggles.reporter.md_parser import MarkdownParser, MarkdownParserError

class TestMarkdownParser:
    """Tests for the MarkdownParser class."""

    @staticmethod
    def _baselines_directory() -> Path:
        return Path(scubagoggles_pkg.__file__).resolve().parent / "baselines"

    def test_parse_baselines_returns_correct_format(self):
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
        snippets_directory = Path(__file__).parent / "BaselineSnippets"
        parser = MarkdownParser(snippets_directory)

        with pytest.raises(MarkdownParserError):
            parser.parse_baselines(["missing_policies_section"])

    def test_parse_baselines_raises_parser_error_for_product_mismatch(self):
        snippets_directory = Path(__file__).parent / "BaselineSnippets"
        parser = MarkdownParser(snippets_directory)

        with pytest.raises(MarkdownParserError) as exception_info:
            parser.parse_baselines(["product_mismatch"])

        msg = str(exception_info.value)
        # md_parser.py will raise:
        assert "different product encountered calendar != product_mismatch" in msg

    def test_parse_baselines_raises_parser_error_for_group_mismatch(self):
        snippets_directory = Path(__file__).parent / "BaselineSnippets"
        parser = MarkdownParser(snippets_directory)

        with pytest.raises(MarkdownParserError) as exception_info:
            parser.parse_baselines(["group_mismatch"])

        msg = str(exception_info.value)
        # md_parser.py will raise:
        assert "mismatching group number (2) for group id 1 (External Sharing Options)" in msg

    def test_parse_baselines_raises_parser_error_for_invalid_baseline_version(self):
        snippets_directory = Path(__file__).parent / "BaselineSnippets"
        parser = MarkdownParser(snippets_directory)

        with pytest.raises(MarkdownParserError) as exception_info:
            parser.parse_baselines(["invalid_baseline_version"])

        msg = str(exception_info.value)
        # md_parser.py will raise:
        assert "invalid baseline version" in msg

    def test_parse_baselines_raises_parser_error_for_missing_baseline_description(self):
        pass