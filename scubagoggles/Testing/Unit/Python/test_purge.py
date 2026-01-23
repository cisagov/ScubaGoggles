import argparse
import datetime
import logging
import re
import shutil
import time
from operator import itemgetter
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest
from scubagoggles.purge import purge_reports

class TestPurge:

    # Fixture to provide a standard set of mock arguments
    @pytest.fixture
    def mock_args():
        args = argparse.Namespace()
        args.user_config = MagicMock()
        args.user_config.output_dir = Path("/mock/output")
        args.keep = 2
        args.expire = None
        return args

    # Test successful purge based on 'keep' count
    @patch('scubagoggles.purge.find_report_directories')
    @patch('shutil.rmtree')
    def test_purge_reports_keep_logic(mock_rmtree, mock_find, mock_args):
        """Verify oldest directories are deleted when exceeding keep count."""
        # Mock 5 directories (Oldest -> Newest)
        mock_dirs = [
            (Path("/mock/output/Report1"), 1000.0),
            (Path("/mock/output/Report2"), 2000.0),
            (Path("/mock/output/Report3"), 3000.0),
            (Path("/mock/output/Report4"), 4000.0),
            (Path("/mock/output/Report5"), 5000.0)
        ]
        mock_find.return_value = mock_dirs
        mock_args.keep = 2 # Keep the 2 newest

        purge_reports(mock_args)

        # Should delete the 3 oldest (5 total - 2 kept)
        assert mock_rmtree.call_count == 3
        expected_calls = [
            call(Path("/mock/output/Report1"), ignore_errors=True),
            call(Path("/mock/output/Report2"), ignore_errors=True),
            call(Path("/mock/output/Report3"), ignore_errors=True)
        ]
        mock_rmtree.assert_has_calls(expected_calls)

    # Test expiration day logic
    @patch('scubagoggles.purge.find_report_directories')
    @patch('shutil.rmtree')
    def test_purge_reports_expiration_logic(mock_rmtree, mock_find, mock_args):
        """Verify directories are only deleted if they are older than expiration days."""
        now = time.time()
        one_day = 86400

        # 3 directories: 2 very old, 1 recent
        mock_dirs = [
            (Path("/expired1"), now - (10 * one_day)),
            (Path("/expired2"), now - (5 * one_day)),
            (Path("/recent"), now - (1 * one_day))
        ]
        mock_find.return_value = mock_dirs
        mock_args.keep = 1   # Candidate to keep 1 (recent)
        mock_args.expire = 3 # But only delete those > 3 days old

        purge_reports(mock_args)

        # recent is kept by 'keep'. expired1 and expired2 are candidates and > 3 days old.
        assert mock_rmtree.call_count == 2

    # Test input validation using pytest.raises
    def test_purge_reports_negative_values(mock_args):
        """Ensure negative values raise ValueError."""
        mock_args.keep = -1
        with pytest.raises(ValueError, match="negative keep count"):
            purge_reports(mock_args)

        mock_args.keep = 5
        mock_args.expire = -1
        with pytest.raises(ValueError, match="negative expire days"):
            purge_reports(mock_args)

    # Integration-style test with real temporary files
    def test_purge_reports_with_real_fs(tmp_path, mock_args):
        """Verify actual file system deletion using tmp_path fixture."""
        # Create mock directory structure
        report_dir = tmp_path / "GWSBaselineConformance_20260121"
        report_dir.mkdir()
        (report_dir / "report.html").write_text("content")

        # Override find_report_directories to return our real tmp path
        with patch('scubagoggles.purge.find_report_directories') as mock_find:
            mock_find.return_value = [(report_dir, time.time() - 10000)]
            mock_args.keep = 0
            mock_args.user_config.output_dir = tmp_path

            purge_reports(mock_args)

        assert not report_dir.exists()
