import argparse
import time
from pathlib import Path
import pytest
from scubagoggles.purge import purge_reports

class TestPurge:

    @pytest.fixture
    def mock_args(self, mocker):
        args = argparse.Namespace()
        args.user_config = mocker.MagicMock()
        args.user_config.output_dir = Path("/mock/output")
        args.keep = 2
        args.expire = None
        return args

    def test_purge_reports_keep_logic(self, mocker, mock_args):
        """Verify oldest directories are deleted when exceeding keep count."""
        mock_find = mocker.patch('scubagoggles.purge.find_report_directories')
        mock_rmtree = mocker.patch('shutil.rmtree')

        # Mock 5 directories (Oldest -> Newest)
        mock_dirs = [
            (Path("/mock/output/Report1"), 1000.0),
            (Path("/mock/output/Report2"), 2000.0),
            (Path("/mock/output/Report3"), 3000.0),
            (Path("/mock/output/Report4"), 4000.0),
            (Path("/mock/output/Report5"), 5000.0)
        ]
        mock_find.return_value = mock_dirs
        mock_args.keep = 2

        purge_reports(mock_args)

        # Should delete the 3 oldest (5 total - 2 kept)
        assert mock_rmtree.call_count == 3
        # In pytest-mock, call is accessed via mocker.call
        expected_calls = [
            mocker.call(Path("/mock/output/Report1"), ignore_errors=True),
            mocker.call(Path("/mock/output/Report2"), ignore_errors=True),
            mocker.call(Path("/mock/output/Report3"), ignore_errors=True)
        ]
        mock_rmtree.assert_has_calls(expected_calls)

    def test_purge_reports_expiration_logic(self, mocker, mock_args):
        """Verify directories are only deleted if they are older than expiration days."""
        mock_find = mocker.patch('scubagoggles.purge.find_report_directories')
        mock_rmtree = mocker.patch('shutil.rmtree')

        now = time.time()
        one_day = 86400

        mock_dirs = [
            (Path("/expired1"), now - (10 * one_day)),
            (Path("/expired2"), now - (5 * one_day)),
            (Path("/recent"), now - (1 * one_day))
        ]
        mock_find.return_value = mock_dirs
        mock_args.keep = 1
        mock_args.expire = 3

        purge_reports(mock_args)

        # recent is kept by 'keep'. expired1 and expired2 are candidates and > 3 days old.
        assert mock_rmtree.call_count == 2

    def test_purge_reports_negative_keep(self, mock_args):
        """Ensure negative values raise ValueError."""
        mock_args.keep = -1
        with pytest.raises(ValueError, match="negative keep count"):
            purge_reports(mock_args)

    def test_purge_reports_negative_expire(self, mocker, mock_args):
        """Ensure negative values raise ValueError."""

        mock_find = mocker.patch('scubagoggles.purge.find_report_directories')

        # Mock 5 directories (Oldest -> Newest)
        mock_dirs = [
            (Path("/mock/output/Report1"), 1000.0),
            (Path("/mock/output/Report2"), 2000.0),
            (Path("/mock/output/Report3"), 3000.0),
            (Path("/mock/output/Report4"), 4000.0),
            (Path("/mock/output/Report5"), 5000.0)
        ]
        mock_find.return_value = mock_dirs


        mock_args.keep = 1
        mock_args.dir_count = len(mock_dirs)
        mock_args.expire = -1
        with pytest.raises(ValueError, match="negative expire days"):
            purge_reports(mock_args)

    def test_purge_reports_with_real_fs(self, tmp_path, mocker, mock_args):
        """Verify actual file system deletion using tmp_path fixture."""
        report_dir = tmp_path / "GWSBaselineConformance_20260121"
        report_dir.mkdir()
        (report_dir / "report.html").write_text("content")

        mock_find = mocker.patch('scubagoggles.purge.find_report_directories')
        mock_find.return_value = [(report_dir, time.time() - 10000)]

        mock_args.keep = 0
        mock_args.user_config.output_dir = tmp_path

        purge_reports(mock_args)

        assert not report_dir.exists()
