"""Implementation of ScubaGoggles conformance report directory purge.
"""

import argparse
import datetime
import logging
import re
import shutil
import time

from operator import itemgetter
from pathlib import Path

from scubagoggles.user_setup import default_file_names

log = logging.getLogger(__name__)


def purge_reports(arguments: argparse.Namespace):

    """Main purge reports function - this calls other functions in this module.

    The arguments provide a keep count, and optionally the number of expiration
    days.  If the keep count is non-zero. the specified number of report
    directories is kept.  The remaining directories are deleted, unless the
    number of expiration days is given.  In that case, any remaining directory
    newer than the expiration day count is excluded from being deleted.

    NOTE: this only affects ScubaGoggles report output directories in the
    user's output directory, and only those having names starting with
    "GWSBaselineConformance" (the default output folder name (i.e., prefix)
    and ending with a timestamp.  Any directory not named in this way is
    untouched.

    :param arguments: arguments collected by the ArgumentParser.
    """

    log.info('GWS Conformance Report Directory Purge')

    config = arguments.user_config
    output_dir = config.output_dir

    # Find all directories with generated names in the user's output directory.
    # The returned directories are sorted by date (the oldest first).

    report_dir_data = find_report_directories(output_dir)
    dir_count = len(report_dir_data)

    log.info('  Report directories: %d', dir_count)

    expire_days = arguments.expire
    keep_count = arguments.keep

    # First, there's nothing to do if the number of directories is less or
    # equal to the keep count.  If there are more, we exclude the newest
    # directories from consideration.

    if keep_count is None or dir_count <= keep_count:
        return

    if keep_count < 0:
        raise ValueError(f'? {keep_count} - negative keep count')

    report_dir_data = report_dir_data[0:dir_count - keep_count]

    if expire_days:
        # The "expire days" value is the number of days back from the
        # current date (i.e., now).  Any older directory is considered
        # "expired" and will be deleted (unless excluded by the keep
        # count above).

        if expire_days < 0:
            raise ValueError(f'? {expire_days} - negative expire days')

        days = datetime.timedelta(abs(expire_days))
        expiration_date = datetime.datetime.now() - days
        expiration_time = time.mktime(expiration_date.timetuple())

        report_dir_data = [s for s in report_dir_data
                           if s[1] < expiration_time]

    # What remains in the list are the directories to be deleted, after
    # considering both the keep count and expire days values.  We do not
    # care if the directory could not be deleted for some reason - that
    # is the user's issue.

    delete_count = len(report_dir_data)
    log.info('  Report directories to be deleted: %d', delete_count)
    log.debug('  %s', output_dir)

    for data in report_dir_data:
        output_path = data[0]
        log.debug('    %s', output_path.name)
        shutil.rmtree(output_path, ignore_errors = True)

    return


def find_report_directories(user_directory: Path) -> list:

    """Finds ScubaGoggles report directories with generated names, and
    returns them as a list sorted by modification date (the oldest first).
    Each element in the returned list contains the Path instance of the
    directory and the modification time as a tuple.

    :return: tuples containing the Path and modification time of each
        directory found.
    :rtype: list
    """

    result = []

    report_root = Path(user_directory)

    if not report_root.exists():
        return result

    dir_prefix = default_file_names.output_folder_name
    dirname_re = re.compile(f'(?i){dir_prefix}_' + r'\d{4}(?:_\d{2}){5}$')

    for report_path in report_root.glob(f'{dir_prefix}*'):

        if (not report_path.is_dir()
           or not dirname_re.match(report_path.name)):
            continue

        dir_data = (report_path, report_path.stat().st_mtime)
        result.append(dir_data)

    result.sort(key = itemgetter(1))

    return result
