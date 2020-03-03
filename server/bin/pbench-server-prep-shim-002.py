#!/usr/bin/env python3
# -*- mode: python -*-

import os
import sys
import glob
import shutil
import tempfile

from pathlib import Path
from pbench import PbenchConfig
from pbench.common.exceptions import BadConfig
from pbench.server.report import Report
from pbench.server.logger import get_pbench_logger
from pbench.server.utils import md5sum, quarantine


_NAME_ = "pbench-server-prep-shim-002"


class Results(object):
    def __init__(
        self, nstatus="", ntotal=0, ntbs=0, nquarantined=0, ndups=0, nerrs=0,
    ):
        self.nstatus = nstatus
        self.ntotal = ntotal
        self.ntbs = ntbs
        self.nquarantined = nquarantined
        self.ndups = ndups
        self.nerrs = nerrs


def fetch_config_val(config, ef):

    qdir = config.get("pbench-server", "pbench-quarantine-dir")
    if not qdir:
        ef.write("Failed: getconf.py pbench-quarantine-dir pbench-server\n")
        return None, None

    qdir = Path(qdir).resolve()
    if not qdir.is_dir():
        ef.write(f"Failed: {qdir} does not exist, or is not a directory\n")
        return None, None

    receive_dir_prefix = config.get("pbench-server", "pbench-receive-dir-prefix")
    if not receive_dir_prefix:
        ef.write("Failed: getconf.py pbench-receive-dir-prefix pbench-server\n")
        return None, None

    receive_dir = Path(f"{receive_dir_prefix}-002").resolve()
    if not receive_dir.is_dir():
        ef.write(f"Failed: {receive_dir} does not exist, or is not a directory\n")
        return None, None

    return (qdir, receive_dir)


def qdirs_check(qdir_val, qdir, logger):
    try:
        os.makedirs(qdir)
    except FileExistsError:
        # directory already exists, ignore
        pass
    except Exception:
        logger.exception(
            "os.mkdir: Unable to create {} destination directory: {}", qdir_val, qdir,
        )
        return None
    return qdir


def md5_check(tb, tbmd5, logger):
    # read the md5sum from md5 file
    try:
        with tbmd5.open() as f:
            archive_md5_hex_value = f.readline().split(" ")[0]
    except Exception:
        logger.exception("Quarantine: Could not read {}", tbmd5)

    # get hex value of the tarball's md5sum
    try:
        archive_tar_hex_value = md5sum(tb)
    except Exception:
        logger.exception("Quarantine: Could not read {}", tb)

    return (archive_md5_hex_value, archive_tar_hex_value)


def process_tb(config, logger, receive_dir, qdir_md5, duplicates, errors, ef):

    list_check = glob.glob(
        os.path.join(receive_dir, "**", "*.tar.xz.md5"), recursive=True
    )

    archive = Path(config.ARCHIVE)
    logger.info("{}", config.TS)
    list_check.sort()
    nstatus = ""

    ntotal = ntbs = nerrs = nquarantined = ndups = 0

    for tbmd5 in list_check:
        ntotal += 1
        tb = Path(tbmd5[0:-4])
        tbmd5 = Path(tbmd5)
        tbdir = tb.parent
        result_name = tb.name

        controller = tbdir.name
        dest = archive / controller

        if (
            (dest / result_name).is_file()
            and (dest / tbmd5.name).is_file()
            and (dest / result_name).exists()
            and (dest / tbmd5.name).exists()
        ):
            ef.write(f"{config.TS}: Duplicate: {tb} duplicate name\n")
            quarantine((duplicates / controller), logger, tb, tbmd5)
            ndups += 1
            continue

        archive_tar_hex_value, archive_md5_hex_value = md5_check(tb, tbmd5, logger)
        if archive_tar_hex_value != archive_md5_hex_value:
            ef.write(f"{config.TS}: Quarantined: {tb} failed MD5 check\n")
            logger.info("{}: FAILED", tb.name)
            logger.info("md5sum: WARNING: 1 computed checksum did NOT match")
            quarantine((qdir_md5 / controller), logger, tb, tbmd5)
            nquarantined += 1
            continue

        try:
            os.makedirs(dest / "TODO")
        except FileExistsError:
            # directory already exists, ignore
            pass
        except Exception:
            logger.error("{}: Error in creating TODO directory.", config.TS)
            quarantine(os.path.join(errors, controller), logger, tb, tbmd5)
            nerrs += 1
            continue

        try:
            shutil.copy(tb, dest)
            shutil.copy(tbmd5, dest)
        except Exception:
            logger.error(
                "{}: Error in copying tarball files to Destination path.", config.TS
            )
            try:
                os.remove(dest / result_name)
                os.remove(dest / tbmd5.name)
            except Exception:
                logger.error(
                    "{}: Warning: cleanup of copy failure failed itself.", config.TS
                )
            quarantine((errors / controller), logger, tb, tbmd5)
            nerrs += 1
            continue

        try:
            os.remove(tb)
            os.remove(tbmd5)
        except Exception:
            logger.error(
                "{}: Warning: cleanup of successful copy operation failed.", config.TS
            )

        try:
            os.symlink((dest / result_name), (dest / "TODO" / result_name))
        except Exception:
            logger.error("{}: Error in creation of symlink.", config.TS)
            quarantine(
                (errors / controller), logger, (dest / tb), (dest / tbmd5),
            )
            nerrs += 1
            continue

        ntbs += 1

        nstatus = f"{nstatus}{config.TS}: processed {tb}\n"
        logger.info(f"{tb.name}: OK")

    return Results(
        nstatus=nstatus,
        ntotal=ntotal,
        ntbs=ntbs,
        nquarantined=nquarantined,
        ndups=ndups,
        nerrs=nerrs,
    )


def main(cfg_name):
    if not cfg_name:
        print(
            f"{_NAME_}: ERROR: No config file specified; set"
            " _PBENCH_SERVER_CONFIG env variable or use --config <file> on the"
            " command line",
            file=sys.stderr,
        )
        return 2

    try:
        config = PbenchConfig(cfg_name)
    except BadConfig as e:
        print(f"{_NAME_}: {e} (config file {cfg_name})", file=sys.stderr)
        return 1

    archive = Path(config.ARCHIVE)
    archive_p = archive.resolve()

    if not archive_p:

        print(f"{_NAME_}: Bad ARCHIVE={config.ARCHIVE}", file=sys.stderr)
        return 1

    if not archive_p.is_dir():
        print(f"{_NAME_}: Bad ARCHIVE={config.ARCHIVE}", file=sys.stderr)
        return 1

    # logger = get_pbench_logger(_NAME_, config)

    try:
        os.mkdir(os.path.join(config.LOGSDIR, "pbench-server-prep-shim-002"))
    except FileExistsError:
        # directory already exists, ignore
        pass
    except Exception:
        print("os.mkdir: Unable to create destination directory")
        return 1

    errorfile = Path(
        config.LOGSDIR,
        "pbench-server-prep-shim-002",
        "pbench-server-prep-shim-002.error",
    )
    error_f = open(errorfile, "w")

    qdir, receive_dir = fetch_config_val(config, error_f)

    if qdir is None and receive_dir is None:
        return 2

    logger = get_pbench_logger(_NAME_, config)

    qdir_md5 = qdirs_check("quarantine", Path(qdir, "md5-002"), logger)
    duplicates = qdirs_check("duplicates", Path(qdir, "duplicates-002"), logger)

    # The following directory holds tarballs that are quarantined because
    # of operational errors on the server. They should be retried after
    # the problem is fixed: basically, move them back into the reception
    # area for 002 agents and wait.
    errors = qdirs_check("errors", Path(qdir, "errors-002"), logger)

    if qdir_md5 is None or duplicates is None or errors is None:
        return 1

    counts = process_tb(
        config, logger, receive_dir, qdir_md5, duplicates, errors, error_f
    )

    result_string = (
        f"{config.TS}: Processed {counts.ntotal} entries,"
        f" {counts.ntbs} tarballs successful,"
        f" {counts.nquarantined} quarantined tarballs,"
        f" {counts.ndups} duplicately-named tarballs,"
        f" {counts.nerrs} errors."
    )

    logger.info(result_string)

    # prepare and send report
    with tempfile.NamedTemporaryFile(mode="w+t", dir=config.TMP) as reportfp:
        reportfp.write(f"{counts.nstatus}{result_string}\n")
        reportfp.seek(0)

        report = Report(config, _NAME_)
        report.init_report_template()
        try:
            report.post_status(config.timestamp(), "status", reportfp.name)
        except Exception:
            logger.warning("Report post Unsuccesful")

    return 0


if __name__ == "__main__":
    cfg_name = os.environ.get("_PBENCH_SERVER_CONFIG")
    status = main(cfg_name)
    sys.exit(status)
