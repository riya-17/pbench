#! /usr/bin/env python3

import os
import sys
import glob
import tempfile

from pathlib import Path
from pbench.server import PbenchServerConfig
from pbench.common.exceptions import BadConfig
from pbench.common.logger import get_pbench_logger
from pbench.server.report import Report
from configparser import ConfigParser, NoSectionError, NoOptionError
from pbench.server.hierarchy import (
    Hierarchy,
    ArchiveHierarchy,
    ControllerHierarchy,
    IncomingHierarchy,
    ResultsHierarchy,
    UserHierarchy,
)


_NAME_ = "pbench-audit-server"


class PbenchMDLogConfig(object):
    """A simple class to wrap a ConfigParser object in order to query a specific
    metadata.log file for a given tarball.
    """

    def __init__(self, cfg_name):
        self.conf = ConfigParser()
        self.files = self.conf.read([cfg_name])

    def get(self, *args, **kwargs):
        return self.conf.get(*args, **kwargs)


def verify_valid_controllers(hier, controllers):
    """Find all the non-directory files at the same level of the controller
    directories and report them, and find all the normal controller directories.
    """
    for controller in controllers:
        controller_path = Path(controller)
        if controller_path.is_dir():
            hier.add_controller(controller_path.name)
        else:
            hier.add_bad_controller(controller)
    return 0


# Archive Hierarchy
def verify_subdirs(hier, controller, directories):
    linkdirs = sorted(hier.config.LINKDIRS.split(" "))
    if directories:
        for dirent in directories:
            if all(
                [
                    Path(hier.path, controller, dirent).exists(),
                    dirent != "_QUARANTINED",
                    not dirent.startswith("WONT-INDEX"),
                ]
            ):
                if dirent not in linkdirs:
                    hier.add_unexpected_controllers(
                        Hierarchy.UNEXPECTED_DIRS, controller, dirent
                    )
    else:
        hier.add_unexpected_controllers(
            Hierarchy.SUBDIR_STATUS_INDICATORS, controller, "subdirs"
        )

    return 0


def verify_prefixes(hier, controller):
    prefix_dir = Path(hier.path, controller, ".prefix")
    if not prefix_dir.exists():
        return 0
    if not prefix_dir.is_dir():
        hier.add_unexpected_controllers(
            Hierarchy.PREFIX_STATUS_INDICATORS, controller, "prefix_dir"
        )
        return 1

    prefixes = glob.iglob(os.path.join(str(prefix_dir), "*"))

    for prefix in prefixes:
        prefix_path = Path(prefix)
        if not prefix_path.name.startswith("prefix.") and not prefix_path.name.endswith(
            ".prefix"
        ):
            hier.add_unexpected_controllers(
                Hierarchy.NON_PREFIXES, controller, prefix_path.name
            )
        elif prefix_path.name.startswith("prefix."):
            hier.add_unexpected_controllers(
                Hierarchy.WRONG_PREFIXES, controller, prefix_path.name
            )

    return 0


# 'hier' is an object of ArchiveHierarchy class imported from hierarchy.py
def verify_archive(hier):

    controllers = glob.iglob(os.path.join(hier.path, "*"))
    verify_valid_controllers(hier, controllers)

    # now check each "good" controller and get the tarballs it contains
    for controller in hier.controllers:
        direct_entries = glob.iglob(os.path.join(hier.path, controller, "*"))
        hidden_entries = glob.glob(os.path.join(hier.path, controller, ".*"))
        if hidden_entries:
            for hid_entries in hidden_entries:
                hid_entries_path = Path(hid_entries)
                if hid_entries_path.is_file():
                    hier.add_unexpected_controllers(
                        Hierarchy.UNEXPECTED_OBJECTS, controller, hid_entries_path.name,
                    )
        controller_subdir = list()
        for item in direct_entries:
            item_path = Path(item)
            if item_path.is_dir():
                controller_subdir.append(item_path.name)
            elif item_path.is_symlink():
                try:
                    item_p = item_path.resolve(strict=True)
                except FileNotFoundError:
                    print(
                        f"{item_path.name}_path, '{item_path}', does not resolve to a real location"
                    )
                    return 1
                symlink_item = f"{item_path.name} -> {item_p}"
                hier.add_unexpected_controllers(
                    Hierarchy.UNEXPECTED_SYMLINKS, controller, symlink_item
                )
            elif all(
                [
                    item_path.is_file(),
                    not item_path.name.endswith(".tar.xz"),
                    not item_path.name.endswith(".tar.xz.md5"),
                ]
            ):
                hier.add_unexpected_controllers(
                    Hierarchy.UNEXPECTED_OBJECTS, controller, item_path.name
                )
            elif item_path.is_file() and (
                item_path.name.endswith(".tar.xz")
                or item_path.name.endswith(".tar.xz.md5")
            ):
                hier.add_tarballs(controller)
            else:
                print(
                    f"{item_path} item should have been handled by the above mentioned conditions. "
                    f"It is an unexpected item which should not have occured, "
                    f"leading to an inappropriate condition"
                )
        verify_subdirs(hier, controller, controller_subdir)
        verify_prefixes(hier, controller)

    return 0


# Incoming Hierarchy
def verify_tar_dirs(ihier, tarball_dirs, tblist, controller):
    for tb in tarball_dirs:
        if tb.endswith("unpack"):
            tar = tb[:-7]
            tar = f"{tar}.tar.xz"
            val = Hierarchy.INVALID_UNPACKING_DIRS
        else:
            tar = f"{tb}.tar.xz"
            val = Hierarchy.INVALID_TB_DIRS
        tarfile = Path(ihier.config.ARCHIVE, controller, tar)
        if tarfile.exists():
            with tarfile.open(mode="r") as f:
                try:
                    file_content = f.read(1)
                    if file_content:
                        continue
                except Exception:
                    pass
        else:
            tblist(val, controller, Path(tb).name)
    return 0


# 'ihier' is IncomingHierarchy class object
def verify_incoming(ihier, verifylist):

    for controller in verifylist:
        ihier.add_controller(controller)
        direct_entries = glob.iglob(
            os.path.join(ihier.config.INCOMING, controller, "*")
        )
        tarball_dirs = list()
        unpacking_tarball_dirs = list()

        if not Path(ihier.config.ARCHIVE, controller).is_dir():
            # Skip incoming controller directories that don't have an $ARCHIVE
            # directory, handled in another part of the audit.
            continue

        for dirent in direct_entries:
            dir_path = Path(dirent)
            if (
                dir_path.is_dir()
                and not dir_path.name.endswith(".unpack")
                and not len(os.listdir(dir_path)) == 0
            ):
                tarball_dirs.append(dir_path.name)
            elif (
                dir_path.is_dir()
                and not dir_path.name.endswith(".unpack")
                and len(os.listdir(dir_path)) == 0
            ):
                ihier.add_unexpected_controllers(
                    Hierarchy.EMPTY_TARBALL_DIRS, controller, dir_path.name
                )
            elif (
                dir_path.is_dir()
                and dir_path.name.endswith(".unpack")
                and len(os.listdir(dir_path)) == 0
            ):
                unpacking_tarball_dirs.append(dir_path.name)
            elif dir_path.is_symlink():
                ihier.add_unexpected_controllers(
                    Hierarchy.TARBALL_LINKS, controller, dir_path.name
                )

        if tarball_dirs:
            verify_tar_dirs(
                ihier, tarball_dirs, ihier.add_unexpected_controllers, controller
            )

        if unpacking_tarball_dirs:
            verify_tar_dirs(
                ihier,
                unpacking_tarball_dirs,
                ihier.add_unexpected_controllers,
                controller,
            )

    return 0


# Results Hierarchy
def verify_user_arg(rhier, mdlogcfg, user_arg, user_controller, path):
    """fetch user from the config file and verifies its validity"""
    user = ""
    try:
        user = mdlogcfg.get("run", "user")
    except NoSectionError:
        pass
    except NoOptionError:
        pass
    if not user:
        """No user in the metadata.log of the tar ball, but
        we are examining a link in the user tree that
        does not have a configured user, report it.
        """
        rhier.add_unexpected_controllers(
            Hierarchy.UNEXPECTED_USER_LINKS, user_controller, path
        )
    elif user_arg != user:
        """Configured user does not match the user tree in
        which we found the link."""
        rhier.add_unexpected_controllers(
            Hierarchy.WRONG_USER_LINKS, user_controller, path
        )

    return 0


def list_direct_entries(results_hierarchy, controller):

    direct_entries = list()
    for root, dirs, files in os.walk(Path(results_hierarchy, controller), topdown=True):
        for name in files:
            direct_entries.append(os.path.join(root, name))
        for name in dirs:
            direct_entries.append(os.path.join(root, name))

    return direct_entries


def verify_results(rhier, verifylist, user_arg):
    """'rhier' is ResultsHierarchy class. user_arg consists of
    users which gets passed from user hierarchy.
    """
    if user_arg:
        results_hierarchy = Path(rhier.config.USERS, user_arg)
    else:
        results_hierarchy = Path(rhier.path)

    for controller in verifylist:
        if not Path(rhier.config.ARCHIVE, controller).is_dir():
            """Skip incoming controller directories that don't have an $ARCHIVE
            directory, handled in another part of the audit.
            """
            continue

        direct_entries = list_direct_entries(results_hierarchy, controller)

        if user_arg:
            user_controller = f"{user_arg}/{controller}"
            rhier.add_controller(user_controller)
        else:
            rhier.add_controller(controller)

        for dirent in direct_entries:
            path = Path(dirent.split(os.path.join(controller, ""), 1)[1])
            dir_path = Path(dirent)
            if dir_path.is_dir() and len(os.listdir(dir_path)) == 0:
                if user_arg:
                    rhier.add_unexpected_controllers(
                        Hierarchy.EMPTY_TARBALL_DIRS, user_controller, path
                    )
                else:
                    rhier.add_unexpected_controllers(
                        Hierarchy.EMPTY_TARBALL_DIRS, controller, path
                    )
            elif dir_path.is_symlink():
                link = os.path.realpath(dirent)
                tb = f"{path.name}.tar.xz"
                incoming_path = Path(rhier.config.INCOMING, controller, dir_path.name)
                if not Path(rhier.config.ARCHIVE, controller, tb).exists():
                    rhier.add_unexpected_controllers(
                        Hierarchy.INVALID_TB_LINKS, controller, dir_path.name
                    )
                else:
                    if link != str(incoming_path):
                        rhier.add_unexpected_controllers(
                            Hierarchy.INCORRECT_TB_DIR_LINKS, controller, dir_path.name
                        )
                    elif not incoming_path.is_dir() and not incoming_path.is_symlink():
                        rhier.add_unexpected_controllers(
                            Hierarchy.INVALID_TB_DIR_LINKS, controller, dir_path.name
                        )
                    else:
                        prefix_path = os.path.dirname(str(path))
                        prefix_file = Path(
                            rhier.config.ARCHIVE, controller, ".prefix", dir_path.name
                        )
                        prefix_file = Path(f"{prefix_file}.prefix")
                        mdlogcfg = PbenchMDLogConfig(
                            Path(incoming_path, "metadata.log")
                        )
                        prefix = ""
                        try:
                            prefix = mdlogcfg.get("run", "prefix")
                        except NoSectionError:
                            pass
                        except NoOptionError:
                            pass
                        if prefix_path == "":
                            if prefix:
                                rhier.add_unexpected_controllers(
                                    Hierarchy.BAD_PREFIXES, controller, path
                                )
                            elif prefix_file.exists():
                                rhier.add_unexpected_controllers(
                                    Hierarchy.UNUSED_PREFIX_FILES, controller, path
                                )
                        else:
                            if prefix:
                                if prefix != str(prefix_path):
                                    rhier.add_unexpected_controllers(
                                        Hierarchy.BAD_PREFIXES, controller, path
                                    )
                            elif not prefix_file.exists():
                                rhier.add_unexpected_controllers(
                                    Hierarchy.MISSING_PREFIX_FILES, controller, path
                                )
                            else:
                                f = 0
                                try:
                                    with prefix_file.open(mode="r") as file:
                                        prefix = file.read().replace("\n", "")
                                except Exception:
                                    f = 1
                                if f == 1:
                                    rhier.add_unexpected_controllers(
                                        Hierarchy.BAD_PREFIX_FILES, controller, path
                                    )
                                else:
                                    if prefix != prefix_path:
                                        rhier.add_unexpected_controllers(
                                            Hierarchy.BAD_PREFIXES, controller, path
                                        )
                        if user_arg:
                            """We are reviewing a user tree, so check the user in
                            the configuration.  Version 002 agents use the
                            metadata log to store a user as well.
                            """
                            verify_user_arg(
                                rhier, mdlogcfg, user_arg, user_controller, path
                            )

    return 0


# Controller Hierarchy
def verify_controllers(hier):
    """'ihier' is either IncomingHierarchy class object or ResultsHierarchy
    class object based on the instance it is called and hier is a
    ControllerHierarchy class object. user_arg is the user of Users hierarchy
    """
    controllers = glob.iglob(os.path.join(hier.path, "*"))
    verify_valid_controllers(hier, controllers)

    if hier.controllers:
        for controller in hier.controllers:
            dir_path = Path(hier.path, controller)
            unexpected_dirs = list()
            if not Path(hier.config.ARCHIVE, controller).is_dir():
                """We have a controller in the hierarchy which does not have a
                controller of the same name in the archive hierarchy.  All
                we do is report it, don't bother analyzing it further.
                """
                hier.add_controller_list(Hierarchy.MIALIST, Path(controller).name)
            else:
                """Report any controllers with objects other than directories
                and links, while also recording any empty controllers.
                """
                if len(os.listdir(dir_path)) == 0:
                    hier.add_controller_list(Hierarchy.EMPTY_CONTROLLERS, controller)
                    continue
                else:
                    direct_entries = glob.iglob(
                        os.path.join(hier.path, controller, "*")
                    )
                    for item in direct_entries:
                        item_path = Path(item)
                        if not item_path.is_dir() and not item_path.is_symlink():
                            unexpected_dirs.append(controller)

                if unexpected_dirs:
                    hier.add_controller_list(
                        Hierarchy.UNEXPECTED_CONTROLLERS, controller
                    )
                hier.add_verify_list(controller)

    return 0


# User Hierarchy


def expected_unexpected_users(hier, user_dirs):
    """Find all the non-directory files at the same level of the controller
    directories and report them, and find all the normal controller directories.
    """
    for user in user_dirs:
        user_path = Path(user)
        if user_path.is_dir():
            hier.add_user_dir(user_path.name)
        else:
            hier.add_unexpected_objects(user_path.name)
    return 0


def verify_users(hier):
    """'rhier' is the ResultsHierarchy class object,
    'chier' is ControllerHierarchy class object and
    'hier' is UserHierarchy class object.
    """
    if not Path(hier.path).is_dir():
        print(
            "The setting for USERS in the config file is {}, but that is"
            " not a directory",
            hier.path,
        )
        return 1

    users_dirs = glob.iglob(os.path.join(hier.path, "*"))
    expected_unexpected_users(hier, users_dirs)

    return 0


def check_and_dump(f, hier, ihier):

    cnt = 0
    first_check = hier.check_controller()
    second_check = ihier.check_controller()
    if first_check or second_check:
        hier.header(f, "start")
        if first_check:
            cnt = hier.dump(f)
        if second_check:
            cnt += ihier.dump(f)
        hier.header(f, "end")
    return cnt


def check_func(pbdir_path, pbdirname):
    """check function deals with handling the integrity of
    ARCHIVE, INCOMING, RESULTS and USERS hierarchy
    """
    pbdir = pbdir_path
    try:
        pbdir_p = Path(pbdir).resolve(strict=True)
    except FileNotFoundError:
        print(f"{_NAME_}: Bad {pbdirname}={pbdir}", file=sys.stderr)
        return 1

    if not pbdir_p.is_dir():
        print(f"{_NAME_}: Bad {pbdirname}={pbdir}", file=sys.stderr)
        return 1

    return 0


def main():
    cfg_name = os.environ.get("_PBENCH_SERVER_CONFIG")
    if not cfg_name:
        print(
            "{}: ERROR: No config file specified; set CONFIG env variable or"
            " use --config <file> on the command line".format(_NAME_),
            file=sys.stderr,
        )
        return 2

    try:
        config = PbenchServerConfig(cfg_name)
    except BadConfig as e:
        print("{}: {} (config file {})".format(_NAME_, e, cfg_name), file=sys.stderr)
        return 1

    if check_func(config.ARCHIVE, "ARCHIVE") > 0:
        return 1

    if check_func(config.INCOMING, "INCOMING") > 0:
        return 1

    if check_func(config.RESULTS, "RESULTS") > 0:
        return 1

    if check_func(config.USERS, "USERS") > 0:
        return 1

    logger = get_pbench_logger(_NAME_, config)

    ret = 0

    try:
        Path(config.LOGSDIR, "pbench-audit-server").mkdir()
    except FileExistsError:
        # directory already exists, ignore
        pass
    except Exception:
        print("os.mkdir: Unable to create destination directory")
        return 1
    logfile = Path(config.LOGSDIR, "pbench-audit-server", "pbench-audit-server.log")
    # TEMPORARY addition of error file for the sake of test cases
    errorfile = Path(config.LOGSDIR, "pbench-audit-server", "pbench-audit-server.error")
    with errorfile.open(mode="w") as f:
        pass
    # END

    logger.info("start-{}", config.TS)

    with logfile.open(mode="w") as f:

        ahier = ArchiveHierarchy("archive", config.ARCHIVE, config)
        verify_archive(ahier)
        cnt = 0
        if ahier.check_controller():
            f.write(f"\nstart-{config.TS[4:]}: archive hierarchy: {config.ARCHIVE}\n")
            cnt = ahier.dump(f)
            ahier.header(f, "end")
        if cnt > 0:
            ret += 1

        ihier = IncomingHierarchy("incoming", config.INCOMING, config)
        cihier = ControllerHierarchy("incoming", config.INCOMING, config)
        verify_controllers(cihier)
        verify_incoming(ihier, cihier.verifylist)
        cnt = check_and_dump(f, cihier, ihier)
        if cnt > 0:
            ret += 1

        rhier = ResultsHierarchy("results", config.RESULTS, config)
        crhier = ControllerHierarchy("results", config.RESULTS, config)
        verify_controllers(crhier)
        verify_results(rhier, crhier.verifylist, None)
        cnt = check_and_dump(f, crhier, rhier)
        if cnt > 0:
            ret += 1

        ruhier = ResultsHierarchy("results", config.USERS, config)
        uhier = UserHierarchy("users", config.USERS, config)
        verify_users(uhier)
        if uhier.USER_DIR:
            for user in uhier.USER_DIR:
                verify_results(ruhier, crhier.verifylist, user)
        cnt = check_and_dump(f, uhier, ruhier)
        if cnt > 0:
            ret += 1

    # prepare and send report
    with tempfile.NamedTemporaryFile(mode="w+t", dir=config.TMP) as reportfp:
        with open(logfile, "r") as f:
            reportfp.write(
                f"{_NAME_}.run-{config.timestamp()}({config.PBENCH_ENV})\n{f.read()}"
            )
            reportfp.seek(0)

            report = Report(config, _NAME_)
            report.init_report_template()
            try:
                report.post_status(config.timestamp(), "status", reportfp.name)
            except Exception:
                pass

    f.close()

    return ret


if __name__ == "__main__":
    sts = main()
    sys.exit(sts)
