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


# Archive Hierarchy


def verify_subdirs(hier, controller, directories):
    linkdirs = sorted(hier.config.LINKDIRS.split(" "))
    if directories:
        for dirent in directories:
            if all(
                [
                    os.path.exists(os.path.join(hier.path, controller, dirent)),
                    dirent != "_QUARANTINED",
                    not dirent.startswith("WONT-INDEX"),
                ]
            ):
                if dirent not in linkdirs:
                    hier.add_unexpected_controllers(
                        "unexpected_dirs", controller, dirent
                    )
    else:
        hier.add_unexpected_controllers(
            "subdir_status_indicators", controller, "subdirs"
        )

    return 0


def verify_prefixes(hier, controller):
    prefix_dir = os.path.join(hier.path, controller, ".prefix")
    if not os.path.exists(prefix_dir):
        return
    if not os.path.isdir(prefix_dir):
        hier.add_unexpected_controllers(
            "prefix_status_indicators", controller, "prefix_dir"
        )
        return

    prefixes = glob.iglob(os.path.join(prefix_dir, "*"))

    for prefix in prefixes:
        base_prefix = os.path.basename(prefix)
        if not base_prefix.startswith("prefix.") and not base_prefix.endswith(
            ".prefix"
        ):
            hier.add_unexpected_controllers("non_prefixes", controller, base_prefix)
        elif base_prefix.startswith("prefix."):
            hier.add_unexpected_controllers("wrong_prefixes", controller, base_prefix)

    return


# 'hier' is an object of ArchiveHierarchy class imported from hierarchy.py
def verify_archive(hier):
    controllers = glob.iglob(os.path.join(hier.path, "*"))

    # Find all the non-directory files at the same level of the controller
    # directories and report them, and find all the normal controller directories.
    for controller in controllers:
        if os.path.isdir(controller):
            hier.add_controller(os.path.basename(controller))
        else:
            hier.add_bad_controller(controller)

    # now check each "good" controller and get the tarballs it contains
    for controller in hier.controllers:
        direct_entries = glob.iglob(os.path.join(hier.path, controller, "*"))
        hidden_entries = glob.glob(os.path.join(hier.path, controller, ".*"))
        if hidden_entries:
            for hid_entries in hidden_entries:
                if os.path.isfile(hid_entries):
                    hier.add_unexpected_controllers(
                        "unexpected_objects", controller, os.path.basename(hid_entries)
                    )
        controller_subdir = list()
        for item in direct_entries:
            base_item = os.path.basename(item)
            if os.path.isdir(item):
                controller_subdir.append(base_item)
            elif os.path.islink(item):
                symlink_item = f"{base_item} -> {os.path.realpath(item)}"
                hier.add_unexpected_controllers(
                    "unexpected_symlinks", controller, symlink_item
                )
            elif all(
                [
                    os.path.isfile(item),
                    not base_item.endswith(".tar.xz"),
                    not base_item.endswith(".tar.xz.md5"),
                ]
            ):
                hier.add_unexpected_controllers(
                    "unexpected_objects", controller, base_item
                )
            elif os.path.isfile(item) and (
                base_item.endswith(".tar.xz") or base_item.endswith(".tar.xz.md5")
            ):
                hier.add_tarballs(controller)
            else:
                print(
                    f"{base_item} item should have been handled by the above mentioned conditions. "
                    f"It is an unexpected item which should not have occured, "
                    f"leading to an inappropriate condition"
                )
        verify_subdirs(hier, controller, controller_subdir)
        verify_prefixes(hier, controller)

    return


# Incoming Hierarchy


def verify_tar_dirs(ihier, tarball_dirs, tblist, controller):
    for tb in tarball_dirs:
        if tb.endswith("unpack"):
            tar = tb[:-7]
            tar = f"{tar}.tar.xz"
            val = "invalid_unpacking_dirs"
        else:
            tar = f"{tb}.tar.xz"
            val = "invalid_tb_dirs"
        tarfile = os.path.join(ihier.config.ARCHIVE, controller, tar)
        if os.path.exists(tarfile):
            with open(tarfile, "r") as f:
                try:
                    file_content = f.read(1)
                    if file_content:
                        continue
                except Exception:
                    pass
        else:
            tblist(val, controller, os.path.basename(tb))


# 'ihier' is IncomingHierarchy class object
def verify_incoming(ihier, verifylist):

    for controller in verifylist:
        ihier.add_controller(controller)
        direct_entries = glob.iglob(
            os.path.join(ihier.config.INCOMING, controller, "*")
        )
        tarball_dirs, unpacking_tarball_dirs = (list() for i in range(2))

        if not os.path.isdir(os.path.join(ihier.config.ARCHIVE, controller)):
            # Skip incoming controller directories that don't have an $ARCHIVE
            # directory, handled in another part of the audit.
            continue

        for dirent in direct_entries:
            dirt = os.path.basename(dirent)
            if (
                os.path.isdir(dirent)
                and not dirt.endswith(".unpack")
                and not len(os.listdir(dirent)) == 0
            ):
                tarball_dirs.append(dirt)
            elif (
                os.path.isdir(dirent)
                and not dirt.endswith(".unpack")
                and len(os.listdir(dirent)) == 0
            ):
                ihier.add_tarball_dirs("empty_tarball_dirs", controller, dirt)
            elif (
                os.path.isdir(dirent)
                and dirt.endswith(".unpack")
                and len(os.listdir(dirent)) == 0
            ):
                unpacking_tarball_dirs.append(dirt)
            elif os.path.islink(dirent):
                ihier.add_tarball_dirs("tarball_links", controller, dirt)

        if tarball_dirs:
            verify_tar_dirs(ihier, tarball_dirs, ihier.add_tarball_dirs, controller)

        if unpacking_tarball_dirs:
            verify_tar_dirs(
                ihier, unpacking_tarball_dirs, ihier.add_tarball_dirs, controller,
            )

    return 0


# Results Hierarchy


def verify_user_arg(rhier, mdlogcfg, user_arg, controler, path):
    user = ""
    try:
        user = mdlogcfg.get("run", "user")
    except NoSectionError:
        pass
    except NoOptionError:
        pass
    if not user:
        # No user in the metadata.log of the tar ball, but
        # we are examining a link in the user tree that
        # does not have a configured user, report it.
        rhier.add_tarball_dirs("unexpected_user_links", controler, path)
    elif user_arg != user:
        # Configured user does not match the user tree in
        # which we found the link.
        rhier.add_tarball_dirs("wrong_user_links", controler, path)

    return


# 'rhier' is ResultsHierarchy class  and 'hier' is a
# ControllerHierarchy class object. user_arg consists of
# users which gets passed from user hierarchy.
def verify_results(rhier, hier, user_arg=False):
    if user_arg:
        results_hierarchy = os.path.join(rhier.config.USERS, user_arg)
    else:
        results_hierarchy = hier.path

    for controller in hier.verifylist:
        tarball_dirs, unpacking_tarball_dirs = (list() for i in range(2))
        if not os.path.isdir(os.path.join(rhier.config.ARCHIVE, controller)):
            # Skip incoming controller directories that don't have an $ARCHIVE
            # directory, handled in another part of the audit.
            continue

        dirent_entries = list()
        for root, dirs, files in os.walk(
            os.path.join(results_hierarchy, controller), topdown=True
        ):
            for name in files:
                dirent_entries.append(os.path.join(root, name))
            for name in dirs:
                dirent_entries.append(os.path.join(root, name))

        if user_arg:
            controler = f"{user_arg}/{controller}"
            rhier.add_controller(controler)
        else:
            rhier.add_controller(controller)

        for dirent in dirent_entries:
            base_dir = os.path.basename(dirent)
            path = dirent.split(os.path.join(controller, ""), 1)[1]
            if os.path.isdir(dirent) and len(os.listdir(dirent)) == 0:
                if user_arg:
                    rhier.add_tarball_dirs("empty_tarball_dirs", controler, path)
                else:
                    rhier.add_tarball_dirs("empty_tarball_dirs", controller, path)
            elif os.path.islink(dirent):
                link = os.path.realpath(dirent)
                tb = f"{os.path.basename(path)}.tar.xz"
                incoming_path = os.path.join(
                    rhier.config.INCOMING, controller, base_dir
                )
                if not os.path.exists(
                    os.path.join(rhier.config.ARCHIVE, controller, tb)
                ):
                    rhier.add_tarball_dirs("invalid_tb_links", controller, base_dir)
                else:
                    if link != incoming_path:
                        rhier.add_tarball_dirs(
                            "incorrect_tb_dir_links", controller, base_dir
                        )
                    elif not os.path.isdir(incoming_path) and not os.path.islink(
                        incoming_path
                    ):
                        rhier.add_tarball_dirs(
                            "invalid_tb_dir_links", controller, base_dir
                        )
                    else:
                        prefix_path = os.path.dirname(path)
                        prefix_file = os.path.join(
                            rhier.config.ARCHIVE, controller, ".prefix", base_dir
                        )
                        prefix_file = f"{prefix_file}.prefix"
                        mdlogcfg = PbenchMDLogConfig(
                            os.path.join(incoming_path, "metadata.log")
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
                                rhier.add_tarball_dirs("bad_prefixes", controller, path)
                            elif os.path.exists(prefix_file):
                                rhier.add_tarball_dirs(
                                    "unused_prefix_files", controller, path
                                )
                        else:
                            if prefix:
                                if prefix != prefix_path:
                                    rhier.add_tarball_dirs(
                                        "bad_prefixes", controller, path
                                    )
                            elif not os.path.exists(prefix_file):
                                rhier.add_tarball_dirs(
                                    "missing_prefix_files", controller, path
                                )
                            else:
                                f = 0
                                try:
                                    with open(prefix_file, "r") as file:
                                        prefix = file.read().replace("\n", "")
                                except Exception:
                                    f = 1
                                    pass
                                if f == 1:
                                    rhier.add_tarball_dirs(
                                        "bad_prefix_files", controller, path
                                    )
                                else:
                                    if prefix != prefix_path:
                                        rhier.add_tarball_dirs(
                                            "bad_prefixes", controller, path
                                        )
                        if user_arg:
                            # We are reviewing a user tree, so check the user in
                            # the configuration.  Version 002 agents use the
                            # metadata log to store a user as well.
                            verify_user_arg(rhier, mdlogcfg, user_arg, controler, path)

    return


# Controller Hierarchy

hierarchy_dispatcher = {
    "incoming": verify_incoming,
    "results": verify_results,
    "users": verify_results,
}


# ihier is either IncomingHierarchy class object or ResultsHierarchy
# class object based on the instance it is called and hier is a
# ControllerHierarchy class object. hierarchy is the path of the
# respective hierarchy
def verify_hierarchy(ihier, hier, hierarchy):

    hierchy = os.path.basename(hierarchy)
    users = hier.config.USERS

    if hier.verifylist:
        if hierchy == "incoming":
            hierarchy_dispatcher[hierchy](ihier, hier.verifylist)
        elif hierchy == "results":
            hierarchy_dispatcher[hierchy](ihier, hier)
        elif os.path.dirname(hierarchy) == str(users):
            hierarchy_dispatcher["users"](ihier, hier, hierchy)
        else:
            print(
                '${PROG}: verify_controllers bad argument, hierarchy_root="${hierarchy}"\n'
            )
            return 1
    return 0


# 'ihier' is either IncomingHierarchy class object or ResultsHierarchy
# class object based on the instance it is called and hier is a
# ControllerHierarchy class object. hierarchy is the path of the
# respective hierarchy
def verify_controllers(ihier, hier, hierarchy):

    controllers = glob.iglob(os.path.join(hier.path, "*"))

    # Find all the normal controller directories
    for controller in controllers:
        if os.path.isdir(controller):
            hier.add_controller(os.path.basename(controller))
        else:
            hier.add_controller_list("unexpected_objects", os.path.basename(controller))

    if hier.controllers:
        for controller in hier.controllers:
            dirent = os.path.join(hier.path, controller)
            unexpected_dirs = list()
            if not os.path.isdir(os.path.join(hier.config.ARCHIVE, controller)):
                # We have a controller in the hierarchy which does not have a
                # controller of the same name in the archive hierarchy.  All
                # we do is report it, don't bother analyzing it further.
                hier.add_controller_list("mialist", os.path.basename(controller))
            else:
                # Report any controllers with objects other than directories
                # and links, while also recording any empty controllers.
                if len(os.listdir(dirent)) == 0:
                    hier.add_controller_list("empty_controllers", controller)
                    continue
                else:
                    direct_entries = glob.iglob(
                        os.path.join(hier.path, controller, "*")
                    )
                    for item in direct_entries:
                        if not os.path.isdir(item) and not os.path.islink(item):
                            unexpected_dirs.append(controller)

                if unexpected_dirs:
                    hier.add_controller_list("unexpected_controllers", controller)
                hier.add_verifylist(controller)

    if verify_hierarchy(ihier, hier, hierarchy) > 0:
        return 1

    return 0


# User Hierarchy

# 'rhier' is the ResultsHierarchy class object,
# 'chier' is ControllerHierarchy class object and
# 'hier' is UserHierarchy class object.
def verify_users(rhier, chier, hier):
    cnt = 0
    users = hier.path

    if not os.path.isdir(users):
        print(
            "The setting for USERS in the config file is {}, but that is"
            " not a directory",
            users,
        )
        return 1

    users_dirs = glob.iglob(os.path.join(users, "*"))
    user_dir = list()

    for user in users_dirs:
        u = os.path.basename(user)
        if os.path.isdir(user):
            user_dir.append(user)
            hier.add_user_dir(u)
        else:
            hier.add_unexpected_objects(u)

    if user_dir:
        for user in user_dir:
            verify_controllers(rhier, chier, user)
            if cnt > 0:
                cnt = cnt + 1

    return


# check function deals with handling the integrity of
# ARCHIVE, INCOMING, RESULTS and USERS hierarchy
def check_func(name, pbdirname):
    pbdir = name
    pbdir_p = os.path.realpath(pbdir)

    if not pbdir_p:
        print(f"{_NAME_}: Bad {pbdirname}={pbdir}", file=sys.stderr)
        return 1

    if not os.path.isdir(pbdir_p):
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
        os.mkdir(os.path.join(config.LOGSDIR, "pbench-audit-server"))
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
        cnt = ahier.dump(f)
        if cnt > 0:
            ret += 1

        ihier = IncomingHierarchy(config)
        cihier = ControllerHierarchy("incoming", config.INCOMING, config)
        verify_controllers(ihier, cihier, config.INCOMING)
        cnt = cihier.dump(f, ihier, cihier)
        if cnt > 0:
            ret += 1

        rhier = ResultsHierarchy(config)
        crhier = ControllerHierarchy("results", config.RESULTS, config)
        verify_controllers(rhier, crhier, config.RESULTS)
        cnt = crhier.dump(f, rhier, crhier)
        if cnt > 0:
            ret += 1

        ruhier = ResultsHierarchy(config)
        cuhier = ControllerHierarchy("results", config.RESULTS, config)
        uhier = UserHierarchy("users", config.USERS, config)
        verify_users(ruhier, cuhier, uhier)
        cnt = uhier.dump(f, ruhier, uhier)
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
