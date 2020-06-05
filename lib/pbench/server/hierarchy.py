import os
import time
from collections import OrderedDict


permdict = {
    "0": "---",
    "1": "--x",
    "2": "-w-",
    "3": "-wx",
    "4": "r--",
    "5": "r-x",
    "6": "rw-",
    "7": "rwx",
}


def filepermissions(mode):
    fperm = ""
    modebits = oct(mode)[-3:]
    for bits in modebits:
        if bits in permdict:
            fperm += permdict[bits]
        else:
            raise ValueError(
                f"Could not find key '{bits}' in file permissions dictionary"
            )

    return fperm


def header(fil, status, timestamp, hierarchy, path):
    if status == "start":
        fil.write(f"\n\n{status}-{timestamp}: {hierarchy} hierarchy: {path}\n")
    else:
        fil.write(f"\n{status}-{timestamp}: {hierarchy} hierarchy: {path}\n")


def dump_check(fil, hierarchy_check, controller, key):
    if controller in hierarchy_check[key]._dict:
        fil.write(f"\t{hierarchy_check[key].get_msg()}\n")
        output_format(fil, hierarchy_check[key]._dict[controller])
    return 1


def output_format(fil, controller_list):
    for val in sorted(controller_list):
        fil.write(f"\t\t{val}\n")
    return 1


class Hierarchy(object):
    def __init__(self, name, path, config):
        self.name = name
        self.path = path
        self.config = config


class DictOfList(object):
    """Class used to create and add elements to Dictionary
    """

    def __init__(self, msg):
        self._dict = OrderedDict()
        self._msg = msg

    def get_msg(self):
        return self._msg

    def add_entry(self, key, value):
        if key in self._dict:
            self._dict.get(key).append(value)
        else:
            self._dict[key] = [value]


class ArchiveHierarchy(Hierarchy):
    def __init__(self, name, path, config):
        super().__init__(name, path, config)

        self.controllers = list()
        self.bad_controllers = list()
        self.tarballs = list()
        self.archive_check = {
            "unexpected_dirs": DictOfList(
                "Unexpected state directories found in this controller directory:"
            ),
            "subdir_status_indicators": DictOfList(""),
            "unexpected_symlinks": DictOfList(
                "Unexpected symlinks in controller directory:"
            ),
            "unexpected_objects": DictOfList(
                "Unexpected files in controller directory:"
            ),
            "non_prefixes": DictOfList(
                "Unexpected file system objects in .prefix directory:"
            ),
            "wrong_prefixes": DictOfList(
                "Wrong prefix file names found in /.prefix directory:"
            ),
            "prefix_status_indicators": DictOfList(""),
        }

    def add_controller(self, controller):
        self.controllers.append(controller)

    def add_bad_controller(self, controller):
        self.bad_controllers.append(controller)

    def add_tarballs(self, controller):
        self.tarballs.append(controller)

    def add_unexpected_controllers(self, val, controller, dirs):
        self.archive_check[val].add_entry(controller, dirs)

    def dump(self, fil):
        cnt = 0
        check_h = False
        for controller in sorted(self.controllers):
            check_h = any(
                [
                    controller in self.archive_check[key]._dict
                    or controller not in self.tarballs
                    for key in self.archive_check
                ]
            )
        if check_h or self.bad_controllers:
            fil.write(f"\nstart-{self.config.TS[4:]}: archive hierarchy: {self.path}\n")
            if self.bad_controllers:
                fil.write("\nBad Controllers:\n")
                cnt += 1
                for controller in sorted(self.bad_controllers):
                    contStatOb = os.stat(controller)
                    fperm = filepermissions(contStatOb.st_mode)
                    mTime = time.strftime(
                        "%a %b %d %H:%M:%S.0000000000 %Y",
                        time.gmtime(contStatOb.st_mtime),
                    )
                    bname = os.path.basename(controller)
                    fil.write(f"\t-{fperm}          0 {mTime} {bname}\n")
            for controller in sorted(self.controllers):
                check = any(
                    [
                        controller in self.archive_check[key]._dict
                        for key in self.archive_check
                    ]
                )
                if check or controller not in self.tarballs:
                    fil.write(f"\nController: {controller}\n")

                    for key in self.archive_check:
                        cnt += self.dump_check(
                            fil, self.archive_check, controller, key, cnt
                        )

                    if controller not in self.tarballs:
                        fil.write(
                            "\t* No tar ball files found in this controller directory.\n"
                        )
                        cnt += 1

            fil.write(f"\nend-{self.config.TS[4:]}: archive hierarchy: {self.path}\n")
        return cnt

    def dump_check(self, fil, archive_check, controller, key, cnt):
        if controller in archive_check[key]._dict:
            if key != "subdir_status_indicators" and key != "prefix_status_indicators":
                fil.write(f"\t* {archive_check[key].get_msg()}\n")
                cnt = self.output_format(fil, archive_check[key]._dict[controller], cnt)
            elif "subdirs" in archive_check[key]._dict[controller]:
                fil.write(
                    "\t* No state directories found in this controller directory.\n"
                )
                cnt += 1
            elif "prefix_dir" in archive_check[key]._dict[controller]:
                fil.write("\t* Prefix directory, .prefix, is not a directory!\n")
                cnt += 1

        return cnt

    def output_format(self, fil, controller_list, cnt):
        fil.write("\t  ++++++++++\n")
        for val in sorted(controller_list):
            fil.write(f"\t  {val}\n")
        fil.write("\t  ----------\n")
        cnt += 1
        return cnt


class ControllerHierarchy(Hierarchy):
    def __init__(self, name, path, config):
        super().__init__(name, path, config)

        self.controllers = list()
        self.verifylist = list()
        self.controller_check = {
            "unexpected_objects": list(),
            "mialist": list(),
            "empty_controllers": list(),
            "unexpected_controllers": list(),
        }
        self.controller_msg = {
            "unexpected_objects": "Unexpected files found:",
            "mialist": f"Controllers which do not have a {self.config.ARCHIVE} directory:",
            "empty_controllers": "Controllers which are empty:",
            "unexpected_controllers": "Controllers which have unexpected objects:",
        }

    def add_controller(self, controller):
        self.controllers.append(controller)

    def add_controller_list(self, val, controller):
        self.controller_check[val].append(controller)

    def add_verifylist(self, controller):
        if controller not in self.verifylist:
            self.verifylist.append(controller)

    def dump(self, fil, ihier, chier):
        cnt = 0
        check = any([self.controller_check[val] for val in self.controller_check])
        if check:
            header(fil, "start", self.config.TS[4:], self.name, self.path)
            for val in self.controller_check:
                if self.controller_check[val]:
                    fil.write(f"\n{self.controller_msg[val]}\n")
                    cnt += self.output_format(fil, self.controller_check[val], cnt)
            if self.verifylist:
                cnt += ihier.dump(fil, 0)
            header(fil, "end", self.config.TS[4:], self.name, self.path)
        else:
            if self.verifylist:
                cnt += ihier.dump(fil, 1, chier)
        return cnt

    def output_format(self, fil, verify_tardir, cnt):
        for controller in sorted(verify_tardir):
            fil.write(f"\t{controller}\n")
            cnt += 1
        return cnt


class IncomingHierarchy(object):
    def __init__(self, config):

        self.config = config
        self.controllers = list()
        self.incoming_check = {
            "invalid_tb_dirs": DictOfList(
                f"Invalid tar ball directories (not in {self.config.ARCHIVE}):"
            ),
            "empty_tarball_dirs": DictOfList("Empty tar ball directories:"),
            "invalid_unpacking_dirs": DictOfList(
                "Invalid unpacking directories (missing tar ball):"
            ),
            "tarball_links": DictOfList("Invalid tar ball links:"),
        }

    def add_controller(self, controller):
        self.controllers.append(controller)

    def add_tarball_dirs(self, val, controller, dirt):
        self.incoming_check[val].add_entry(controller, dirt)

    def dump(self, fil, stat, hier=False):
        cnt = 0
        for controller in sorted(self.controllers):
            check = any(
                [
                    controller in self.incoming_check[key]._dict
                    for key in self.incoming_check
                ]
            )
            if check:
                cnt = 1
                if stat == 1:
                    header(fil, "start", self.config.TS[4:], hier.name, hier.path)
                fil.write(f"\nIncoming issues for controller: {controller}\n")

                for key in self.incoming_check:
                    dump_check(fil, self.incoming_check, controller, key)

                if stat == 1:
                    header(fil, "end", self.config.TS[4:], hier.name, hier.path)

        return cnt


class ResultsHierarchy(object):
    def __init__(self, config):

        self.config = config
        self.controllers = list()
        self.results_check = {
            "empty_tarball_dirs": DictOfList("Empty tar ball directories:"),
            "invalid_tb_links": DictOfList(
                f"Invalid tar ball links (not in {self.config.ARCHIVE}):"
            ),
            "incorrect_tb_dir_links": DictOfList(
                "Incorrectly constructed tar ball links:"
            ),
            "invalid_tb_dir_links": DictOfList(
                "Tar ball links to invalid incoming location:"
            ),
            "unused_prefix_files": DictOfList(
                "Tar ball links with unused prefix files:"
            ),
            "missing_prefix_files": DictOfList(
                "Tar ball links with missing prefix files:"
            ),
            "bad_prefix_files": DictOfList("Tar ball links with bad prefix files:"),
            "bad_prefixes": DictOfList("Tar ball links with bad prefixes:"),
            "unexpected_user_links": DictOfList(
                "Tar ball links not configured for this user:"
            ),
            "wrong_user_links": DictOfList("Tar ball links for the wrong user:"),
        }

    def add_controller(self, controller):
        self.controllers.append(controller)

    def add_tarball_dirs(self, val, controller, tbdir):
        self.results_check[val].add_entry(controller, tbdir)

    def dump(self, fil, stat, hier=False):
        cnt = 0
        for controller in sorted(self.controllers):
            check = any(
                [
                    controller in self.results_check[key]._dict
                    for key in self.results_check
                ]
            )
            if check:
                cnt = 1
                if stat == 1:
                    header(fil, "start", self.config.TS[4:], hier.name, hier.path)
                fil.write(f"\nResults issues for controller: {controller}\n")

                for key in self.results_check:
                    dump_check(fil, self.results_check, controller, key)

                if stat == 1:
                    header(fil, "end", self.config.TS[4:], hier.name, hier.path)

        return cnt


class UserHierarchy(Hierarchy):
    def __init__(self, name, path, config):
        super().__init__(name, path, config)

        self.user_dir = list()
        self.unexpected_objects = list()

    def add_unexpected_objects(self, user):
        self.unexpected_objects.append(user)

    def add_user_dir(self, user):
        self.user_dir.append(user)

    def dump(self, fil, hier, uhier):
        cnt = 0
        if self.unexpected_objects:
            header(fil, "start", self.config.TS[4:], self.name, self.path)
            fil.write("\nUnexpected files found:\n")
            for controller in sorted(self.unexpected_objects):
                fil.write(f"\t{controller}\n")
            cnt = cnt + 1
            if self.user_dir:
                cnt += hier.dump(fil, 0)
            header(fil, "end", self.config.TS[4:], self.name, self.path)
        else:
            if self.user_dir:
                cnt += hier.dump(fil, 1, uhier)

        return cnt
