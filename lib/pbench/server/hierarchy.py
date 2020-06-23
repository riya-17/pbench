""" Collection and Structure Module for pbench-audit-server
"""

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
    """Convert File permissions from numeric to symbolic.
    from '755' --> 'rwxr-xr-x' """
    fperm = ""
    modebits = oct(mode)[-3:]
    for bits in modebits:
        try:
            fperm += permdict[bits]
        except IndexError:
            raise ValueError(
                f"Could not find key '{bits}' in file permissions dictionary"
            )

    return fperm


class Hierarchy(object):
    """Super class of Hierarchies"""

    def __init__(self, name, path, config):
        self.name = name
        self.path = path
        self.config = config

    def header(self, fp, status):
        """Adds main starting and ending messages for each Hierarchy"""
        lead_newline = "\n" if status == "start" else ""
        fp.write(
            f"{lead_newline}\n{status}-{self.config.TS[4:]}: {self.name} hierarchy: {self.path}\n"
        )
        return

    def check_controller_in_list(self, controller, hierarchy_check):
        """Checks whether there are controllers in dictionary or not"""
        return any(
            [controller in hierarchy_check[key]._dict for key in hierarchy_check]
        )

    def _dump(self, fp, hierarchy_check):
        """Validates and Output collected data"""
        cnt = 0
        for controller in sorted(self.controllers):
            if self.check_controller_in_list(controller, hierarchy_check):
                fp.write(f"\n{self.name.title()} issues for controller: {controller}\n")
                for key in hierarchy_check:
                    cnt = self.dump_check(fp, hierarchy_check, controller, key, cnt)

        return cnt

    """
    ##FIXME: The mention of hierarchies(archive, controller) from here on, in
            Hierarchy class is mainly to keep the format algned with the shell script
    """

    def dump_check(self, fp, hierarchy_check, controller, key, cnt, hierarchy=False):
        """Output Messages for each list of controllers, files,
        directories, etc depicting their cause of being added to
        that list or dictionary
        """
        lead_asterisk = "\t* " if hierarchy == "archive" else "\t"
        if controller in hierarchy_check[key]._dict:
            if key not in ["subdir_status_indicators", "prefix_status_indicators"]:
                fp.write(f"{lead_asterisk}{hierarchy_check[key]._get_msg()}\n")
                if hierarchy == "archive":
                    cnt = self.output_format(
                        fp, hierarchy_check[key]._dict[controller], cnt, "archive"
                    )
                else:
                    cnt = self.output_format(
                        fp, hierarchy_check[key]._dict[controller], cnt
                    )
            elif "subdirs" in hierarchy_check[key]._dict[controller]:
                fp.write(
                    "\t* No state directories found in this controller directory.\n"
                )
                cnt += 1
            elif "prefix_dir" in hierarchy_check[key]._dict[controller]:
                fp.write("\t* Prefix directory, .prefix, is not a directory!\n")
                cnt += 1
        return cnt

    def check_tab_format(self, hierarchy):
        """Check the format of tab acc. to hierarchy"""

        lead_tab = ""
        if hierarchy == "controller":
            lead_tab = "\t"
        elif hierarchy == "archive":
            lead_tab = "\t  "

        return lead_tab

    def output_format(self, fp, controller_list, cnt, hierarchy=False):
        """Output format of list"""

        lead_tab = self.check_tab_format(hierarchy) if hierarchy else "\t\t"
        if hierarchy == "archive":
            fp.write("\t  ++++++++++\n")
        self.output_list(fp, lead_tab, controller_list)
        if hierarchy == "archive":
            fp.write("\t  ----------\n")
        cnt += 1
        return cnt

    def output_list(self, fp, lead_tab, controller_list):
        """ Writing list value to file"""
        for value in sorted(controller_list):
            fp.write(f"{lead_tab}{value}\n")
        return


class DictOfList(object):
    """Class used to create and add elements to Dictionary"""

    def __init__(self, msg):
        self._dict = OrderedDict()
        self._msg = msg

    def _get_msg(self):
        return self._msg

    def __setitem__(self, key, value):
        if key in self._dict:
            self._dict[key].append(value)
        else:
            self._dict[key] = [value]


class List(object):
    """Class used to create and add elements to Dictionary"""

    def __init__(self, msg):
        self._list = list()
        self._msg = msg

    def _get_msg(self):
        return self._msg

    def additem(self, value):
        self._list.append(value)

    def getlist(self):
        return self._list


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
        """Gather values for each archive_check dict key"""
        self.archive_check[val][controller] = dirs

    def dump(self, fp):
        """Checks and Output collected data"""
        cnt = 0
        if self.bad_controllers:
            self.output_bad_controllers(fp)
            cnt += 1
        for controller in sorted(self.controllers):
            check = self.check_controller_in_list(controller, self.archive_check)
            if check or controller not in self.tarballs:
                fp.write(f"\nController: {controller}\n")
                for key in self.archive_check:
                    cnt += self.dump_check(
                        fp, self.archive_check, controller, key, cnt, "archive"
                    )
                if controller not in self.tarballs:
                    fp.write(
                        "\t* No tar ball files found in this controller directory.\n"
                    )
                    cnt += 1
        return cnt

    def check_controller_in_archive(self):
        for controller in sorted(self.controllers):
            if (
                self.check_controller_in_list(controller, self.archive_check)
                or controller not in self.tarballs
            ):
                return True
        return False

    def output_bad_controllers(self, fp):
        fp.write("\nBad Controllers:\n")
        for controller in sorted(self.bad_controllers):
            """Formatting output into ls -l format to align
            output with gold files
            """
            contStatOb = os.stat(controller)
            fperm = filepermissions(contStatOb.st_mode)
            mTime = time.strftime(
                "%a %b %d %H:%M:%S.0000000000 %Y", time.gmtime(contStatOb.st_mtime)
            )
            bname = os.path.basename(controller)
            fp.write(f"\t-{fperm}          0 {mTime} {bname}\n")
        return


class ControllerHierarchy(Hierarchy):
    def __init__(self, name, path, config):
        super().__init__(name, path, config)

        self.controllers = list()
        self.verifylist = list()
        self.controller_check = {
            "unexpected_objects": List("Unexpected files found:"),
            "mialist": List(
                f"Controllers which do not have a {self.config.ARCHIVE} directory:"
            ),
            "empty_controllers": List("Controllers which are empty:"),
            "unexpected_controllers": List(
                "Controllers which have unexpected objects:"
            ),
        }

    def add_controller(self, controller):
        self.controllers.append(controller)

    def add_controller_list(self, val, controller):
        """Gather values for each controller_check dict key"""
        self.controller_check[val].additem(controller)

    def add_verifylist(self, controller):
        if controller not in self.verifylist:
            self.verifylist.append(controller)

    def check_controller_in_controller(self):
        return any(
            [self.controller_check[val].getlist() for val in self.controller_check]
        )

    def dump(self, fp):
        """Validates and Output collected Hierarchy data"""
        cnt = 0
        for val in self.controller_check:
            if self.controller_check[val].getlist():
                fp.write(f"\n{self.controller_check[val]._get_msg()}\n")
                cnt += self.output_format(
                    fp, self.controller_check[val].getlist(), cnt, "controller"
                )
        return cnt


class IncomingHierarchy(Hierarchy):
    def __init__(self, name, path, config):
        super().__init__(name, path, config)

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
        """Gather values for each incoming_check dict key"""
        self.incoming_check[val][controller] = dirt

    def check_controller_in_incoming(self):
        for controller in sorted(self.controllers):
            if self.check_controller_in_list(controller, self.incoming_check):
                return True
        return False

    def dump(self, fp):
        """Validates and output collected data"""
        return self._dump(fp, self.incoming_check)


class ResultsHierarchy(Hierarchy):
    def __init__(self, name, path, config):
        super().__init__(name, path, config)

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
        """Gather values for each results_check dict key"""
        self.results_check[val][controller] = tbdir

    def check_controller_in_results(self):
        for controller in sorted(self.controllers):
            if self.check_controller_in_list(controller, self.results_check):
                return True
        return False

    def dump(self, fp):
        """Validates and Output collected data"""
        return self._dump(fp, self.results_check)


class UserHierarchy(Hierarchy):
    def __init__(self, name, path, config):
        super().__init__(name, path, config)

        self.user_dir = list()
        self.unexpected_objects = list()

    def add_unexpected_objects(self, user):
        self.unexpected_objects.append(user)

    def add_user_dir(self, user):
        self.user_dir.append(user)

    def check_controller_in_users(self):
        if self.unexpected_objects:
            return True
        return False

    def dump(self, fp):
        """Validates and Output Collected data"""
        cnt = 0
        fp.write("\nUnexpected files found:\n")
        for controller in sorted(self.unexpected_objects):
            fp.write(f"\t{controller}\n")
        cnt = cnt + 1

        return cnt
