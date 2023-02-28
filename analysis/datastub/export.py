"""
Copyright (C) 2017-2018 IAIK TU Graz and Fraunhofer AISEC

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

##
# @package analysis.datastub.export
# @file export.py
# @brief Everything related to storing and loading leaks and more.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3


import os
import gzip
import subprocess
import shlex
import pickle
from datastub.DataFS import DataFS
from datastub.IpInfoShort import IpInfoShort, IP_INFO_FILE
from datastub.SymbolInfo import SymbolInfo
from datastub.utils import debug

"""
*************************************************************************
"""


def storepickle(pfile, leaks):
    debug(1, "Storing pickle file")
    with gzip.GzipFile(pfile, "wb", compresslevel=6) as f:
        pickle.dump(leaks, f)


"""
*************************************************************************
"""


class MyUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        result = None
        # These files have been moved into 'datastub' package
        mapper = [
            "leaks",
            "IpInfoShort",
            "DataFS",
            "export",
            "printer",
            "SortedCollection",
            "SymbolInfo",
        ]
        if module in mapper:
            module = "datastub." + module
        try:
            result = super().find_class(module, name)
        except Exception as e:
            debug(0, "Error unpickling module %s, object %s" % (module, name))
            debug(1, "Exception: " + str(e))
            raise e
        return result

    def load_global(self):
        module = self.readline()[:-1].decode("utf-8")
        print("Module: " + module)
        name = self.readline()[:-1].decode("utf-8")
        print("Name: " + module)
        klass = self.find_class(module, name)
        print("Class: " + klass)
        self.append(klass)


"""
*************************************************************************
"""


def loadpickle(pfile):
    debug(1, "Loading pickle file")
    try:
        with gzip.GzipFile(pfile, "rb", compresslevel=6) as f:
            unp = MyUnpickler(f, encoding="latin1")
            new = unp.load()
            return new
    except Exception as e:
        raise IOError("Error loading pickle file: %s" % str(e))


"""
*************************************************************************
"""


def getGdbSourceFileInfo(addr, binary_path):
    command = f"gdb -ex 'set print asm-demangle on' -ex 'info line *{addr}' -ex quit {binary_path}"
    output = subprocess.check_output(shlex.split(command)).decode("utf-8")
    tmp = "No line number information available"
    if not tmp in output:
        return None, 0
    tmp = output.split(tmp)[1]
    tmp = tmp.split("<", 1)[1]
    tmp = tmp[::-1].split(">", 1)[1]
    output = tmp[::-1]

    tmp = "@plt"
    if not tmp in output:
        return None, 0
    fn_name = output.split(tmp)[0]

    command = f"gdb -ex 'set print asm-demangle on' -ex 'info line {fn_name}' -ex quit {binary_path}"
    output = subprocess.check_output(shlex.split(command)).decode("utf-8")
    tmp = "Line"
    if not tmp in output:
        return None, 0
    linenr, _, rel_filepath = output.split(tmp)[-1].splitlines()[0].lstrip().split(" ")
    linenr = int(linenr)
    rel_filepath = rel_filepath.strip('"')
    basepath = "/".join(binary_path.split("/")[:-1])
    filepath = f"{basepath}/{rel_filepath}"

    debug(2, "[SRC] available via gdb for %s in %s", (addr, binary_path))
    debug(2, f"[SRC] in {filepath}:{linenr}")
    return filepath, linenr


def getSourceFileInfo(addr, binary_path):
    # e.g., addr2line 0x42d4b9 -e openssl
    #   -> file_name:line_nr
    # from man pages:
    # if the filename cannot be determined -> print two question marks
    # if the line nr cannot be determined  -> print 0
    try:
        output = subprocess.check_output(
            ["addr2line", addr, "-e", binary_path], universal_newlines=True
        )
        infos = output.split(":")
        source_file_path, source_line_number = infos[0], infos[1]
        if "??" == source_file_path:
            raise subprocess.CalledProcessError(1, "addr2line")
    except subprocess.CalledProcessError:
        debug(2, "[SRC] unavailable for %s in %s", (addr, binary_path))
        return getGdbSourceFileInfo(addr, binary_path)

    if "discriminator" in source_line_number:
        source_line_number = source_line_number.split()[0]

    try:
        source_line_number = int(source_line_number)
    except ValueError:
        source_line_number = 0

    return source_file_path, source_line_number


"""
*************************************************************************
"""


def getAsmFileInfo(addr, asm_dump):
    line_count = 0
    search_str = format(addr, "x") + ":"
    for asm_line in asm_dump.splitlines():
        if search_str in asm_line:
            return line_count
        line_count += 1
    return -1


"""
*************************************************************************
"""

DOWNLOADED_PACKAGE_SOURCES = list()

def searchSourceInPackages(bin_file_path, ip):

    def search_in_directory(filename, filepath):
        command = f"find -iname {filename}"
        debug(4, f"exec: {command}")
        output = subprocess.check_output(shlex.split(command)).decode("utf-8")
        lines = output.splitlines()
        filepath_chunks = 1
        while len(lines) > 1:
            filepath_chunks += 1
            filename = "/".join(filepath.split("/")[-filepath_chunks:])
            lines = [line for line in lines if filename in line]
        if len(lines) == 1:
            return lines[0]
        else:
            return None


    if bin_file_path not in DOWNLOADED_PACKAGE_SOURCES:
        # Identify source
        command = f"dpkg -S {bin_file_path}"
        debug(4, f"exec: {command}")
        output = subprocess.check_output(shlex.split(command)).decode("utf-8")
        lines = output.splitlines()
        assert len(lines) == 1
        package = lines[0].split(":")[0]

        # Download source package
        command = f"apt-get source {package}"
        debug(4, f"exec: {command}")
        subprocess.check_output(shlex.split(command))

        DOWNLOADED_PACKAGE_SOURCES.append(bin_file_path)

    # Use gdb to get filename for address
    command = f"gdb -batch -ex 'set print asm-demangle on' -ex 'info line *{hex(ip)}' {bin_file_path}"
    debug(4, f"exec: {command}")
    output = subprocess.check_output(shlex.split(command)).decode("utf-8")
    lines = output.splitlines()
    assert len(lines) == 1
    if "No line number information available" in lines[0]:
        return None, 0
    line = lines[0].split("starts at address ")[1].split(" and ends at")[0]
    line = line.split("<", 1)[1]
    line = line[::-1].split(">", 1)[1]
    if "+" in line:
        line = line.split("+", 1)[1]
    functionname = line[::-1]
    filelinenumber = int(lines[0].split(" ")[1])

    command = f"gdb -batch -ex 'set print asm-demangle on' -ex 'info line {functionname}' {bin_file_path}"
    debug(4, f"exec: {command}")
    output = subprocess.check_output(shlex.split(command)).decode("utf-8")
    lines = output.splitlines()
    assert len(lines) == 1
    filepath = lines[0].split('"')[1]
    filename = filepath.split("/")[-1]

    src_file_path = search_in_directory(filename, filepath)
    if src_file_path is not None:
        return src_file_path, filelinenumber

    # Check if there are any tar.xz with the source code
    command = f"ls **/*.tar.xz | xargs -n 1 -i bash -c 'tar -tf {str('{}')} | grep {filename} | wc -l | xargs echo {str('{}')}'"
    debug(4, f"exec: {command}")
    output = subprocess.check_output(command, shell=True).decode("utf-8")
    lines = output.splitlines()
    parts_list = [parts for line in lines if int((parts := line.split(" "))[1])]
    assert len(parts_list) == 1
    [tarball, cnt] = parts_list[0]

    # Extract files and remove tarball
    command = f"tar -xvf {tarball}"
    debug(4, f"exec: {command}")
    subprocess.check_output(shlex.split(command))

    command = f"rm {tarball}"
    debug(4, f"exec: {command}")
    subprocess.check_output(shlex.split(command))

    src_file_path = search_in_directory(filename, filepath)
    assert src_file_path is not None
    return src_file_path, filelinenumber


def export_ip(ip, datafs, imgmap, info_map):
    if ip is None or ip == 0:
        return
    if ip not in info_map:
        sym = SymbolInfo.lookup(ip)
        assert sym is not None
        if sym.img.dynamic:
            addr = ip - sym.img.lower
        else:
            addr = ip
        bin_file_path = sym.img.name
        asm_file_path = bin_file_path + ".asm"
        # Add binary (ELF) + ASM objdump to datafs
        if bin_file_path not in imgmap:
            try:
                datafs.add_file(bin_file_path)
            except FileNotFoundError:
                debug(0, "Error: Binary file missing: %s", (bin_file_path))
                return
            except Exception as error:
                debug(0, f"lookup: {error} not catched!")
                debug(0, "Error: Binary file missing: %s", (bin_file_path))
                return
            asm_dump = ""
            try:
                debug(1, "[ASM] objdump %s", (str(bin_file_path)))
                with datafs.create_file(asm_file_path) as f:
                    subprocess.call(
                        [
                            "objdump",
                            "--disassemble",
                            "--demangle",
                            "--source",
                            "--no-show-raw-insn",
                            bin_file_path,
                        ],
                        universal_newlines=True,
                        stdout=f,
                    )
                    f.seek(0)
                    asm_dump = f.read().decode("utf-8")
            except subprocess.CalledProcessError as err:
                debug(
                    0,
                    "[ASM] objdump %s failed with error_code: %s",
                    (str(bin_file_path), str(err.returncode)),
                )
                asm_dump = None
            imgmap[bin_file_path] = asm_dump
        if ip not in info_map:
            # Search for leak in asm dump
            asm_dump = imgmap[bin_file_path]
            asm_line_nr = getAsmFileInfo(addr, asm_dump)
            if asm_line_nr < 0:
                debug(1, "[ASM] unavailable for %s in %s", (hex(addr), bin_file_path))
            # Search for leak in source code
            src_file_path, src_line_nr = getSourceFileInfo(hex(addr), bin_file_path)
            if src_file_path is None:
                src_file_path, src_line_nr = searchSourceInPackages(bin_file_path, addr)
                debug(
                    1, "[SRC] available in package sources for %s in %s", (hex(addr), bin_file_path)
                )
            if src_file_path is not None and os.path.exists(src_file_path):
                datafs.add_file(src_file_path)
            elif src_file_path is None:
               debug(
                   1, "[SRC] unavailable for %s in %s", (hex(addr), bin_file_path)
               )
            else:
                debug(1, "[SRC] source file %s missing", (src_file_path))
            ip_info = IpInfoShort(
                asm_file_path, asm_line_nr, src_file_path, src_line_nr
            )
            info_map[ip] = ip_info


"""
*************************************************************************
"""


def export_ip_recursive(leaks, datafs, imgmap, info_map):
    if leaks.ctxt is not None:
        export_ip(leaks.ctxt.caller, datafs, imgmap, info_map)
        export_ip(leaks.ctxt.callee, datafs, imgmap, info_map)
    for leak in leaks.dataleaks:
        export_ip(leak.ip, datafs, imgmap, info_map)
    for leak in leaks.cfleaks:
        export_ip(leak.ip, datafs, imgmap, info_map)
    for k in leaks.children:
        child = leaks.children[k]
        export_ip_recursive(child, datafs, imgmap, info_map)


"""
*************************************************************************
"""


def export_leaks(callHistory, zipfile, syms):
    datafs = DataFS(zipfile, write=True)
    imgmap = {}
    info_map = {}
    export_ip_recursive(callHistory, datafs, imgmap, info_map)
    with datafs.create_file(IP_INFO_FILE) as f:
        pickle.dump(info_map, f)
    datafs.add_file(syms.name)
    datafs.close()
