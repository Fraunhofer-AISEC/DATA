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
            raise subprocess.CalledProcessError
    except subprocess.CalledProcessError:
        debug(2, "[SRC] unavailable for %s in %s", (addr, binary_path))
        return None, 0
    except Exception as error:
        debug(0, f"lookup: {error} not catched!")
        debug(2, "[SRC] unavailable for %s in %s", (addr, binary_path))
        return None, 0

    if "discriminator" in source_line_number:
        source_line_number = source_line_number.split()[0]

    try:
        source_line_number = int(source_line_number)
    except ValueError:
        source_line_number = 0
    except Exception as error:
        debug(0, f"lookup: {error} not catched!")
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
                # asm_dump = subprocess.check_output(["objdump", "-Dj", ".text", bin_file_path], universal_newlines=True)
                with datafs.create_file(asm_file_path) as f:
                    subprocess.call(
                        ["objdump", "-dS", bin_file_path],
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
            if src_file_path is not None and os.path.exists(src_file_path):
                datafs.add_file(src_file_path)
            else:
                if src_file_path is None:
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
