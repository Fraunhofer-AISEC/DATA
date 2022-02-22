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
# @package analysis.datastub.symbolinfo
# @file SymbolInfo.py
# @brief Binary symbol information.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3


import sys
import os.path
import subprocess
from operator import itemgetter
from datastub.SortedCollection import SortedCollection
from datastub.utils import debug

"""
*************************************************************************
"""


def readelfsyms(fname, image):
    try:
        command = "objdump -f %s" % (fname)
        output = subprocess.check_output(command.split(" ")).decode("utf-8")
        image.dynamic = output.find("DYNAMIC") >= 0
        command = "nm -nS --defined-only %s" % (fname)
        output = subprocess.check_output(command.split(" ")).decode("utf-8")
        lines = output.splitlines()
    except:
        debug(0, "Exception reading ELF symbols: %s", (sys.exc_info()))
        return None

    if lines is None or len(lines) == 0:
        return None

    syms = []
    for line in lines:
        values = line.split(" ")
        nval = len(values)
        idx = 1
        if nval < 3 or nval > 4:
            continue
        saddr = int(values[0], 16)
        if nval == 4:
            ssize = int(values[1], 16)
            idx += 1
        else:
            ssize = 0
        stype = values[idx]
        sname = values[idx + 1]
        if image.dynamic:
            saddr += image.lower
        syms.append([saddr, ssize, sname, stype])
    return syms


"""
*************************************************************************
"""


class SymbolInfo:
    instance = None

    def __init__(self, fname):
        self.images = []
        self.symbols = SortedCollection(key=itemgetter(0))
        self.read_img(fname)

    @classmethod
    def open(cls, fname):
        if cls.instance:
            cls.close()
        if fname is not None:
            cls.instance = SymbolInfo(fname)

    @classmethod
    def close(cls):
        cls.instance = None

    @classmethod
    def isopen(cls):
        return cls.instance is not None

    def insert_update_symbol(self, symbol):
        (_, csym) = self.symbols.find_le(symbol.addr)
        if csym.addr == symbol.addr:
            if symbol.size > csym.size:
                csym.size = symbol.size
            csym.type = symbol.type
            csym.mergename(symbol.name)
            assert csym.img == symbol.img
            if symbol.islibstart:
                csym.islibstart = True
        else:
            self.symbols.insert((symbol.addr, symbol))

    def read_img(self, f):
        line = f.readline().strip()
        img = None
        while line != "":
            if line == "Image:":
                imgname = f.readline().strip()
                nextline = f.readline()
                if "dynamic" in nextline:
                    dynamic = True
                    nextline = f.readline()
                elif "static" in nextline:
                    dynamic = False
                    nextline = f.readline()
                else:
                    # No information about dynamic/static. This is the case for pinsyms.txt
                    # We assume first image is static and others are dynamic
                    dynamic = len(self.images) > 0
                [lower, upper] = [int(hx, 16) for hx in nextline.split(":")]
                img = Image(imgname, lower, upper, dynamic)
                self.images.append(img)
                self.symbols.insert(
                    (lower, Symbol(lower, upper - lower, "", img, "", True))
                )
            else:
                data = line.split(":")
                if len(data) == 2:
                    [addr, symbol] = data
                    size = "0"
                    stype = "t"
                else:
                    assert len(data) == 4
                    [addr, size, symbol, stype] = data
                addr = int(addr, 16)
                size = int(size, 16)
                self.insert_update_symbol(Symbol(addr, size, symbol, img, stype))
            line = f.readline().strip()

    @classmethod
    def reload_syms_from_elf(cls):
        assert cls.instance is not None
        assert len(cls.instance.images) > 0
        for image in cls.instance.images:
            fname = image.name
            if not os.path.isfile(fname):
                # We assume that memory regions without file are special mappings like vdso
                image.dynamic = True
                continue
            syms = readelfsyms(fname, image)
            if syms is None:
                continue
            for s in syms:
                (addr, size, sym, stype) = s
                cls.instance.insert_update_symbol(Symbol(addr, size, sym, image, stype))

    @classmethod
    def lookup(cls, address):
        assert cls.instance is not None
        try:
            (_, sym) = cls.instance.symbols.find_le(address)
            return sym
        except:
            return None

    @classmethod
    def doprint(cls):
        assert cls.instance is not None
        for s in cls.instance.symbols:
            (_, sym) = s
            debug(0, sym)

    @classmethod
    def write(cls, f):
        assert cls.instance is not None
        for s in cls.instance.symbols:
            (_, sym) = s
            sym.write(f)


"""
*************************************************************************
"""


class Symbol:
    def __init__(self, addr, size, name, img, stype, islibstart=False):
        self.name = []
        self.addr = addr
        self.size = size
        self.setname(name)
        assert img is None or isinstance(img, Image)
        self.img = img
        self.type = stype
        self.islibstart = islibstart

    def mergename(self, names):
        for n in names:
            self.setname(n)

    def setname(self, name):
        if name is None:
            return
        if len(name) == 0:
            return
        if name not in self.name:
            self.name.append(name)

    def getname(self):
        fullname = ""
        for name in self.name:
            fullname += name + ","
        return fullname[:-1]

    def strat(self, ip):
        string = "%08x" % (ip)
        if self.img is not None and self.img.dynamic:
            string += "(+%x)" % (ip - self.img.lower)
        if self.size > 0:
            string += "[%x]" % (self.size)
        string += ":"
        if self.size == 0:
            string += "?"
        elif ip >= self.addr + self.size:
            string += "after"
        string += " %s(%s)" % (self.getname(), self.type)
        if self.img is not None:
            string += "@" + self.img.name
        return string

    def __str__(self):
        return self.strat(self.addr)

    def write(self, f):
        if self.islibstart:
            assert self.img is not None
            f.write("Image:\n")
            f.write(self.img.name + "\n")
            if self.img.dynamic:
                f.write("dynamic\n")
            else:
                f.write("static\n")
            f.write("%x:%x\n" % (self.img.lower, self.img.upper))
        for n in self.name:
            f.write("%x:%x:%s:%s\n" % (self.addr, self.size, n, self.type))


"""
*************************************************************************
"""


class Image:
    def __init__(self, name, lower, upper, dynamic):
        self.name = name
        self.lower = lower
        self.upper = upper
        self.dynamic = dynamic

    def __eq__(self, other):
        return (self.name, self.lower, self.upper) == (
            other.name,
            other.lower,
            other.upper,
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return self.lower

    def __lt__(self, other):
        return self.lower < other.lower

    def __str__(self):
        return str.format(
            "%s %x-%x%s"
            % (self.name, self.lower, self.upper, " (dynamic)" if self.dynamic else "")
        )
