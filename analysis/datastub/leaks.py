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
# @package analysis.datastub.leaks
# @file leaks.py
# @brief Everything related to control-flow and data leaks.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3


import sys
import os
import struct
import copy
from enum import Enum
from queue import Queue
from datastub.SymbolInfo import Image, Symbol, SymbolInfo
from datastub.utils import debug, sorted_keys, debuglevel

"""
*************************************************************************
"""

CONTEXT = "context"
DATALEAKS = "dataleaks"
CFLEAKS = "cfleaks"
DATALEAK = "leak"
CFLEAK = "leak"

"""
*************************************************************************
"""

TYPE_A = 0
TYPE_B = 1
TYPE_C = 2
TYPE_D = 3


class MaskType(Enum):
    NONE = 0
    BRANCH = 4
    HEAP = 8
    LEAK = 16


# fmt: off
class Type(Enum):
    READ  = MaskType.NONE.value | TYPE_A # noqa
    WRITE = MaskType.NONE.value | TYPE_B # noqa

    BRANCH     = MaskType.BRANCH.value | TYPE_A # noqa
    FUNC_ENTRY = MaskType.BRANCH.value | TYPE_B # noqa
    FUNC_EXIT  = MaskType.BRANCH.value | TYPE_C # noqa
    FUNC_BBL   = MaskType.BRANCH.value | TYPE_D # noqa

    HREAD  = MaskType.HEAP.value | TYPE_A # noqa
    HWRITE = MaskType.HEAP.value | TYPE_B # noqa
    HALLOC = MaskType.HEAP.value | TYPE_C # noqa
    HFREE  = MaskType.HEAP.value | TYPE_D # noqa

    DLEAK  = MaskType.LEAK.value | TYPE_A # noqa
    CFLEAK = MaskType.LEAK.value | TYPE_B # noqa
# fmt: on

    @classmethod
    def isbranch(cls, e):
        return (e.type & cls.BRANCH.value) == cls.BRANCH.value


"""
*************************************************************************
"""

FUNC_ENTRY_BIN = struct.pack("B", Type.FUNC_ENTRY.value)
FUNC_EXIT_BIN = struct.pack("B", Type.FUNC_EXIT.value)

bs = (
    1 + 8 + 8
)  # has to match the binary format: type (1 byte), ip (8 bytes), data (8 bytes)
blocks = 256  # number of blocks processed concurrently
chunk_size = bs * blocks

"""
*************************************************************************
"""


class Entry:
    def __init__(self, arr):
        (self.type, self.ip, self.data) = arr

    def __eq__(self, other):
        if other is None:
            return False
        return (self.type, self.ip, self.data) == (other.type, other.ip, other.data)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return (self.type << 128) & (self.ip << 64) & (self.data)

    def __str__(self):
        return str.format(
            "%d(%s):%08x:%08x" % (self.type, str(Type(self.type)), self.ip, self.data)
        )


"""
*************************************************************************
"""


class MergePoint:
    def __init__(self, mtype, ip, depth):
        (self.type, self.ip, self.depth) = (mtype, ip, depth)

    def __eq__(self, other):
        if other is None:
            return False
        return (self.type, self.ip, self.depth) == (other.type, other.ip, other.depth)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return (self.type << 128) & (self.ip << 64) & (self.depth)

    def __str__(self):
        return str.format("%d:%08x:%08x" % (self.type, self.ip, self.depth))


"""
*************************************************************************
"""


class Context:
    def __init__(self, caller, callee):
        self.caller = caller
        self.callee = callee

    @classmethod
    def fromFuncCall(cls, entry):
        assert entry.type == Type.FUNC_ENTRY.value
        return cls(entry.ip, entry.data)

    def __eq__(self, other):
        return (self.caller, self.callee) == (other.caller, other.callee)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        return self.caller < other.caller

    """
    The context is uniquely identified by the function entry point (the callee)
    """

    def __hash__(self):
        myid = self.caller
        lower = self.callee & 0x00000000FFFFFFFF
        upper = self.callee >> 32
        myid ^= upper | (lower << 32)
        return myid


"""
*************************************************************************
"""

"""
Single call stack instance containing current snapshot only
"""


class CallStack:
    def __init__(self, cid=-1):
        self.stack = []
        self.id = cid

    def __copy__(self):
        new = CallStack()
        new.stack = self.stack[:]
        return new

    def __len__(self):
        return len(self.stack)

    def __getitem__(self, index):
        return self.stack[index]

    def __eq__(self, other):
        if other is None:
            return False
        return self.stack == other.stack

    def __ne__(self, other):
        return not self.__eq__(other)

    def depth(self):
        return len(self.stack)

    def docall_context(self, c):
        assert isinstance(c, Context)
        self.stack.append(c)

    def doreturn_context(self):
        return self.stack.pop()

    def docall(self, e):
        debug(3, "[%d]call from %08x to %08x", (self.id, e.ip, e.data))
        self.docall_context(Context.fromFuncCall(e))
        pass

    def doreturn(self):
        size = len(self.stack)
        assert size > 0
        ctxt = self.doreturn_context()
        size -= 1

        if size >= 1:
            debug(
                3,
                "[%d]Return from ctxt %08x to %08x",
                (self.id, ctxt.callee, self.stack[size - 1].callee),
            )
        else:
            debug(1, "[%d]Return from ctxt %08x to nowhere", (self.id, ctxt.callee))
            if size < 0:
                size = 0

    def update_context(self, e):
        if e.type == Type.FUNC_ENTRY.value:
            self.docall(e)
        if e.type == Type.FUNC_EXIT.value:
            self.doreturn()

    def doprint_reverse(self):
        debug(0, "callstack:")
        for i in reversed(range(0, len(self.stack))):
            debug(0, "callee %x", (self.stack[i].callee))
            debug(0, " caller %x", (self.stack[i].caller))

    def top(self):
        size = len(self.stack)
        if size == 0:
            return None
        else:
            return self.stack[size - 1]


"""
*************************************************************************
"""


class MergeMap:
    def __init__(self, mtype):
        self.mymap = {}
        self.mytype = mtype

    def __len__(self):
        return len(self.mymap)

    def __getitem__(self, key):
        return self.mymap[key]

    def __iter__(self):
        return self.mymap.__iter__()

    def clear(self):
        self.mymap = {}

    def merge(self, newmap):
        if isinstance(newmap, list):
            for item in newmap:
                self.merge(item)
            return
        if not isinstance(newmap, self.mytype):
            debug(0, newmap.__class__)
            debug(
                0,
                "Wrong class instance: %s vs %s",
                (str(newmap.__class__), str(self.mytype)),
            )
        assert isinstance(newmap, self.mytype)
        if newmap not in self.mymap:
            self.mymap[newmap] = newmap
        else:
            self.mymap[newmap].merge(newmap)

    def has_key(self, key):
        return key in self.mymap

    def keys(self):
        return self.mymap.keys()

    def values(self):
        return self.mymap.values()

    def doprint(self, printer):
        for e in sorted_keys(self.mymap):
            self.mymap[e].doprint(printer)


"""
*************************************************************************
"""


class Key:
    MAX_BYTES_TO_PRINT = 32

    def __init__(self, index, value):
        self.index = index
        self.value = value

    def __str__(self):
        label = "key"
        value = self.value.decode()
        if "\n" in value or len(value) > Key.MAX_BYTES_TO_PRINT:
            label = "key_index"
            value = self.index
        string = f"{label}='{value}'"
        return string

    def __len__(self):
        # length of the string representing the key
        return len(self.value.decode())

    def get_bytes(self):
        return self.value

"""
*************************************************************************
"""


class DataLeakEntry:
    def __init__(self, addr):
        self.addr = addr
        self.count = 1

    def __hash__(self):
        return self.addr

    def __eq__(self, other):
        return self.addr == other.addr

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        return self.addr < other.addr

    def quantize(self, mask):
        self.addr &= mask

    def merge(self, newentry):
        self.count += newentry.count

    def __str__(self):
        return str.format("%08x: %d" % (self.addr, self.count))

    def doprint(self, printer):
        printer.doprint_generic(self)


"""
*************************************************************************
"""


class CFLeakEntry:
    def __init__(self, bp, length, mp):
        self.bp = bp
        self.length = length
        self.mp = mp
        self.count = 1

    def __hash__(self):
        return self.bp.ip + (self.mp << 64) + (self.length << 64)

    def __eq__(self, other):
        return (self.bp.ip, self.length, self.mp) == (
            other.bp.ip,
            other.length,
            other.mp,
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        if self.bp.ip != other.bp.ip:
            return self.bp.ip < other.bp.ip
        if self.length != other.length:
            return self.length < other.length
        if self.mp != other.mp:
            return self.mp < other.mp

    def quantize(self, mask):
        self.bp.ip &= mask
        self.mp &= mask

    def collapse(self):
        self.length = 0
        self.mp = 0

    def merge(self, newentry):
        self.count += newentry.count

    def __str__(self):
        string = str.format("%08x" % self.bp.ip)
        if self.mp > 0:
            string += str.format(" - %08x" % self.mp)
        if self.length > 0:
            string += str.format(" (%d)" % self.length)
        return string + str.format(": %d" % self.count)

    def doprint(self, printer):
        printer.doprint_generic(self)


"""
*************************************************************************
"""


class LeakStatus:
    def __init__(self):
        self.properties = set()
        self.nsperformed = False  # true if generic leakage tests were performed
        self.spperformed = (
            set()
        )  # contains targets, if specific leakage tests were performed
        self.nsleak = list()  # results of generic leakage-tests, if any
        self.spleak = set()  # results of specific leakage-tests, if any

    def merge(self, other):
        self.nsperformed |= other.nsperformed
        self.spperformed = self.spperformed.union(other.spperformed)
        self.nsleak += other.nsleak
        self.spleak = self.spleak.union(other.spleak)

    def is_generic_tested(self):
        return self.nsperformed

    def is_specific_tested(self):
        if len(self.spperformed) > 0:
            return True
        else:
            return False

    def has_generic_results(self):
        if len(self.nsleak) > 0:
            return True
        else:
            return False

    def has_specific_results(self):
        if len(self.spleak) > 0:
            return True
        else:
            return False

    def is_generic_leak(self):
        for ns in self.nsleak:
            if ns.isleak:
                return True
        return False

    def is_specific_leak(self):
        for sp in self.spleak:
            if sp.isleak:
                return True
        return False

    def max_leak(self):
        max_leak = None
        if self.is_generic_leak():
            max_leak_ns = max(self.nsleak, key=lambda l: l.normalized())
            # Remove M_pos, as it does not work properly
            # normalized = max(normalized, max(self.nsleak, key=lambda l: 0 if l.nstype == NSPType.Type3 else l.normalized()).normalized())
            max_leak = max_leak_ns
        if self.is_specific_leak():
            max_leak_sp = max(self.spleak, key=lambda l: l.normalized())
            # Remove M_pos, as it does not work properly
            # normalized = max(normalized, max(self.spleak, key=lambda l: 0 if l.sptype == NSPType.Type3 else l.normalized()).normalized())
            max_leak = max_leak_sp if max_leak_sp.normalized() > max_leak.normalized() else max_leak
        return max_leak

    def max_leak_normalized(self):
        max_leak = self.max_leak()
        if max_leak is None:
            return 0
        return max_leak.normalized()

    def __str__(self):
        # check for generic leaks
        havensleak = self.is_generic_leak()
        havensresults = self.has_generic_results()

        # check for specific leaks
        havespleak = self.is_specific_leak()
        havespresults = self.has_specific_results()

        # approved difference
        if not (havensleak or havensresults or havespleak or havespresults):
            rstr = "status='difference'"

        # approved/refuted leakage
        elif havensresults or havespresults:
            lsrc = []
            rstr = ""
            if havensleak or havespleak:
                rstr = "status='leak'"
                if havensleak:
                    lsrc.append("generic")
                if havespleak:
                    lsrc.append("specific")
            else:
                rstr = "status='dropped'"
                if havensresults:
                    lsrc.append("generic")
                if havespresults:
                    lsrc.append("specific")
            rstr += " type='" + ",".join(lsrc) + "'"

        # unknown
        else:
            rstr = "status='unknown'"

        # return
        return rstr


"""
*************************************************************************
"""


# fmt: off
class NSPType(Enum):
    Type1a = 0  # number of addresses
    Type1b = 1  # number of unique addresses
    Type2  = 2  # number of accesses per address    # noqa
    Type2a = 3  # number of accesses per address    # noqa
    Type3  = 4  # position of address during access # noqa
    Noleak = 5  # special: no leakage detected
# fmt: on

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented

    def __str__(self):
        if self == NSPType.Noleak:
            string = "none"
        elif self == NSPType.Type1a:
            string = "pos(a)"
        elif self == NSPType.Type1b:
            string = "pos(b)"
        elif self == NSPType.Type2:
            string = "addr"
        elif self == NSPType.Type2a:
            string = "addr_sort"
        elif self == NSPType.Type3:
            string = "pos"
        else:
            assert False
        return string


"""
*************************************************************************
"""


class NSLeak(object):
    def __init__(
        self, nstype, key, addr=0, statistic=0.0, limit=0.0, conf=0.0, isleak=False
    ):
        self.nstype = nstype
        self.address = addr
        self.teststat = statistic
        self.limit = limit
        self.confidence = conf
        self.isleak = isleak

        self.key = key

    def normalized(self):
        if not self.isleak or self.nstype == NSPType.Noleak:
            return 0.0
        assert self.teststat is not None
        assert self.limit is not None
        if self.teststat < self.limit:
            return 0.0
        return (self.teststat - self.limit) / (1.0 - self.limit)

    def threshold(self):
        return self.limit

    def __lt__(self, other):
        if self.isleak is False and other.isleak is True:
            return True
        elif self.isleak is True and other.isleak is False:
            return False
        elif self.isleak is False and other.isleak is False:
            return self.nstype < other.nstype
        elif (
            (self.nstype in [NSPType.Type1a, NSPType.Type1b])
            and (other.nstype in [NSPType.Type1a, NSPType.Type1b])
        ) or ((self.nstype in [NSPType.Type2]) and (other.nstype in [NSPType.Type2])):
            return self.key.index < other.key.index

    def __eq__(self, other):
        if self.isleak is False and other.isleak is False:
            return self.nstype == other.nstype
        if (
            (self.nstype == other.nstype)
            and (self.address == other.address)
            and (self.teststat == other.teststat)
            and (self.limit == other.limit)
            and (self.confidence == other.confidence)
            and (self.isleak == other.isleak)
            and (self.key.index == self.key.index)
        ):
            return True
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        if self.isleak is False:
            return hash(self.nstype)
        return hash(tuple(sorted(self.__dict__.items())))

    def __str__(self):
        if self.nstype == NSPType.Noleak:
            assert False

        result = "leak" if self.isleak else "none"
        string = f"result='{result}' source='H_{str(self.nstype)}'"

        if not self.isleak:
            return string

        string += (
            f" kuiper='{self.teststat:.4f}' "
            f"significance='{self.limit:.4f}' confidence='{self.confidence:.4f}' "
            f"{str(self.key)}"
        )
        return string


"""
*************************************************************************
"""


class SPLeak(object):
    def __init__(
        self,
        sptype,
        prop=0,
        addr=0,
        pos=0,
        rdc=0.0,
        rdc_limit=0.0,
        ind=True,
        target="",
        conf=0.0,
    ):
        self.sptype = sptype
        self.property = prop
        self.address = addr
        self.position = pos
        self.rdc = rdc
        self.rdc_limit = rdc_limit
        self.confidence = conf
        self.isleak = not ind
        self.target = target

    def __lt__(self, other):
        if self.sptype == other.sptype:
            if self.property == other.property:
                srdc = 0.0 if self.rdc is None else self.rdc
                ordc = 0.0 if other.rdc is None else other.rdc
                return srdc < ordc
            else:
                return self.property < other.property
        else:
            return self.sptype < other.sptype

    def __eq__(self, other):
        if (
            (self.sptype == other.sptype)
            and (self.property == other.property)
            and (self.address == other.address)
            and (self.position == other.position)
            and (self.rdc == other.rdc)
            and (self.rdc_limit == other.rdc_limit)
            and (self.confidence == other.confidence)
            and (self.isleak == other.isleak)
            and (self.target == other.target)
        ):
            return True
        else:
            return False

    def normalized(self):
        if not self.isleak:
            return 0.0
        assert self.rdc is not None
        assert self.rdc_limit is not None
        if self.rdc < self.rdc_limit:
            return 0.0
        return (self.rdc - self.rdc_limit) / (1.0 - self.rdc_limit)

    def threshold(self):
        return self.rdc_limit

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(tuple(sorted(self.__dict__.items())))

    def __str__(self):
        if self.sptype == NSPType.Noleak:
            assert False

        result = "leak" if self.isleak else "none"
        string = f"result='{result}' source='M_{str(self.sptype)}' leakagemodel='{self.target}'"

        if not self.isleak:
            return string

        string += (
            f" property='{self.property}'"
            f" address='{self.address:x}'"
            f" rdc='{self.rdc:.4f}' significance='{self.rdc_limit:.4f}'"
            f" confidence='{self.confidence:.4f}'"
        )
        return string


"""
*************************************************************************
"""


class EvidenceSource(Enum):
    Generic = 0  # evidence of generic leakage test
    Specific = 1  # evidence of specific leakage test


class EvidenceEntry:
    # EvidenceEntry class attributes
    # entries:  For DLeak: Access address; For CFLeak:
    # key:      Key for which this EE was recorded.
    # source:
    # count:    If EEs are merged, duplicates are collapsed and count is increased.
    def __init__(self, entries, key, source, origin):
        self.entries = entries
        self.source = source
        self.origin = origin
        self.count = 1

        self.key = key

    def element(self):
        entry = -1
        if len(self.entries) != 0:
            entry = self.entries[0]
        return (self.key.index, entry)

    def __hash__(self):
        return hash(self.element())

    def __eq__(self, other):
        return self.element() == other.element()

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        return self.element() < other.element()

    def merge(self, newentry):
        self.count += newentry.count

    def __str_printer__(self):
        entry = "       empty"
        if len(self.entries) != 0:
            entry = format(self.entries[0], 'x')
        string = f"{entry}: {self.count}"
        return string

    def __str__(self):
        # TODO Added assert to find out, if used anywhere in the code base
        assert False
        string = "Key: " + str(self.key) + "\n"
        string += "Source: " + str(self.source) + "\n"
        for e in self.entries:
            string += str.format("%x " % e)
        return string

    def doprint(self, printer):
        printer.doprint_generic(self)


"""
*************************************************************************
"""


class Leak:
    def __init__(self, ip):
        self.ip = ip
        self.status = LeakStatus()
        # self.entries is instantiated in derived classes and contains
        # phase 1 results

        # self.evidence contains phase2/3 evidences
        # Evidence is not merged but chained in a list of EvidenceEntries
        self.evidence = []
        self.meta = None

    def clone_collapsed(self, mask, do_collapse=False):
        clone = self.__class__(self.ip & mask)
        clone.status = copy.deepcopy(self.status)
        for e in self.entries:
            c = copy.copy(e)
            c.quantize(mask)
            if do_collapse:
                c.collapse()
            clone.append(c)
        return clone

    def append(self, entry):
        if len(self.entries) == 0:
            debug(1, f"Empty Leak @{hex(self.ip)}")
        if isinstance(entry, DataLeakEntry):
            location = f"addr={hex(entry.addr)}"
        else:
            location = f"  bp={hex(entry.bp.ip)}"
        debug(1, f"New entry for Leak @{hex(self.ip)}: {location} count={hex(entry.count)}")
        self.entries.merge(entry)

    def __hash__(self):
        return self.ip

    def __eq__(self, other):
        return self.ip == other.ip

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        return self.ip < other.ip

    def merge(self, newleak):
        assert self.ip == newleak.ip
        debug(1, "Merge Leaks into one.")
        for e in newleak.entries:
            self.entries.merge(newleak.entries[e])
        self.status.merge(newleak.status)
        self.evidence += newleak.evidence

    def add_evidence(self, ev):
        assert isinstance(ev, EvidenceEntry)
        debug(1, f"New evidence for Leak @{hex(self.ip)}")
        self.evidence.append(ev)

    def __str__(self):
        string = ""
        for e in sorted_keys(self.entries):
            string += str(e) + "\n"
        return string


"""
*************************************************************************
"""


class FunctionLeak:
    def __init__(self, leak):
        self.dataleaks = MergeMap(DataLeak)
        self.cfleaks = MergeMap(CFLeak)
        self.sym = SymbolInfo.lookup(leak.ip)
        if self.sym is None:
            img = Image("Unknown", 0, 0, False)
            self.sym = Symbol(0, 0, "UnknownSym", img, "")
        self.fentry = self.sym.addr
        self.append(leak)

    # Append a Leak
    def append(self, leak):
        if isinstance(leak, DataLeak):
            self.dataleaks.merge(leak)
        elif isinstance(leak, CFLeak):
            self.cfleaks.merge(leak)
        else:
            debug(0, "Unknown type: " + str(leak.__class__))
            assert False

    # Merge a FunctionLeak
    def merge(self, fleak):
        assert self.fentry == fleak.fentry
        for e in fleak.dataleaks:
            self.dataleaks.merge(fleak.dataleaks[e])
        for e in fleak.cfleaks:
            self.cfleaks.merge(fleak.cfleaks[e])

    def __hash__(self):
        return self.fentry

    def __eq__(self, other):
        return self.fentry == other.fentry

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        return self.fentry < other.fentry

    def doprint(self, printer, printleaks=False):
        printer.doprint_generic(self, printleaks)

    def __str__(self):
        return str(self.sym)


"""
*************************************************************************
"""


class Library:
    def __init__(self, fleak):
        self.entries = MergeMap(FunctionLeak)
        self.libentry = fleak.sym.img
        self.append(fleak)

    # Append a FunctionLeak
    def append(self, fleak):
        assert isinstance(fleak, FunctionLeak)
        self.entries.merge(fleak)

    # Merge a Library
    def merge(self, libleak):
        assert self.libentry == libleak.libentry
        for e in libleak.entries:
            self.append(e)

    def __hash__(self):
        return self.libentry.__hash__()

    def __eq__(self, other):
        return self.libentry.__eq__(other.libentry)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        return self.libentry.__lt__(other.libentry)

    def doprint(self, printer, printleaks=False):
        printer.doprint_generic(self, printleaks)

    def __str__(self):
        return str(self.libentry)


"""
*************************************************************************
"""


class LibHierarchy:
    def __init__(self):
        self.entries = MergeMap(Library)

    def merge(self, leak):
        self.report_leak(leak)

    def report_leak(self, leak):
        fleak = FunctionLeak(leak)
        lib = Library(fleak)
        self.entries.merge(lib)

    def doprint(self, printer, printleaks=False):
        printer.doprint_generic(self, printleaks)


"""
*************************************************************************
"""


class DataLeak(Leak):
    name = "DataLeak"

    def __init__(self, ip, entry=None):
        Leak.__init__(self, ip)
        self.entries = MergeMap(DataLeakEntry)
        if entry is not None:
            self.append(entry)

    def doprint(self, printer, printleaks=True):
        printer.doprint_generic(self, printleaks)


class CFLeak(Leak):
    name = "CFLeak"

    def __init__(self, ip, entry=None):
        Leak.__init__(self, ip)
        self.entries = MergeMap(CFLeakEntry)
        if entry is not None:
            self.append(entry)

    def get_mergepoint(self):
        mp = set([])
        for e in self.entries:
            mp.add(e.mp)
        return mp

    def doprint(self, printer, printleaks=True):
        printer.doprint_generic(self, printleaks)


"""
*************************************************************************
"""

"""
History of call stack containing leaks
"""


class CallHistory:
    def __init__(self, ctxt=None, parent=None):
        self.children = {}  # maps Context to CallHistory
        self.dataleaks = MergeMap(DataLeak)
        self.cfleaks = MergeMap(CFLeak)
        assert ctxt is None or isinstance(ctxt, Context)
        self.ctxt = ctxt
        assert parent is None or isinstance(parent, CallHistory)
        self.parent = parent

    def __lt__(self, other):
        if self.ctxt is None:
            return True
        if other.ctxt is None:
            return False
        return self.ctxt.callee < other.ctxt.callee

    def report_leak(self, callstack, leak, nocreate=False):
        if callstack is None or len(callstack) == 0:
            self.consume_leak(leak)
        else:
            # advance to correct calling context recursively
            # by consuming first callstack entry
            ctxt = callstack[0]
            assert isinstance(ctxt, Context)
            if debuglevel(5):
                debug(5, "Processing callstack")
                for ci in callstack:
                    debug(5, "%08x--%08x", (ci.caller, ci.callee))
                debug(5, "Handling ctxt %08x--%08x", (ctxt.caller, ctxt.callee))

            if nocreate:
                assert ctxt in self.children
            elif ctxt not in self.children:
                self.children[ctxt] = CallHistory(ctxt, self)
            self.children[ctxt].report_leak(callstack[1:], leak, nocreate)

    def consume_leak(self, leak):
        debug(2, "consuming leak@ctxt %08x", (self.ctxt.callee))
        if isinstance(leak, DataLeak):
            self.dataleaks.merge(leak)
        elif isinstance(leak, CFLeak):
            self.cfleaks.merge(leak)
        else:
            debug(0, "Unknown type: " + str(leak.__class__))
            assert False

    def doprint(self, printer, printleaks=False):
        printer.doprint_generic(self, printleaks)

    def flatten(self, flat=None):
        main = False
        if flat is None:
            flat = LibHierarchy()
            main = True

        for leak in sorted_keys(self.dataleaks):
            c = copy.deepcopy(leak)
            flat.merge(c)
        for leak in sorted_keys(self.cfleaks):
            c = copy.deepcopy(leak)
            flat.merge(c)

        for k in sorted_keys(self.children):
            self.children[k].flatten(flat)

        if main:
            return flat

    def __str__(self):
        return str(self.ctxt)

    def has_leak(self, callstack, leak):
        if callstack is None or len(callstack) == 0:
            if isinstance(leak, DataLeak):
                return leak in self.dataleaks
            elif isinstance(leak, CFLeak):
                return leak in self.cfleaks
            else:
                assert False
        else:
            # advance to correct calling context recursively
            # by consuming first callstack entry
            ctxt = callstack[0]
            assert isinstance(ctxt, Context)
            if debuglevel(3):
                debug(3, "Processing callstack:")
                for ci in callstack:
                    debug(3, "%08x--%08x", (ci.caller, ci.callee))

            if ctxt in self.children:
                return self.children[ctxt].has_leak(callstack[1:], leak)


"""
*************************************************************************
"""


class LeakCounter:
    def __init__(self):
        self.cflow_diff_total = 0
        self.cflow_diff_total_dropped = 0
        self.cflow_diff_total_untested = 0
        self.cflow_leaks_generic = 0
        self.cflow_leaks_specific = {}
        self.cflow_leaks_total = 0
        self.data_diff_total = 0
        self.data_diff_total_dropped = 0
        self.data_diff_total_untested = 0
        self.data_leaks_generic = 0
        self.data_leaks_specific = {}
        self.data_leaks_total = 0

    def increment(self, other):
        self.cflow_diff_total += other.cflow_diff_total
        self.cflow_diff_total_dropped += other.cflow_diff_total_dropped
        self.cflow_diff_total_untested += other.cflow_diff_total_untested
        self.cflow_leaks_generic += other.cflow_leaks_generic
        for sp in other.cflow_leaks_specific.keys():
            if sp in self.cflow_leaks_specific:
                self.cflow_leaks_specific[sp] += other.cflow_leaks_specific[sp]
            else:
                self.cflow_leaks_specific[sp] = other.cflow_leaks_specific[sp]
        self.cflow_leaks_total += other.cflow_leaks_total
        self.data_diff_total += other.data_diff_total
        self.data_diff_total_dropped += other.data_diff_total_dropped
        self.data_diff_total_untested += other.data_diff_total_untested
        self.data_leaks_generic += other.data_leaks_generic
        for sp in other.data_leaks_specific.keys():
            if sp in self.data_leaks_specific:
                self.data_leaks_specific[sp] += other.data_leaks_specific[sp]
            else:
                self.data_leaks_specific[sp] = other.data_leaks_specific[sp]
        self.data_leaks_total += other.data_leaks_total

    @classmethod
    def count(cls, obj):
        counter = LeakCounter()
        if isinstance(obj, CallHistory) or isinstance(obj, FunctionLeak):
            # data leaks
            for leak in obj.dataleaks:
                counted_generic = False
                counter.data_diff_total += 1
                if leak.status.is_generic_tested():
                    if leak.status.is_generic_leak():
                        counter.data_leaks_generic += 1
                        counter.data_leaks_total += 1
                        counted_generic = True
                    else:
                        if leak.status.has_generic_results():
                            if not leak.status.is_specific_leak():
                                counter.data_diff_total_dropped += 1
                        else:
                            counter.data_diff_total_untested += 1
                else:
                    if (
                        leak.status.is_specific_tested()
                        and not leak.status.is_specific_leak()
                    ):
                        counter.data_diff_total_dropped += 1

                counted_targets = []
                counted_leak = False
                for sp in leak.status.spleak:
                    if not sp.isleak:
                        continue
                    if sp.target in counted_targets:
                        continue
                    if sp.target not in counter.data_leaks_specific:
                        counter.data_leaks_specific[sp.target] = 1
                    else:
                        counter.data_leaks_specific[sp.target] += 1
                    counted_targets.append(sp.target)
                    if not counted_leak:
                        if not counted_generic:
                            counter.data_leaks_total += 1
                        counted_leak = True
            # cflow leaks
            for leak in obj.cfleaks:
                counted_generic = False
                counter.cflow_diff_total += 1
                if leak.status.is_generic_tested():
                    if leak.status.is_generic_leak():
                        counter.cflow_leaks_generic += 1
                        counter.cflow_leaks_total += 1
                        counted_generic = True
                    else:
                        if leak.status.has_generic_results():
                            if not leak.status.is_specific_leak():
                                counter.cflow_diff_total_dropped += 1
                        else:
                            counter.cflow_diff_total_untested += 1
                else:
                    if (
                        leak.status.is_specific_tested()
                        and not leak.status.is_specific_leak()
                    ):
                        counter.cflow_diff_total_dropped += 1

                counted_targets = []
                counted_leak = False
                for sp in leak.status.spleak:
                    if not sp.isleak:
                        continue
                    if sp.target in counted_targets:
                        continue
                    if sp.target not in counter.cflow_leaks_specific:
                        counter.cflow_leaks_specific[sp.target] = 1
                    else:
                        counter.cflow_leaks_specific[sp.target] += 1
                    counted_targets.append(sp.target)
                    if not counted_leak:
                        if not counted_generic:
                            counter.cflow_leaks_total += 1
                        counted_leak = True
        if isinstance(obj, CallHistory):
            for c in obj.children:
                counter.increment(LeakCounter.count(obj.children[c]))
        elif isinstance(obj, LibHierarchy) or isinstance(obj, Library):
            for c in obj.entries:
                counter.increment(LeakCounter.count(obj.entries[c]))
        elif isinstance(obj, FunctionLeak):
            pass
        else:
            debug(0, str(obj))
            assert False
        return counter

    def doprint(self, printer):
        printer.doprint_generic(self)


"""
*************************************************************************
"""


class QueueDebugger:
    def __init__(self, myid):
        self.id = myid

    def debug(self, level, fstr, values=()):
        if debuglevel(level):
            instr = str(fstr % values)
            debug(level, "[%d]%s", (self.id, instr))


class Lookahead(QueueDebugger):
    def __init__(self, tracequeue):
        QueueDebugger.__init__(self, tracequeue.id)
        self.tq = tracequeue
        self.callstack = copy.copy(tracequeue.callstack)
        self.callstack.id = tracequeue.id
        self.myset = set()
        self.shift = 0
        self.branch = None

    def consume_entry(self, e):
        self.debug(3, "Adding bp candidate %08x", (e.ip))
        # Add to current set, ignore data such that set intersection
        # only considers type and ip
        self.myset.add(MergePoint(e.type, e.ip, self.callstack.depth()))

    def advance_next_bp_candidate(self, bdepth=-1):
        while True:
            assert bdepth < 0 or self.callstack.depth() + 1 >= bdepth

            e = self.tq.lookahead(self.shift)
            self.shift += 1

            if e is None:
                return False

            if bdepth >= 0 and self.callstack.depth() + 1 == bdepth:
                # Last entry was a FUNC_RET
                # reached end of function context
                self.debug(3, "Reached end of context, waiting at %08x", (e.ip))
                self.consume_entry(e)
                return False

            # We only merge at branch points (also call/ret) and branch targets, skip other entries
            if not Type.isbranch(e):
                continue

            assert self.callstack.depth() >= bdepth
            if bdepth < 0 or self.callstack.depth() == bdepth:
                # We are in the right context
                self.consume_entry(e)
                # Consume Call/Ret
                self.callstack.update_context(e)
                return True
            else:
                self.debug(3, "Ignoring %08x", (e.ip))
                self.callstack.update_context(e)

    def depth(self):
        return self.callstack.depth()

    @classmethod
    def intersect(cls, lhA, lhB):
        intersect = set.intersection(lhA.myset, lhB.myset)
        if len(intersect) == 0:
            return None
        return intersect.pop()


"""
*************************************************************************
"""


class TraceQueue(QueueDebugger):
    def __init__(self, tfile, tid, showprogress=False):
        QueueDebugger.__init__(self, tid)
        self.file = tfile
        self.q = Queue()
        self.chunk = None
        self.callstack = CallStack(tid)
        self.fsize = os.path.getsize(self.file.name)
        self.debug(2, "file size is %d", (self.fsize))
        self.stepsize = self.fsize / 1000
        self.fpos = 0
        self.showprogress = showprogress
        # create a virtual call to the entry
        einit = self.lookahead(0)
        assert einit.type == Type.FUNC_ENTRY.value

    def refill(self, elem=blocks):
        if not self.load_chunk(elem):
            return False
        self.refill_chunk()
        return True

    # Call load_chunk before this method
    def refill_chunk(self):
        assert self.chunk is not None
        assert len(self.chunk) % bs == 0
        cblocks = int(len(self.chunk) / bs)
        unpacked = struct.unpack("<" + "BQQ" * cblocks, self.chunk)
        for i in range(0, cblocks):
            e = Entry(unpacked[i * 3 : (i + 1) * 3])
            self.q.put_nowait(e)
            if debuglevel(4):
                self.debug(4, "parsing %s", (e))
            if Type.isbranch(e):
                if e.data != 0:
                    # Report conditional branches/call/ret twice:
                    # once as original branch/call/ret at the branch point
                    # and once as BBL at the branch target
                    e2 = Entry([Type.FUNC_BBL.value, e.data, 0])
                    self.q.put_nowait(e2)
                    if debuglevel(4):
                        self.debug(4, "Is branch, creating %s", (e2))
        self.chunk = None

    def load_chunk(self, elem=blocks):
        assert self.chunk is None
        self.chunk = self.file.read(elem * bs)
        if self.showprogress:
            self.fpos += elem * bs
            if self.fpos > self.stepsize:
                sys.stderr.write(
                    "%c[2K\r[%02.1f]" % (27, self.file.tell() / float(self.fsize) * 100)
                )
                self.fpos = 0
        if len(self.chunk) == 0:
            self.chunk = None
            return False
        return True

    def peak_last_branch_from_chunk(self):
        assert self.chunk is not None
        assert len(self.chunk) % bs == 0
        idx = len(self.chunk)

        while idx >= 17:
            idx -= 17
            unpacked = struct.unpack("<" + "BQQ", self.chunk[idx : idx + 17])
            e = Entry(unpacked)
            if Type.isbranch(e):
                return e
        return None

    def get(self):
        while True:
            if self.q.empty():
                if not self.refill():
                    return None
            e = self.q.get_nowait()
            self.callstack.update_context(e)
            if Type(e.type) in (Type.HALLOC, Type.HFREE):
                continue
            if debuglevel(4):
                self.debug(4, str(e))
            return e

    def get_nofill(self):
        return self.q.get_nowait()

    def lookahead(self, i):
        while i >= self.q.qsize():
            if not self.refill():
                return None
        e = self.q.queue[i]
        if debuglevel(4):
            self.debug(4, str(e))
        return e

    def size(self):
        return self.q.qsize()

    # Advance queue to mergepoint such that next self.get yields the mergepoint
    def advance(self, mp):
        self.debug(3, "advancing to %08x", (mp.ip))
        count = 0
        while True:
            # Make sure queue has enough items
            if self.q.empty():
                if not self.refill():
                    assert False
                    return -1
            e = self.q.queue[0]

            if (
                self.callstack.depth() == mp.depth
                and e.ip == mp.ip
                and e.type == mp.type
            ):
                self.debug(3, "advanced in %d steps", (count))
                return count
            # skip item and advance
            e = self.q.get_nowait()
            self.callstack.update_context(e)
            count += 1
