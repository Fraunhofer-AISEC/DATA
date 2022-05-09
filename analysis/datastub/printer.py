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
# @package analysis.datastub.printer
# @file printer.py
# @brief Prints and formats internal data types and structures.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3


import struct
from collections import Counter
from copy import deepcopy

from datastub.utils import debug
from datastub.SymbolInfo import SymbolInfo
from datastub.leaks import (
    LeakCounter,
    CallHistory,
    sorted_keys,
    CFLeak,
    DataLeak,
    CFLeakEntry,
    DataLeakEntry,
    EvidenceEntry,
    LeakStatus,
    LibHierarchy,
    Library,
    MergeMap,
    FunctionLeak,
    Type,
)

"""
*************************************************************************
"""

CONTEXT = "context"
DATALEAKS = "dataleaks"
CFLEAKS = "cfleaks"
DATALEAK = "leak"
CFLEAK = "leak"
LEAK = "leak"

"""
*************************************************************************
"""


class XmlLeakPrinter:
    def __init__(self, outfile):
        self.depth = 0
        self.outstream = outfile

    def doprint(self, text, ip, leak):
        self.outstream.write(" " * self.depth)
        if len(text) > 0:
            self.outstream.write(text + " ")
        if SymbolInfo.isopen():
            sym = SymbolInfo.lookup(ip)
            if sym is not None:
                self.outstream.write(sym.strat(ip))
            else:
                self.outstream.write(hex(ip))
        else:
            self.outstream.write(hex(ip))
        self.outstream.write("\n")
        if leak is not None:
            leak.doprint(self)

    def doprint_line(self, text):
        self.outstream.write(" " * self.depth + text + "\n")

    def doprint_summary(self, title, val):
        self.doprint_line("%s: %d" % (title, val))

    def printHeader(self):
        self.outstream.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        self.startNode("Report")

    def printFooter(self):
        self.endNode("Report")

    def startNode(self, node):
        self.outstream.write(" " * self.depth)
        self.outstream.write("<%s>\n" % (node))
        self.depth += 1

    def endNode(self, node):
        assert self.depth > 0
        self.depth -= 1
        self.outstream.write(" " * self.depth)
        self.outstream.write("</%s>\n" % (node))

    def startEndNode(self, node, text):
        self.outstream.write(" " * self.depth)
        self.outstream.write("<%s %s/>\n" % (node, text))

    def doprint_hierarchy(self, leaks):
        self.startNode("CallHierarchy")
        leaks.doprint(self, True)
        LeakCounter.count(leaks).doprint(self)
        self.endNode("CallHierarchy")

    def doprint_flat(self, flat):
        flat.doprint(self, True)

    def doprint_generic(self, obj, param1=False):
        if isinstance(obj, LeakCounter):
            self.startNode("LeakStats")
            self.startNode("Differences")
            self.doprint_summary("cflow", obj.cflow_diff_total)
            self.doprint_summary("cflow-drop", obj.cflow_diff_total_dropped)
            self.doprint_summary("cflow-notest", obj.cflow_diff_total_untested)
            self.doprint_summary("data", obj.data_diff_total)
            self.doprint_summary("data-drop", obj.data_diff_total_dropped)
            self.doprint_summary("data-notest", obj.data_diff_total_untested)
            self.endNode("Differences")
            self.startNode("Leaks")
            self.startNode("Generic")
            self.doprint_summary("cflow", obj.cflow_leaks_generic)
            self.doprint_summary("data", obj.data_leaks_generic)
            self.endNode("Generic")
            combinedset = set(obj.cflow_leaks_specific.keys()).union(
                set(obj.data_leaks_specific.keys())
            )
            if len(combinedset) == 0:
                self.startNode("Specific")
                self.doprint_summary("cflow", 0)
                self.doprint_summary("data", 0)
                self.endNode("Specific")
            else:
                for sp in combinedset:
                    self.startNode("Specific")
                    self.doprint_line("leakage-model: %s" % str(sp))
                    if sp in obj.cflow_leaks_specific:
                        self.doprint_summary("cflow", obj.cflow_leaks_specific[sp])
                    else:
                        self.doprint_summary("cflow", 0)
                    if sp in obj.data_leaks_specific:
                        self.doprint_summary("data", obj.data_leaks_specific[sp])
                    else:
                        self.doprint_summary("data", 0)
                    self.endNode("Specific")
            self.endNode("Leaks")
            self.endNode("LeakStats")
        elif isinstance(obj, CallHistory):
            if obj.ctxt is not None:
                self.startNode(CONTEXT)
                self.doprint("CALL", obj.ctxt.caller, None)
                self.doprint("TO", obj.ctxt.callee, None)
            if param1:
                if len(obj.dataleaks) > 0:
                    self.startNode(DATALEAKS)
                    for leak in sorted_keys(obj.dataleaks):
                        leak.doprint(self)
                    self.endNode(DATALEAKS)
                if len(obj.cfleaks) > 0:
                    self.startNode(CFLEAKS)
                    for leak in sorted_keys(obj.cfleaks):
                        leak.doprint(self)
                    self.endNode(CFLEAKS)
            for k in sorted_keys(obj.children):
                obj.children[k].doprint(self, param1)
            if obj.ctxt is not None:
                self.endNode(CONTEXT)
        elif isinstance(obj, CFLeak) or isinstance(obj, DataLeak):
            self.startNode(LEAK)
            self.doprint("", obj.ip, None)

            if len(obj.entries) > 0:
                self.startNode("entries")
                obj.entries.doprint(self)
                self.endNode("entries")

            if len(obj.evidence) > 0:
                self.startNode("evidences")

                key_indxs = [e.key_index for e in obj.evidence]
                evidences = [[] for _ in range(max(key_indxs) + 1)]
                for (idx, key_indx) in enumerate(key_indxs):
                    evidences[key_indx].append(obj.evidence[idx])

                for (idx, evidence) in enumerate(evidences):
                    if len(evidence) == 0:
                        continue
                    evidence = deepcopy(evidence)

                    obj_print = MergeMap(EvidenceEntry)
                    obj_print.merge(evidence)

                    node_plain = "phase2" if evidence[0].source == 0 else "phase3"
                    if idx == 0:
                        node = f"{node_plain} origin='random'"
                    else:
                        key = evidence[0].key.decode()
                        node = f"{node_plain} origin='fixed' key='{key}'"
                    self.startNode(node)
                    obj_print.doprint(self)
                    self.endNode(node_plain)

                self.endNode("evidences")

            self.doprint_generic(obj.status)

            self.endNode(LEAK)
        elif isinstance(obj, CFLeakEntry):
            self.doprint_line(obj.__str__())
        elif isinstance(obj, DataLeakEntry):
            self.doprint_line(obj.__str__())
        elif isinstance(obj, EvidenceEntry):
            self.doprint_line(obj.__str_printer__())
        elif isinstance(obj, LeakStatus):
            if len(obj.nsleak) == 0 and len(obj.spleak) and 0:
                self.startEndNode("result", str(obj))
                return

            self.startNode(f"result {str(obj)}")

            # Print NSLeak
            status_leaks = Counter(sorted(obj.nsleak))
            for sl_key in status_leaks.keys():
                self.startEndNode(
                    "generic", f"{str(sl_key)} count='{status_leaks[sl_key]}'"
                )
            # Print SPLeak
            for n in sorted(list(obj.spleak)):
                self.startEndNode("specific", str(n))

            self.endNode("result")

        elif isinstance(obj, LibHierarchy):
            self.startNode("LibHierarchy")
            for k in sorted_keys(obj.entries):
                obj.entries[k].doprint(self, param1)
            self.endNode("LibHierarchy")
        elif isinstance(obj, Library):
            self.startNode("Lib")
            self.doprint_line(obj.__str__())
            for k in sorted_keys(obj.entries):
                obj.entries[k].doprint(self, param1)
            LeakCounter.count(obj).doprint(self)
            self.endNode("Lib")
        elif isinstance(obj, FunctionLeak):
            self.startNode("Function")
            self.doprint_line(obj.__str__())
            if param1:
                if len(obj.dataleaks) > 0:
                    self.startNode(DATALEAKS)
                    for leak in sorted_keys(obj.dataleaks):
                        leak.doprint(self)
                    self.endNode(DATALEAKS)
                if len(obj.cfleaks) > 0:
                    self.startNode(CFLEAKS)
                    for leak in sorted_keys(obj.cfleaks):
                        leak.doprint(self)
                    self.endNode(CFLEAKS)
            self.endNode("Function")
        else:
            debug(0, "Unknown instance %s", (obj.__class__))
            debug(0, str(isinstance(obj, CallHistory)))
            debug(0, str(type(obj) is CallHistory))
            debug(0, str(id(type(obj))))
            debug(0, str(id(CallHistory)))
            assert False


"""
*************************************************************************
"""

"""
Binary file format:

    1B        8B        1B    len * 8B
  [Type]     [ip]      [len] [val1, val2, ...]

Used entries:
  FUNC_ENTRY ip-caller  1     ip-callee
  FUNC_EXIT  0          0
  DLEAK      ip         0
  CFLEAK     ip         n      mergepoint 1 ... mergepoint n
"""


class BinLeakPrinter:
    def __init__(self, outfile):
        self.outstream = outfile

    def doprint(self, text, ip, leak):
        pass

    def doprint_line(self, typ, ip=0, val=()):
        data = struct.pack("<BQB", *(typ.value, ip, len(val)))
        self.outstream.write(data)
        if len(val) > 0:
            data = struct.pack("%sQ" % len(val), *val)
            self.outstream.write(data)
        return
        self.outstream.write("%s: %x (%d) " % (str(typ), ip, len(val)))
        for v in val:
            self.outstream.write("%x," % (v))
        self.outstream.write("\n")

    def doprint_hierarchy(self, leaks):
        self.doprint_generic(leaks)

    def doprint_flat(self, flat):
        pass

    def doprint_generic(self, obj, param1=None):
        if isinstance(obj, LeakCounter):
            pass
        elif isinstance(obj, CallHistory):
            if obj.ctxt is not None:
                self.doprint_line(Type.FUNC_ENTRY, obj.ctxt.caller, [obj.ctxt.callee])
            if len(obj.dataleaks) > 0:
                for leak in sorted_keys(obj.dataleaks):
                    leak.doprint(self)
            if len(obj.cfleaks) > 0:
                for leak in sorted_keys(obj.cfleaks):
                    leak.doprint(self)
            for k in sorted_keys(obj.children):
                obj.children[k].doprint(self, param1)
            if obj.ctxt is not None:
                self.doprint_line(Type.FUNC_EXIT)
        elif isinstance(obj, CFLeak):
            self.doprint_line(Type.CFLEAK, obj.ip, obj.get_mergepoint())
        elif isinstance(obj, DataLeak):
            self.doprint_line(Type.DLEAK, obj.ip)
        else:
            debug(0, "Unknown instance %s", (obj.__class__))
            assert False

    def printHeader(self):
        pass

    def printFooter(self):
        pass
