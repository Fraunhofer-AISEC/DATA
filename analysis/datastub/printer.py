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
# @version 0.2

"""
*************************************************************************
"""

import struct
from datastub.utils import debug
from datastub.SymbolInfo import SymbolInfo
from datastub.leaks import LeakCounter,CallHistory,sorted_keys,CFLeak,\
DataLeak,CFLeakEntry,DataLeakEntry,LeakStatus,LibHierarchy,Library,\
FunctionLeak,Type

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
        self.outstream.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
        self.startNode("Report")
    
    def printFooter(self):
        self.endNode("Report")
    
    def startNode(self, node):
        self.outstream.write(" " * self.depth)
        self.outstream.write("<%s>\n" % (node))
        self.depth += 1
    
    def endNode(self, node):
        assert(self.depth > 0)
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
    
    def doprint_generic(self, obj, param1 = False):
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
            combinedset = set(obj.cflow_leaks_specific.keys()).union(set(obj.data_leaks_specific.keys()))
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
        elif isinstance(obj, CFLeak):
            self.startNode(CFLEAK)
            self.doprint("", obj.ip, obj.entries if param1 else None)
            self.doprint_generic(obj.status)
            self.endNode(CFLEAK)
        elif isinstance(obj, DataLeak):
            self.startNode(DATALEAK)
            self.doprint("", obj.ip, obj.entries if param1 else None)
            self.doprint_generic(obj.status)
            if param1:
                keys = sorted_keys(obj.entries)
                if len(keys) > 0:
                    self.startNode("MIN")
                    self.doprint("", obj.entries[keys[0]].addr, None)
                    self.endNode("MIN")
                    if len(keys) >= 2:
                        self.startNode("MAX")
                        self.doprint("", obj.entries[keys[-1]].addr, None)
                        self.endNode("MAX")
            self.endNode(DATALEAK)
        elif isinstance(obj, CFLeakEntry):
            self.doprint_line(obj.__str__())
        elif isinstance(obj, DataLeakEntry):
            self.doprint_line(obj.__str__())
        elif isinstance(obj, LeakStatus):
            if len(obj.nsleak) > 0 or len(obj.spleak) > 0:
                self.startNode("result " + str(obj))
                for n in sorted(list(obj.nsleak)):
                    self.startEndNode("generic", str(n))
                for n in sorted(list(obj.spleak)):
                    self.startEndNode("specific", str(n))
                self.endNode("result")
            else:
                self.startEndNode("result", str(obj))
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
            assert(False)

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
    
    def doprint_line(self, typ, ip = 0, val = ()):
        data = struct.pack("<BQB", *(typ.value, ip, len(val)))
        self.outstream.write(data)
        if len(val) > 0:
            data = struct.pack("%sQ" % len(val), *val)
            self.outstream.write(data)
        return
        self.outstream.write("%s: %x (%d) " % (str(typ), ip, len(val)))
        for v in val:
            self.outstream.write("%x," % (v))
        self.outstream.write("\n");
        
    
    def doprint_hierarchy(self, leaks):
        self.doprint_generic(leaks)
    
    def doprint_flat(self, flat):
        pass
    
    def doprint_generic(self, obj, param1 = None):
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
            assert(False)
        
    def printHeader(self):
        pass
    
    def printFooter(self):
        pass

