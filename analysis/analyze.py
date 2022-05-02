#!/usr/bin/env python

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
# @package analysis.analyze
# @file analyze.py
# @brief Main analysis script.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3


import sys
import os
import fcntl
import click
import struct
import copy
import numpy
import types
import fnmatch
import natsort
from collections import Counter, defaultdict
import kuipertest
import rdctest
import datastub
from datastub.SymbolInfo import SymbolInfo
from datastub.utils import debug, debuglevel, set_debuglevel, sorted_keys
from datastub.printer import XmlLeakPrinter, BinLeakPrinter
from datastub.export import storepickle, loadpickle, export_leaks
from datastub.leaks import (
    FUNC_ENTRY_BIN,
    FUNC_EXIT_BIN,
    bs,
    CallHistory,
    CallStack,
    CFLeak,
    CFLeakEntry,
    Context,
    DataLeak,
    DataLeakEntry,
    Entry,
    EvidenceEntry,
    EvidenceSource,
    Lookahead,
    MergePoint,
    NSLeak,
    NSPType,
    SPLeak,
    TraceQueue,
    Type,
    MaskType,
    Leak,
)
import multiprocessing

nospleak = None

"""
*************************************************************************
"""

printer = None
queues = None
leaks = CallHistory()

"""
*************************************************************************
"""


def report_dataleak(callstack, e1, e2):
    debug(1, "Data leak@ %08x: %08x vs %08x", (e1.ip, e1.data, e2.data))
    if debuglevel(3):
        callstack.doprint_reverse()
    leak = DataLeak(e1.ip)
    leak.append(DataLeakEntry(e1.data))
    leak.append(DataLeakEntry(e2.data))
    leaks.report_leak(callstack, leak)


def report_cfleak(callstack, bp, mp, e1, len1, e2, len2):
    debug(
        1,
        "Control flow leak@BB %08x, merging@%08x(%s): %08x(%s)(+%d) vs %08x(%s)(+%d)",
        (
            bp,
            mp.ip,
            Type(mp.type).name,
            e1.ip,
            Type(e1.type),
            len1,
            e2.ip,
            Type(e2.type),
            len2,
        ),
    )
    if debuglevel(3):
        callstack.doprint_reverse()
    leak = CFLeak(bp)
    leak.append(CFLeakEntry(e1, len1, mp.ip))
    leak.append(CFLeakEntry(e2, len2, mp.ip))
    leaks.report_leak(callstack, leak)


"""
*************************************************************************
"""


# Both queues have advanced by a chunk which is not consumed yet but
# equal. We search for calls and rets in one chunk and apply it to both
# queue's call stacks.
def consume_call_ret(queues):
    assert queues[0].chunk is not None
    assert len(queues[0].chunk) % bs == 0
    cblocks = int(len(queues[0].chunk) / bs)
    for i in range(0, cblocks):
        idx = 17 * i
        typ = queues[0].chunk[idx : idx + 1]
        if typ == FUNC_ENTRY_BIN or typ == FUNC_EXIT_BIN:
            e = Entry(struct.unpack("<BQQ", queues[0].chunk[idx : idx + 17]))
            queues[0].callstack.update_context(e)
            queues[1].callstack.update_context(e)
    queues[0].chunk = None
    queues[1].chunk = None


def fast_forward(queues, bp, bdepth):
    # Try at most 5 times to equalize queue size
    # First try might not work since conditional branches are stored
    # as one element in the file but reported as two elements in the queue.
    for _ in range(1, 5):
        s0 = queues[0].size()
        s1 = queues[1].size()
        if s0 > s1:
            queues[1].refill(s0 - s1)
        elif s1 > s0:
            queues[0].refill(s1 - s0)
        else:
            break

    if queues[0].size() != queues[1].size():
        debug(
            2,
            "[fast-forward] queue alignment error %d vs %d",
            (queues[0].size(), queues[1].size()),
        )
        return [queues[0].get(), queues[1].get(), bp, bdepth]

    while queues[0].size() > 0:
        e1 = queues[0].get()
        e2 = queues[1].get()
        if e1 is None:
            assert e2 is None
            break
        if e1 == e2:
            if Type.isbranch(e1):
                bp = e1
                bdepth = queues[0].callstack.depth()
            continue
        else:
            return [e1, e2, bp, bdepth]
    assert queues[1].size() == 0

    # Queues are empty, start fast forward
    debug(2, "[fast-forward] starting fast search")
    while True:
        if not queues[0].load_chunk():
            break
        if not queues[1].load_chunk():
            break
        if queues[0].chunk != queues[1].chunk:
            break
        newbp = queues[0].peak_last_branch_from_chunk()
        # It could happen by incredibly bad luck that last chunk does not contain a branch
        # In this case reuse previous bp.
        if newbp is not None:
            bp = newbp
        consume_call_ret(queues)
    debug(2, "[fast-forward] stopping fast search")
    if queues[0].chunk is not None:
        queues[0].refill_chunk()
    if queues[1].chunk is not None:
        queues[1].refill_chunk()
    bdepth = queues[0].callstack.depth()
    e1 = queues[0].get()
    e2 = queues[1].get()
    return [e1, e2, bp, bdepth]


"""
*************************************************************************
"""


def iterate_queue(files, fast=True):
    global unpacked
    global trace
    global traces
    global queues
    bp = None
    bdepth = -1
    queues = [TraceQueue(files[i], i) for i in range(0, len(files))]
    queues[0].id = 0
    queues[1].id = 1
    while True:
        if fast:
            [e1, e2, bp, bdepth] = fast_forward(queues, bp, bdepth)
        else:
            e1 = queues[0].get()
            e2 = queues[1].get()

        if e1 is None or e2 is None:
            if e1 is not None or e2 is not None:
                debug(0, "Unbalanced end of trace")
            break

        if e1 == e2:
            # no diff
            assert queues[0].callstack == queues[1].callstack
            if Type.isbranch(e1):
                bp = e1
                bdepth = queues[0].callstack.depth()
            continue

        assert bp is None or Type.isbranch(bp)
        if e1.ip != e2.ip:
            # This should never happen. We miss some conditional branches in the code
            debug(0, "Missed some branch (outer miss) @ %08x vs %08x", (e1.ip, e2.ip))
            assert False
        if e1.type == e2.type and e1.ip == e2.ip:
            if Type.isbranch(e1):
                bp = e1
                bcallstack = copy.copy(queues[0].callstack)
                bdepth = bcallstack.depth()
                # We have a control flow leak
                debug(1, "CF Leak @ %08x, depth %d", (bp.ip, bdepth))
                if debuglevel(3):
                    queues[0].callstack.doprint_reverse()
                lhA = Lookahead(queues[0])
                lhB = Lookahead(queues[1])
                # Get 2 branches
                e1b = queues[0].lookahead(0)
                e2b = queues[1].lookahead(0)
                foundA = True
                foundB = True
                while True:
                    if foundA:
                        foundA = lhA.advance_next_bp_candidate(bdepth)
                    if foundB:
                        foundB = lhB.advance_next_bp_candidate(bdepth)
                    mergepoint = Lookahead.intersect(lhA, lhB)
                    if mergepoint is not None:
                        break
                    if not foundA and not foundB:
                        debug(0, "No mergepoint found!")
                        report_cfleak(
                            queues[0].callstack,
                            bp.ip,
                            MergePoint(Type.FUNC_EXIT, 0, 0),
                            e1b,
                            -1,
                            e2b,
                            -1,
                        )
                        return

                assert isinstance(mergepoint, MergePoint)
                debug(2, "found mp: %08x, depth %d", (mergepoint.ip, mergepoint.depth))
                for mp in lhA.myset:
                    debug(3, f"lhA {mp.ip:x}")
                for mp in lhB.myset:
                    debug(3, f"lhB {mp.ip:x}")

                # Advance to mergepoint
                debug(2, "advancing to mp:")
                if debuglevel(3):
                    queues[0].callstack.doprint_reverse()
                len1 = queues[0].advance(mergepoint)
                len2 = queues[1].advance(mergepoint)
                debug(
                    2,
                    "advanced to mp: %08x,%08x",
                    (queues[0].lookahead(0).ip, queues[1].lookahead(0).ip),
                )
                if debuglevel(3):
                    queues[0].callstack.doprint_reverse()

                assert queues[0].lookahead(0).ip == queues[1].lookahead(0).ip
                # assert(queues[0].callstack == queues[1].callstack)
                if not queues[0].callstack == queues[1].callstack:
                    queues[0].callstack.doprint_reverse()
                    print("====")
                    queues[1].callstack.doprint_reverse()
                    assert False
                assert Type.isbranch(bp)
                report_cfleak(bcallstack, bp.ip, mergepoint, e1b, len1, e2b, len2)

            elif Type(e1.type) in (Type.READ, Type.WRITE, Type.HREAD, Type.HWRITE):
                # We have a dataleak
                assert e1.data != 0
                assert e2.data != 0
                assert queues[0].callstack == queues[1].callstack
                if Type(e1.type) in (Type.HREAD, Type.HWRITE):
                    e1.data &= 0x00000000FFFFFFFF
                    e2.data &= 0x00000000FFFFFFFF
                if e1.data != e2.data:
                    report_dataleak(queues[0].callstack, e1, e2)
            else:
                debug(0, "Unknown type")
                assert False
        elif Type(e1.type) in (Type.READ, Type.WRITE, Type.HREAD, Type.HWRITE):
            if Type(e2.type) in (Type.READ, Type.WRITE, Type.HREAD, Type.HWRITE):
                # Mixture of heap and non-heap read/write. Maybe, heap tracking is imprecise
                # We require that both elements are either (h)read or (h)write
                debug(0, "Imprecise heap tracking @ %08x", (e1.ip))
                # assert((e1.type | MaskType.HEAP.value) == (e2.type | MaskType.HEAP.value))
                if (e1.type | MaskType.HEAP.value) > 0:
                    e1.data &= 0x00000000FFFFFFFF
                if (e2.type | MaskType.HEAP.value) > 0:
                    e2.data &= 0x00000000FFFFFFFF
                report_dataleak(queues[0].callstack, e1, e2)
            else:
                # This should never happen. We miss some conditional branches in the code
                debug(0, "Missed some branch (inner miss)")
                assert False
        else:
            # This should never happen. We miss some conditional branches in the code
            debug(0, "Missed some branch (outer miss) @ %08x vs %08x", (e1.ip, e2.ip))
            assert False


"""
*************************************************************************
"""


def loadkeys(directory):
    keyfiles = fnmatch.filter(os.listdir(directory), "*.key")
    keyfiles = natsort.natsorted(keyfiles)
    keys = list()
    for k in keyfiles:
        with open(os.path.join(directory, k)) as f:
            key = f.readline().encode("utf-8")
            keys.append(key)
    return keys


"""
*************************************************************************
"""


def load_leaks(files, keys, source):
    def read_and_advance(chunk, idx, format_type, length):
        if format_type == "B":
            byte_length = length
        elif format_type == "Q":
            byte_length = length * 8
        else:
            assert False
        format_character = f"<{length}{format_type}"
        data = struct.unpack(format_character, chunk[idx : idx + byte_length])
        return (data, idx + byte_length)

    if keys is None:
        assert False

    origin = "fixed" if len(set(keys)) == 1 else "random"

    key_index = 0
    if origin == "fixed":
        # This parsing requires a naming scheme like: `key1.key`
        key_index = int(set(keys).pop().replace("key", "").replace(".", ""))

    for (trace_file, key_file) in zip(files, keys):
        with open(trace_file, "rb") as tf, open(key_file, "rb") as kf:
            trace = tf.read()
            key = kf.read()

        idx = 0
        cs = CallStack()
        while idx < len(trace):
            (data, idx) = read_and_advance(trace, idx, "B", 1)
            typ = data[0]

            if typ not in [
                Type.FUNC_ENTRY.value,
                Type.FUNC_EXIT.value,
                Type.CFLEAK.value,
                Type.DLEAK.value,
            ]:
                debug(0, f"Unknown type: {typ}")
                assert False

            if typ == Type.FUNC_EXIT.value:
                debug(2, "FUNC_EXIT")
                cs.doreturn_context()
                continue

            (data, idx) = read_and_advance(trace, idx, "Q", 2)

            if typ == Type.FUNC_ENTRY.value:
                (caller, callee) = data
                debug(2, "FUNC_ENTRY %x->%x", (caller, callee))
                cs.docall_context(Context(caller, callee))
                continue

            (ip, no) = data
            leak = CFLeak(ip) if typ == Type.CFLEAK.value else DataLeak(ip)
            debug(2, f"{leak.name} {hex(ip)} ({no})")

            (evidence, idx) = read_and_advance(trace, idx, "Q", no)
            debug(2, str(evidence))

            ee = EvidenceEntry(evidence, key, source, origin, key_index)
            leak.add_evidence(ee)
            if debuglevel(3):
                cs.doprint_reverse()
            leaks.report_leak(cs, leak, False)


"""
*************************************************************************
"""


def extract_leakdiff_to_array(A, LeaksOnly=False):
    array = []
    for leak in A.dataleaks:
        if LeaksOnly:
            if leak.status.is_generic_leak():
                array.append(leak)
        else:
            array.append(leak)
    for leak in A.cfleaks:
        if LeaksOnly:
            if leak.status.is_generic_leak():
                array.append(leak)
        else:
            array.append(leak)
    for k in A.children:
        child = A.children[k]
        array += extract_leakdiff_to_array(child, LeaksOnly)
    return array


"""
*************************************************************************
"""


def generic_leakage_test(fixed, random):
    fixedleaks = extract_leakdiff_to_array(fixed)
    randomleaks = extract_leakdiff_to_array(random)
    assert len(fixedleaks) == len(randomleaks)

    # print test types
    debug(1, "Test Types:")
    debug(1, "    1a ... number of addresses")
    debug(1, "    1b ... number of unique addresses")
    debug(1, "    2 .... number of accesses per address")
    debug(1, "")

    # iterate over leaks
    debug(0, "Got %d trace differences.", (len(fixedleaks)))
    sys.stdout.flush()
    for i in range(0, len(fixedleaks)):
        fl = fixedleaks[i]
        rl = randomleaks[i]
        assert fl.ip == rl.ip
        msgwarning = ""
        msgleak = ""
        cursym = SymbolInfo.lookup(fl.ip)
        if (cursym is not None) and (len(cursym.name) > 0):
            cursym = cursym.name[0]
        else:
            cursym = None

        # Parse key_index and key
        key_index = set(e.key_index for e in fl.evidence)
        key = set(e.key for e in fl.evidence)
        ## Check if `fl` only contains fixed traces
        if len(key_index) != 1 or len(key) != 1:
            assert False
        key_index = key_index.pop()
        key = key.pop()

        # always test
        leaktype = "dataleak" if isinstance(fl, DataLeak) else "cfleak"
        msgwarning += "Testing %s@%x...\n" % (leaktype, fl.ip)
        msgleak += "Testing %s@%x...\n" % (leaktype, fl.ip)
        fl.status.nsperformed = True
        rl.status.nsperformed = True

        # sanity check
        cont = False
        if len(fl.evidence) == 0:
            msgwarning += "    warning: no evidences for fixed\n"
            cont = True
        if len(rl.evidence) == 0:
            msgwarning += "    warning: no evidences for random\n"
            cont = True
        if cont:
            debug(0, msgwarning.rstrip())
            continue

        # init
        fnum = {}
        fnum_uniq = {}
        rnum = {}
        rnum_uniq = {}
        fdic = {}
        rdic = {}

        # gather information (fixed)
        for e in fl.evidence:
            if len(e.entries) == 0:
                continue
            if e.source != EvidenceSource.Generic.value:
                continue

            # all entries
            selentries = e.entries

            # Type1a/b
            cn = len(selentries)
            cnu = len(set(selentries))
            if cn in fnum.keys():
                fnum[cn] += 1
            else:
                fnum[cn] = 1
            if cnu in fnum_uniq.keys():
                fnum_uniq[cnu] += 1
            else:
                fnum_uniq[cnu] = 1

            # Type2
            counts = Counter(selentries)
            for c in counts.keys():
                if c in fdic:
                    fdic[c] += counts[c]
                else:
                    fdic[c] = counts[c]

        # gather information (random)
        for e in rl.evidence:
            if len(e.entries) == 0:
                continue
            if e.source != EvidenceSource.Generic.value:
                continue

            # all entries
            selentries = e.entries

            # Type1a/b
            cn = len(selentries)
            cnu = len(set(selentries))
            if cn in rnum.keys():
                rnum[cn] += 1
            else:
                rnum[cn] = 1
            if cnu in rnum_uniq.keys():
                rnum_uniq[cnu] += 1
            else:
                rnum_uniq[cnu] = 1

            # Type2
            counts = Counter(selentries)
            for c in counts.keys():
                if c in rdic:
                    rdic[c] += counts[c]
                else:
                    rdic[c] = counts[c]

        # sanity check
        if (
            len(fnum) == 0
            or len(rnum) == 0
            or len(fnum_uniq) == 0
            or len(rnum_uniq) == 0
        ):
            continue

        ######
        # Test1a: number of addresses
        ######

        cfl = NSLeak(NSPType.Type1a, key_index, key)
        # sanity check
        cont = False
        if len(fnum) == 0:
            cont = True
        if len(rnum) == 0:
            cont = True

        # test
        if not cont:
            # solve entry mismatches
            fset = set(fnum.keys())
            rset = set(rnum.keys())
            if fset != rset:
                for s in list(fset - rset):
                    rnum[s] = 0
                for s in list(rset - fset):
                    fnum[s] = 0

            # compile histograms
            fhist = numpy.array(
                [fnum[j] for j in sorted(fnum.keys())], dtype=numpy.float32
            )
            rhist = numpy.array(
                [rnum[j] for j in sorted(rnum.keys())], dtype=numpy.float32
            )
            fhist_len = numpy.int32(numpy.sum(fhist))
            rhist_len = numpy.int32(numpy.sum(rhist))

            # sanity check
            cont = False
            if fhist_len < 30:
                cont = True
            if rhist_len < 30:
                cont = True

            # stat test
            if not cont:
                (D, L) = kuipertest.kp_histogram(
                    fhist, rhist, fhist_len, rhist_len, 0.9999
                )
                assert not (numpy.isnan(D) or numpy.isnan(L))
                R = D > L
                cfl = NSLeak(NSPType.Type1a, key_index, key, None, D, L, 0.9999, R)
        fl.status.nsleak += [cfl]
        msgleak += "    [Test1a] -- %s\n" % str(cfl)

        ######
        # Test1b: number of unique addresses
        ######

        cfl = NSLeak(NSPType.Type1b, key_index, key)
        # sanity check
        cont = False
        if len(fnum_uniq) == 0:
            cont = True
        if len(rnum_uniq) == 0:
            cont = True

        # test
        if not cont:
            # solve entry mismatches
            fset = set(fnum_uniq.keys())
            rset = set(rnum_uniq.keys())
            if fset != rset:
                for s in list(fset - rset):
                    rnum_uniq[s] = 0
                for s in list(rset - fset):
                    fnum_uniq[s] = 0

            # compile histograms
            fhist = numpy.array(
                [fnum_uniq[j] for j in sorted(fnum_uniq.keys())], dtype=numpy.float32
            )
            rhist = numpy.array(
                [rnum_uniq[j] for j in sorted(rnum_uniq.keys())], dtype=numpy.float32
            )
            fhist_len = numpy.int32(numpy.sum(fhist))
            rhist_len = numpy.int32(numpy.sum(rhist))

            # sanity check
            cont = False
            if fhist_len < 30:
                cont = True
            if rhist_len < 30:
                cont = True

            # stat test
            if not cont:
                (D, L) = kuipertest.kp_histogram(
                    fhist, rhist, fhist_len, rhist_len, 0.9999
                )
                assert not (numpy.isnan(D) or numpy.isnan(L))
                R = D > L
                cfl = NSLeak(NSPType.Type1b, key_index, key, None, D, L, 0.9999, R)
        fl.status.nsleak += [cfl]
        msgleak += "    [Test1b] -- %s\n" % str(cfl)

        ######
        # Test2: number of accesses per address
        ######

        cfl = NSLeak(NSPType.Type2, key_index, key)
        # sanity check
        cont = False
        if len(fdic.keys()) == 0:
            cont = True
        if len(rdic.keys()) == 0:
            cont = True

        # test
        if not cont:
            # solve entry mismatches
            fset = set(fdic.keys())
            rset = set(rdic.keys())
            if fset != rset:
                for s in list(fset - rset):
                    rdic[s] = 0
                for s in list(rset - fset):
                    fdic[s] = 0

            # compile histograms
            fhist = numpy.array(
                [fdic[j] for j in sorted(fdic.keys())], dtype=numpy.float32
            )
            rhist = numpy.array(
                [rdic[j] for j in sorted(rdic.keys())], dtype=numpy.float32
            )
            fhist_len = numpy.int32(numpy.sum(fhist))
            rhist_len = numpy.int32(numpy.sum(rhist))

            # sanity check
            cont = False
            if fhist_len < 30:
                cont = True
            if rhist_len < 30:
                cont = True

            # stat test
            if not cont:
                (D, L) = kuipertest.kp_histogram(
                    fhist, rhist, fhist_len, rhist_len, 0.9999
                )
                assert not (numpy.isnan(D) or numpy.isnan(L))
                R = D > L
                cfl = NSLeak(NSPType.Type2, key_index, key, None, D, L, 0.9999, R)
        fl.status.nsleak += [cfl]
        msgleak += "    [Test2]  -- %s\n" % str(cfl)

        debug(1, msgleak.rstrip())

        # progress
        if len(fixedleaks) > 100:
            if (i % int(len(fixedleaks) / 10)) == 0:
                debug(0, "[Progress] %6.2f%%", ((i * 100.0) / len(fixedleaks)))
        else:
            debug(0, "[Progress] Finished %d", (i + 1))
        sys.stdout.flush()
    debug(0, "[Progress] 100.00%%")
    sys.stdout.flush()


"""
*************************************************************************
"""


def spe_testfunction_initialize(_X_labels, _xtarget):
    global X_labels, xtarget
    X_labels = _X_labels
    xtarget = _xtarget


"""
*************************************************************************
"""


def spe_testfunction(input):
    # global X_labels
    rli, xarr, property_idx, dict_value, dict_key, nsptype = input
    debug(
        3,
        "spe_testfunction: {}, {}, {}, {} START".format(
            property_idx, X_labels[property_idx], nsptype, dict_key
        ),
    )
    (R, L, I) = rdctest.RDC.test(xarr, dict_value, 0.9999)
    debug(
        3,
        "spe_testfunction: {}, {}, {}, {} END".format(
            property_idx, X_labels[property_idx], nsptype, dict_key
        ),
    )
    if I is not None and bool(I) is False:
        leak = SPLeak(
            nsptype,
            X_labels[property_idx],
            dict_key,
            None,
            R,
            L,
            I,
            xtarget,
            0.9999,
        )
        debug(1, "Found leak [Test2+3]: %s", (str(leak)))
        return (rli, leak)
    return (rli, None)


# Specific leakage test requires a callback function that gets a list
# of inputs (e.g. keys) and returns a 2-dimensional numpy array. The
# rows select a specific input, the columns select a specific leakage
# value of that input.
#
# For instance: the function is given a list of 10 AES-128 keys. Each key
# has 16 bytes and the leakage model is the Hamming Weight per key byte.
# Thus, the function creates a 10x16 numpy array that contains 10 rows
# and 16 Hamming Weights per row.
#
# The callback function signature is:
#     def specific_leakage_callback(inputs):
#         a = numpy.ndarray((len(inputs), ...))
#         ...
#         return a
#
def specific_leakage_test(random, callback, keys, LeaksOnly=True, mp=False):
    global nospleak

    # load callback function
    debug(1, "Loading specific leakage model")
    try:
        with open(callback) as fp:
            code = compile(fp.read(), callback, "exec")
        splcb = types.ModuleType("<config>")
        exec(code, splcb.__dict__)
    except Exception as e:
        debug(0, "Unable to load specific leakage test callback function!")
        debug(0, str(e))
        assert False
    assert splcb.specific_leakage_callback
    xtarget = str(os.path.splitext(os.path.basename(callback))[0])
    nospleak = SPLeak(NSPType.Noleak, target=xtarget)

    # print test types
    debug(1, "Test Types:")
    debug(1, "    2 .... number of accesses per address")
    debug(1, "    3 .... position of address during access")
    debug(1, "")

    # process leaks
    randomleaks = extract_leakdiff_to_array(random, LeaksOnly=LeaksOnly)
    debug(0, "Got %d leaks.", (len(randomleaks)))
    sys.stdout.flush()

    # convert keys with callback
    # the callback always returns the matrix X:
    #
    # x_{0,0} x_{0,1} ... x_{0,N}
    # x_{1,0} x_{1,1} ... x_{1,N}
    # ...
    # x_{M,0} x_{M,1} ... x_{M,N}
    #
    # M ... number of keys (one row per key)
    # N ... number of properties in X (one column per property)
    debug(1, "Building leakage model input from keys")
    X = splcb.specific_leakage_callback(keys)
    X_labels = []
    # unpack specific leakage result tuple to extract labels
    if type(X) == tuple:
        X, X_labels = X
    else:
        X_labels = range(0, X.shape[1])
    assert type(X) == numpy.ndarray
    assert len(X_labels) == X.shape[1]

    Xglob = dict(zip(keys, X))

    # Todo: make use of above X/X_labels in below code.
    # Beware of extracting only needed entries

    # Multiprocessing-queue
    queue = list()
    for rli in range(0, len(randomleaks)):
        debug(1, "Loading leak %d/%d", (rli, len(randomleaks)))
        rl = randomleaks[rli]
        noleakdetected = True
        leaktype = "dataleak" if isinstance(rl, DataLeak) else "cfleak"
        debug(1, "Testing %s@%x...", (leaktype, rl.ip))
        cursym = SymbolInfo.lookup(rl.ip)
        if (cursym is not None) and (len(cursym.name) > 0):
            cursym = cursym.name[0]
        else:
            cursym = None
        rl.status.spperformed.add(xtarget)

        # sanity check
        if len(rl.evidence) == 0:
            debug(0, "Warning: no evidences")
            continue

        # gather information -- leaks
        rdic = {}
        cnt_t2 = 0
        rdic_pos = {}
        cnt_t3 = 0
        keys = []
        for e in rl.evidence:
            if len(e.entries) == 0:
                debug(3, "Empty evidence entries")
                continue
            if e.source != EvidenceSource.Specific.value:
                continue

            # all entries
            selentries = e.entries

            # gather information -- keys
            if e.key is None or len(e.key) == 0:
                debug(0, "Error: Key is empty: %s", ((e.key)))
                assert False
            keys.append(e.key)

            # gather information -- type2
            chist = Counter(selentries)
            rset = set(rdic.keys())
            cset = set(chist.keys())
            for s in list(cset - rset):
                rdic[s] = [0] * cnt_t2
            for c in rdic.keys():
                if c in chist.keys():
                    rdic[c] += [chist[c]]
                else:
                    rdic[c] += [0]
            cnt_t2 += 1

            # gather information -- type3
            cs = set(selentries)
            for c in cs:
                cp = [pos for pos, j in enumerate(selentries) if j == c]
                if c not in rdic_pos.keys():
                    rdic_pos[c] = [-1] * cnt_t3
                rdic_pos[c] += [int(numpy.round(numpy.median(cp)))]
            for s in list(set(rdic_pos.keys()) - cs):
                rdic_pos[s] += [-1]
            cnt_t3 += 1

        if len(keys) == 0:
            debug(1, "Warning: Keys are empty. No evidences")
            continue

        # postprocessing -- type2
        for c in rdic.keys():
            rdic[c] = numpy.asarray(rdic[c], dtype=numpy.uint64)

        # postprocessing -- type3
        for c in rdic_pos.keys():
            rdic_pos[c] = numpy.array(rdic_pos[c], dtype=numpy.int64)

        # Extract X in correct order
        X = numpy.asarray([Xglob[k] for k in keys])
        assert type(X) == numpy.ndarray
        assert len(X_labels) == X.shape[1]

        if X.shape[0] != len(keys):
            debug(0, "Warning: callback returned wrong matrix!")
            continue

        ######
        # Test2: number of accesses per address
        # Test3: position of address during access
        ######

        def report_nospleak(rl):
            global nospleak
            rl.status.spleak.add(nospleak)
            leaktype = "dataleak" if isinstance(rl, DataLeak) else "cfleak"
            debug(2, "Reporting %s@%x: %s", (leaktype, rl.ip, str(nospleak)))

        def report_spleak(rl, cleak):
            rl.status.spleak.add(cleak)
            leaktype = "dataleak" if isinstance(rl, DataLeak) else "cfleak"
            debug(1, "Reporting %s@%x: %s", (leaktype, rl.ip, str(cleak)))

        if mp:
            # Multiproccesing: prepare queue for later analysis
            # Test 2
            queue.extend(
                [
                    (rli, X[:, prop], prop, rdic[k], k, NSPType.Type2)
                    for prop in range(0, X.shape[1])
                    for k in rdic.keys()
                ]
            )
            # Test 3
            queue.extend(
                [
                    (rli, X[:, prop], prop, rdic_pos[k], k, NSPType.Type3)
                    for prop in range(0, X.shape[1])
                    for k in rdic_pos.keys()
                ]
            )
        else:
            # Single-threaded: do analysis immediately
            cleaks = list()
            spe_testfunction_initialize(X_labels, xtarget)
            for prop in range(0, X.shape[1]):
                for k in rdic.keys():
                    cleaks.append(
                        spe_testfunction(
                            (rli, X[:, prop], prop, rdic[k], k, NSPType.Type2)
                        )[1]
                    )
                for k in rdic_pos.keys():
                    cleaks.append(
                        spe_testfunction(
                            (rli, X[:, prop], prop, rdic_pos[k], k, NSPType.Type3)
                        )[1]
                    )

            # Collect results
            for cleak in cleaks:
                if cleak:
                    noleakdetected = False
                    report_spleak(rl, cleak)

            # No leaks
            if noleakdetected:
                report_nospleak(rl)

            # Print progress
            if len(randomleaks) > 100:
                if (rli % int(len(randomleaks) / 10)) == 0:
                    debug(0, "[Progress] %6.2f%%", ((rli * 100.0) / len(randomleaks)))
            else:
                debug(0, "[Progress] %d/%d", (rli + 1, len(randomleaks)))
            sys.stdout.flush()
    if mp:
        pool_size = multiprocessing.cpu_count()
        # os.system('taskset -cp 0-%d %s' % (pool_size, os.getpid()))
        debug(1, "Processing all leaks in parallel")
        with multiprocessing.Pool(
            pool_size,
            spe_testfunction_initialize,
            initargs=(
                X_labels,
                xtarget,
            ),
        ) as pool:
            debug(1, "Collecting results")
            results = pool.map(spe_testfunction, queue)
            rlset = set()
            rlall = set()
            for result in results:
                rli, cleak = result
                rl = randomleaks[rli]
                rlall.add(rl)
                if cleak:
                    rlset.add(rl)
                    report_spleak(rl, cleak)
            # No leaks
            for rl in rlall.difference(rlset):
                report_nospleak(rl)
    debug(0, "Finished specific analysis")
    sys.stdout.flush()


"""
*************************************************************************
"""


def precompute_single(input):
    # global precompute_rdc_file
    # global precompute_alpha
    N = input
    debug(1, "Precomputing RDC for N=%d, alpha=%f", (N, precompute_alpha))
    limit = rdctest.RDC.rdc_sigthres_compute(N, precompute_alpha)
    debug(1, "RDC_limit=%f for N=%d, alpha=%f", (limit, N, precompute_alpha))
    with open(precompute_rdc_file, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write("%4d:  %f,\n" % (N, limit))
        fcntl.flock(f, fcntl.LOCK_UN)
    return (N, limit)


"""
*************************************************************************
"""

"""
Precompute RDC limits using multiprocessing.
"""


def get_rdc_single(N, alpha):
    limit = rdctest.RDC.rdc_sigthres(N, alpha)
    debug(0, "RDC_limit=%f for N=%d, alpha=%f", (limit, N, alpha))


"""
*************************************************************************
"""

"""
Precompute RDC limits using multiprocessing.
"""


def precompute_rdc_parallel(target, alpha):
    global precompute_rdc_file
    global precompute_alpha
    precompute_rdc_file = target
    precompute_alpha = alpha
    debug(0, "Writing results to %s", (target))
    pool_size = multiprocessing.cpu_count()
    with multiprocessing.Pool(pool_size, None, None) as pool:
        inp = list()
        inp.extend([(i) for i in range(30, 500, 10)])
        inp.extend([(i) for i in range(550, 1000, 50)])
        inp.extend([(i) for i in range(5000, 10000, 200)])
        debug(0, "Precompute parallel on %s", (inp))
        pool.map(precompute_single, inp)


"""
*************************************************************************
"""

"""
Merge leaks B into global leaks.
"""


def merge_leaks(B):
    merge_leaks_recursive(B, CallStack())


def merge_leaks_recursive(B, callstack):
    if debuglevel(3):
        callstack.doprint_reverse()
    for leak in B.dataleaks:
        c = copy.deepcopy(leak)
        leaks.report_leak(callstack, c)
    for leak in B.cfleaks:
        c = copy.deepcopy(leak)
        leaks.report_leak(callstack, c)
    for k in B.children:
        child = B.children[k]
        callstack.docall_context(child.ctxt)
        merge_leaks_recursive(child, callstack)
        callstack.doreturn_context()


def match_filter(leak, filterarr):
    status = str(leak.status).replace('"', "").replace("'", "")
    for f in filterarr:
        if f not in status:
            return False
    return True


"""
*************************************************************************
"""

"""
mask ... bitmask to apply to all addresses
"""


def collapse_leaks_recursive(
    leaks, collapsed, callstack, collapse_cfleaks, mask, filterarr
):
    for leak in leaks.dataleaks:
        debug(1, "Collapse dleak %x", (leak.ip))
        if len(filterarr) > 0 and not match_filter(leak, filterarr):
            debug(1, "Filtering dleak %x", (leak.ip))
            continue
        n = leak.clone_collapsed(mask)
        if len(n.entries) <= 1:
            debug(1, "Ignoring dleak %x", (n.ip))
        else:
            collapsed.report_leak(callstack, n)
    for leak in leaks.cfleaks:
        debug(1, "Collapse dleak %x", (leak.ip))
        if len(filterarr) > 0 and not match_filter(leak, filterarr):
            debug(1, "Filtering cfleak %x", (leak.ip))
            continue
        n = leak.clone_collapsed(mask, collapse_cfleaks)
        if len(n.entries) <= 1:
            debug(1, "Ignoring cfleak %x", (n.ip))
        else:
            collapsed.report_leak(callstack, n)
    for k in leaks.children:
        child = leaks.children[k]
        callstack.docall_context(child.ctxt)
        collapse_leaks_recursive(
            child, collapsed, callstack, collapse_cfleaks, mask, filterarr
        )
        callstack.doreturn_context()
    return collapsed


"""
granularity ... number of bits
resfilter ... filter results by given strings, semicolon-separated
"""


def collapse_cfleaks(leaks, collapse_cfleaks, granularity, resfilter=""):
    mask = -1
    filterarr = []
    if granularity != 1:
        granularity -= 1
        blen = granularity.bit_length()
        # granularity must be power of 2
        assert 1 << blen == granularity + 1
        mask = -1 << blen
    if len(resfilter) > 0:
        filterarr = resfilter.replace('"', "").replace("'", "").split(";")
        for f in filterarr:
            debug(0, "Filtering results for: " + f)
    if mask == -1 and not collapse_cfleaks:
        # Nothing to collapse
        return leaks
    else:
        debug(1, "Collapsing")
        return collapse_leaks_recursive(
            leaks, CallHistory(), CallStack(), collapse_cfleaks, mask, filterarr
        )


"""
*************************************************************************
"""

"""
Strip all entries from leaks
"""


def strip_entries(leaks):
    for leak in leaks.dataleaks:
        if len(leak.entries) > 0:
            debug(3, "Removing %d entries" % (len(leak.entries)))
        leak.entries = []
    for leak in leaks.cfleaks:
        if len(leak.entries) > 0:
            debug(3, "Removing %d entries" % (len(leak.entries)))
        leak.entries = []
    for k in leaks.children:
        child = leaks.children[k]
        strip_entries(child)


"""
*************************************************************************
"""

"""
Strip all evidences from leaks
"""


def strip_evidences(leaks):
    for leak in leaks.dataleaks:
        if len(leak.evidence) > 0:
            debug(3, "Removing %d evidences" % (len(leak.evidence)))
        leak.evidence = []
    for leak in leaks.cfleaks:
        if len(leak.evidence) > 0:
            debug(3, "Removing %d evidences" % (len(leak.evidence)))
        leak.evidence = []
    for k in leaks.children:
        child = leaks.children[k]
        strip_evidences(child)


"""
*************************************************************************
"""


def print_leaks(leaks, printer, doflatten=False, printerFlat=None):
    debug(1, "Storing XML file")
    if printerFlat is None:
        printerFlat = printer
    printer.printHeader()
    printer.doprint_hierarchy(leaks)
    if doflatten:
        flat = leaks.flatten()
        printerFlat.doprint_flat(flat)
    printer.printFooter()


"""
*************************************************************************
"""


def loadleaksglob(pfile):
    global leaks
    try:
        leaks = loadpickle(pfile)
        return True
    except IOError:
        return False


def add_elf_syms(symfile, newsymfile):
    with open(symfile, "r") as f:
        SymbolInfo.open(f)
    SymbolInfo.reload_syms_from_elf()
    with open(newsymfile, "w") as f:
        SymbolInfo.write(f)


def list_files(pattern, start, end):
    files = []
    for i in range(start, end + 1):
        fname = pattern.replace("%", str(i))
        files.append(fname)
    return files


"""
*************************************************************************
"""


@click.group()
def cli():
    pass


"""
Print symbol info for virtual address
"""


@cli.command("lookup")
@click.argument("syms", default=None, type=click.File("r"))
@click.argument("vaddr", default=None, type=str)
@click.option("--debug", default=-1, type=int)
def lookup(syms, vaddr, debug):
    set_debuglevel(debug)
    assert syms is not None
    if syms:
        SymbolInfo.open(syms)
    try:
        addr = int(vaddr, 16)
    except ValueError:
        datastub.utils.debug(0, "vaddr is not in hex format")
        return
    sym = SymbolInfo.lookup(addr)
    if sym is None:
        datastub.utils.debug(0, "No symbol found for vaddr %s" % (vaddr))
    else:
        print(sym.strat(addr))


"""
Add symbol information to existing symfile.
"""


@cli.command("addsyms")
@click.argument("symfile", type=str)
@click.argument("newsymfile", type=str)
@click.option("--debug", default=-1, type=int)
def addsyms(symfile, newsymfile, debug):
    global printer
    set_debuglevel(debug)
    add_elf_syms(symfile, newsymfile)


"""
Merge leakage from two pickle files.
"""


@cli.command("merge")
@click.argument("picklefiles", type=str, nargs=-1)
@click.option("--syms", default=None, type=click.File("r"))
@click.option("--xml", default=None, type=click.File("w"))
@click.option("--pickle", default=None, type=str)
@click.option("--strip_entry", default=False, type=bool)
@click.option("--strip", default=False, type=bool)
@click.option("--debug", default=-1, type=int)
def merge(picklefiles, syms, xml, pickle, strip, strip_entry, debug):
    global printer
    global leaks
    set_debuglevel(debug)
    assert xml is None or syms is not None
    if syms is not None:
        SymbolInfo.open(syms)
    if len(picklefiles) == 0:
        print("No pickle files to merge!")
        return 1
    for p in picklefiles:
        datastub.utils.debug(1, "Merging %s", (p))
        if not leaks:
            # First pickle file serves as reference
            leaks = loadpickle(p)
        else:
            leakB = loadpickle(p)
            merge_leaks(leakB)
    if strip_entry:
        strip_entries(leaks)
    if strip:
        strip_evidences(leaks)
    if pickle is not None:
        storepickle(pickle, leaks)
    if xml is not None:
        print_leaks(leaks, XmlLeakPrinter(xml), True)


"""
Load leaks from binary file. Open all leak-files
and keys, where character '%' is replaced with
index in range --start to --end.
"""


@cli.command("loadleaks")
@click.argument("pickle", type=str)
@click.argument("files", nargs=-1, type=click.File("rb"))  # Traditional file list
@click.option("--filepattern", default=None, type=str)
@click.option("--keypattern", default=None, type=str)
@click.option("--start", default=1, type=int)
@click.option("--end", default=1, type=int)
@click.option("--source", default=0, type=int)
@click.option("--debug", default=-1, type=int)
def loadleaks(pickle, files, filepattern, keypattern, start, end, source, debug):
    global printer
    set_debuglevel(debug)
    if pickle is not None:
        loadleaksglob(pickle)
    if filepattern is not None:
        files = list_files(filepattern, start, end)
    if keypattern is not None:
        keys = list_files(keypattern, start, end)
    else:
        keys = None
    load_leaks(files, keys, source)
    if pickle is not None:
        storepickle(pickle, leaks)


"""
Print, convert leaks to/from binary/xml/pickle.
"""


@cli.command("show")
@click.argument("picklefile", type=str)
@click.option("--syms", default=None, type=click.File("r"))
@click.option("--xml", default=None, type=click.File("w"))
@click.option("--leakout", default=None, type=click.File("wb"))
@click.option("--debug", default=-1, type=int)
def show(picklefile, syms, xml, leakout, debug):
    global printer
    global leaks
    set_debuglevel(debug)
    assert xml is None or syms is not None
    if syms is not None:
        SymbolInfo.open(syms)
    assert loadleaksglob(picklefile)
    leaks = collapse_cfleaks(leaks, True, 1, "")
    if xml is not None:
        print_leaks(leaks, XmlLeakPrinter(xml), True)
    if leakout is not None:
        print_leaks(leaks, BinLeakPrinter(leakout))


"""
Export results and framework files (ELF, sources) in a compressed zip file.
"""


@cli.command("export")
@click.argument("picklefile", type=str)
@click.argument("zipfile", type=str)
@click.option("--syms", default=None, type=click.File("r"))
@click.option("--debug", default=-1, type=int)
def export(picklefile, zipfile, syms, debug):
    global leaks
    set_debuglevel(debug)
    assert syms is not None
    if syms:
        SymbolInfo.open(syms)
    assert loadleaksglob(picklefile)
    export_leaks(leaks, zipfile, syms)


"""
Analyze two trace files and extract all differences.
"""


@cli.command("diff")
@click.argument("file1", type=click.File("rb"))
@click.argument("file2", type=click.File("rb"))
@click.option("--syms", default=None, type=click.File("r"))
@click.option("--pickle", default=None, type=str)
@click.option("--xml", default=None, type=click.File("w"))
@click.option("--fast", default=True, type=bool)
@click.option("--debug", default=-1, type=int)
def diff(file1, file2, syms, pickle, xml, fast, debug):
    global printer
    set_debuglevel(debug)
    assert xml is None or syms is not None
    if syms:
        SymbolInfo.open(syms)
    if pickle is not None:
        loadleaksglob(pickle)
    iterate_queue([file1, file2], fast)
    if pickle is not None:
        storepickle(pickle, leaks)
    if xml is not None:
        print_leaks(leaks, XmlLeakPrinter(xml), True)


"""
Generic leakage tests.
"""


@cli.command("generic")
@click.argument("fixedpickle", type=str)
@click.argument("randompickle", type=str)
@click.option("--pickle", default=None, type=str)  # output pickle
@click.option("--syms", default=None, type=click.File("r"))
@click.option("--xml", default=None, type=click.File("w"))
@click.option("--debug", default=-1, type=int)
def generic(fixedpickle, randompickle, pickle, syms, xml, debug):
    global printer
    global leaks
    set_debuglevel(debug)
    assert xml is None or syms is not None
    if syms:
        SymbolInfo.open(syms)
    fixed = loadpickle(fixedpickle)
    random = loadpickle(randompickle)
    generic_leakage_test(fixed, random)
    leaks = fixed
    if pickle is not None:
        storepickle(pickle, leaks)
    if xml is not None:
        print_leaks(leaks, XmlLeakPrinter(xml), True)


"""
Specific leakage tests.
"""


@cli.command("specific")
@click.argument("randompickle", type=str)
@click.argument("callback", type=str)
@click.argument("keydir", type=str)
@click.option("--pickle", default=None, type=str)  # output pickle
@click.option("--syms", default=None, type=click.File("r"))
@click.option("--xml", default=None, type=click.File("w"))
@click.option("--debug", default=-1, type=int)
@click.option("--leaksonly", default=True, type=bool)
@click.option("--multiprocessing", default=True, type=bool)
def specific(
    randompickle, callback, keydir, pickle, syms, xml, debug, leaksonly, multiprocessing
):
    global printer
    global leaks
    set_debuglevel(debug)
    if syms:
        SymbolInfo.open(syms)
    keys = loadkeys(keydir)
    leaks = loadpickle(randompickle)
    specific_leakage_test(leaks, callback, keys, leaksonly, multiprocessing)
    if pickle is not None:
        storepickle(pickle, leaks)
    if xml is not None:
        print_leaks(leaks, XmlLeakPrinter(xml), True)


"""
Get Statistics (from phase 3)
"""


@cli.command("statistics")
@click.argument("pickle_file", type=str)
@click.option("--debug", default=-1, type=int)
def statistics(pickle_file, debug):
    global leaks
    set_debuglevel(debug)

    loadleaksglob(pickle_file)

    class Stats(object):
        def __init__(self, call_hierarchy):
            self.allleaks = list()
            self.normalized_per_leakage_model = defaultdict(list)
            self.all_normalized_spleaks = list()

            self.get_leaks(call_hierarchy)

            # get leakage per leakage model:
            for leak in self.allleaks:
                assert isinstance(leak, Leak)
                max_leakage = 0
                # Remove M_pos NSPType.Type3, as it does not work properly
                # for l in (x for x in leak.status.spleak if x.isleak and x.sptype != NSPType.Type3):
                for leak in (x for x in leak.status.spleak if x.isleak):
                    key = (leak.target, leak.property)
                    leakage = leak.normalized()
                    self.normalized_per_leakage_model[key].append(leakage)
                    max_leakage = max(max_leakage, leakage)
                # get max leakage per leak (if a spleak exists with >= 0 leakage)
                if max_leakage:
                    self.all_normalized_spleaks.append(max_leakage)

        def get_leaks(self, call_hierarchy):
            self.allleaks.extend(call_hierarchy.dataleaks)
            self.allleaks.extend(call_hierarchy.cfleaks)
            for k in sorted_keys(call_hierarchy.children):
                self.get_leaks(call_hierarchy.children[k])

        def get_max_per_key(self, key):
            if key not in self.normalized_per_leakage_model:
                return 0
            return round(max(self.normalized_per_leakage_model[key]), 3) * 100

    # import pdb; pdb.set_trace()

    stats = Stats(leaks)

    # Print stats
    print("Phase 1 total: {}".format(len(stats.allleaks)))
    print("Phase 3 total: {}".format(len(stats.all_normalized_spleaks)))
    print("Phase3: Max leakage per leakage model:")
    for key in sorted(stats.normalized_per_leakage_model):
        print("    {:35}  {:6.2f}%".format(str(key), stats.get_max_per_key(key)))

    no_spleaks = len(stats.allleaks) - len(stats.all_normalized_spleaks)
    # Note: using round, because we consider 0.999 as 1
    exactly_100 = sum(round(x, 2) >= 1.00 for x in stats.all_normalized_spleaks)
    less_than_100 = (
        sum(round(x, 2) < 1.00 for x in stats.all_normalized_spleaks) + no_spleaks
    )
    less_than_50 = (
        sum(round(x, 2) < 0.50 for x in stats.all_normalized_spleaks) + no_spleaks
    )
    less_than_1 = (
        sum(round(x, 2) < 0.01 for x in stats.all_normalized_spleaks) + no_spleaks
    )
    exactly_100_relative = exactly_100 * 100 / len(stats.allleaks)
    less_than_100_relative = less_than_100 * 100 / len(stats.allleaks)
    less_than_50_relative = less_than_50 * 100 / len(stats.allleaks)
    less_than_1_relative = less_than_1 * 100 / len(stats.allleaks)
    print(
        "{:25} {:5} {:6.2f}%".format("exactly_100", exactly_100, exactly_100_relative)
    )
    print(
        "{:25} {:5} {:6.2f}%".format(
            "less_than_100", less_than_100, less_than_100_relative
        )
    )
    print(
        "{:25} {:5} {:6.2f}%".format(
            "less_than_50", less_than_50, less_than_50_relative
        )
    )
    print(
        "{:25} {:5} {:6.2f}%".format("less_than_1", less_than_1, less_than_1_relative)
    )

    print("LaTeX Table line: ")
    print(
        r"{} & {:3.1f}\% & {:3.1f}\% & {:3.1f}\% & {:3.1f}\% & {:3.1f}\% & {:3.1f}\% & {:3.1f}\% & {:3.1f}\% & {:3.1f}\% & {:3.1f}\% & {:3.1f}\%".format(
            len(stats.allleaks),
            stats.get_max_per_key(("dsa_nonce", "bits(k)")),
            stats.get_max_per_key(("dsa_nonce", "bits(k+q)")),
            stats.get_max_per_key(("dsa_nonce", "bits(k+2q)")),
            stats.get_max_per_key(("dsa_nonce", "bits(kinv)")),
            stats.get_max_per_key(("dsa_nonce", "hw(k)")),
            stats.get_max_per_key(("dsa_nonce", "hw(k+q)")),
            stats.get_max_per_key(("dsa_nonce", "hw(k+2q)")),
            stats.get_max_per_key(("dsa_nonce", "hw(kinv)")),
            less_than_1_relative,
            less_than_50_relative,
            less_than_100_relative,
        )
    )


"""
Strip evidences
"""


@cli.command("strip")
@click.argument("pickle", type=str)
@click.option("--syms", default=None, type=click.File("r"))
@click.option("--xml", default=None, type=click.File("w"))
@click.option("--debug", default=-1, type=int)
def strip(pickle, syms, xml, debug):
    global printer
    global leaks
    set_debuglevel(debug)
    assert xml is None or syms is not None
    if syms:
        SymbolInfo.open(syms)
    leaks = loadpickle(pickle)
    datastub.utils.debug(1, "Stripping evidences")
    strip_evidences(leaks)
    if pickle is not None:
        storepickle(pickle, leaks)
    if xml is not None:
        print_leaks(leaks, XmlLeakPrinter(xml), True)


"""
Precompute multiple RDC limits for given alpha
"""


@cli.command("precompute_rdc")
@click.option("--file", default="precompute_rdc.txt", type=str)
@click.option("--alpha", default=0.9999, type=float)
@click.option("--debug", default=-1, type=int)
def precompute_rdc(file, alpha, debug):
    set_debuglevel(debug)
    precompute_rdc_parallel(file, alpha)


"""
Get single RDC limit for given alpha
"""


@cli.command("get_rdc")
@click.argument("val", type=int)
@click.option("--alpha", default=0.9999, type=float)
@click.option("--debug", default=-1, type=int)
def get_rdc(val, alpha, debug):
    set_debuglevel(debug)
    get_rdc_single(val, alpha)


if __name__ == "__main__":
    cli()
