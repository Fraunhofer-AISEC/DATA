/************************************************************************
 * Copyright (C) 2017-2018 IAIK TU Graz and Fraunhofer AISEC
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 ***********************************************************************/

/**
 * @file addrtrace.cpp
 * @brief DATA tracing tool for Pin.
 * @license This project is released under the GNU GPLv3+ License.
 * @author See AUTHORS file.
 * @version 0.3
 */

/***********************************************************************/

#include "call-stack.H"
#include "pin-macros.H"
#include "pin.H"
#include "sha1.H"
#include "utils.H"
#include <fcntl.h>
#include <fstream>
#include <getopt.h>
#include <inttypes.h>
#include <iostream>
#include <map>
#include <set>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

using namespace std;

int DEBUG_LEVEL;
int SYSCALL_NUMBER = -1;

/***********************************************************************/

VOID RecordFunctionEntry(THREADID threadid, ADDRINT bbl, ADDRINT bp,
                         BOOL indirect, ADDRINT target, bool report_as_cfleak);
VOID RecordFunctionExit(THREADID threadid, ADDRINT bbl, ADDRINT bp,
                        const CONTEXT *ctxt, bool report_as_cfleak);

/***********************************************************************/

KNOB<string> KnobRawFile(KNOB_MODE_WRITEONCE, "pintool", "raw", "",
                         "Raw output file.");

KNOB<bool> KnobFunc(KNOB_MODE_WRITEONCE, "pintool", "func", "0",
                    "Trace function calls and returns.");

KNOB<bool> KnobBbl(KNOB_MODE_WRITEONCE, "pintool", "bbl", "0",
                   "Trace basic blocks.");

KNOB<bool> KnobMem(KNOB_MODE_WRITEONCE, "pintool", "mem", "0",
                   "Trace data memory accesses.");

KNOB<bool> KnobTrackHeap(KNOB_MODE_WRITEONCE, "pintool", "heap", "0",
                         "Track heap usage (malloc, free).");

KNOB<string> KnobSyms(KNOB_MODE_WRITEONCE, "pintool", "syms", "",
                      "Output file for image information.");

KNOB<string> KnobVDSO(KNOB_MODE_WRITEONCE, "pintool", "vdso", "vdso.so",
                      "Output file for the vdso shared library.");

KNOB<bool> KnobLeaks(KNOB_MODE_WRITEONCE, "pintool", "leaks", "0",
                     "Enable fast recording of leaks, provided via leakin.");

KNOB<string>
    KnobLeakIn(KNOB_MODE_WRITEONCE, "pintool", "leakin", "",
               "Binary input file containing all leaks to trace."
               "If empty, all selected instructions are traced. "
               "In any case specify -func, -bbl, -mem -heap accordingly!"
               "This means that instructions in the -bin file are only traced,"
               "if also the corresponding flag (e.g. -mem, -bbl) is set");

KNOB<string> KnobLeakOut(
    KNOB_MODE_WRITEONCE, "pintool", "leakout", "",
    "Hierarchical output file of all leaks. Only useful with -bin option.");

KNOB<bool>
    KnobCallstack(KNOB_MODE_WRITEONCE, "pintool", "cs", "0",
                  "Take callstack into account and trace leaks only in the "
                  "correct calling context. Only useful with -bin option.");

KNOB<string> KnobMain(KNOB_MODE_WRITEONCE, "pintool", "main", "main",
                      "Main method to start tracing. Defaults to 'main'. "
                      "Provide ALL to trace from the beginning.");

KNOB<bool> KnobStopTrace(KNOB_MODE_WRITEONCE, "pintool", "stop_trace", "1",
                         "Stop tracing within memory allocations");

KNOB<int> KnobDebug(KNOB_MODE_WRITEONCE, "pintool", "debug", "0",
                    "Enable debugging output.");

/***********************************************************************/
/** Recording                                                          */
/***********************************************************************/

// TODO: instrument strdup

#define MALLOC "malloc"
#define REALLOC "realloc"
#define CALLOC "calloc"
#define MMAP "mmap"
#define MREMAP "mremap"
#define MUNMAP "munmap"
#define FREE "free"
#define BRK "brk"

int alloc_instrumented = 0;

/* When using '-main ALL', ensures recording starts at function call */
bool WaitForFirstFunction = false;
bool Record = false;
bool use_callstack = false;

/* Stop tracing within memory allocations */
bool StopTrace = true;
bool Trace = true;

/**
 * Traces are stored in a binary format, containing a sequence of
 * entry_t entries.
 */
typedef struct __attribute__((packed)) {
    uint8_t type;  /* holds values of entry_type_t */
    uint64_t ip;   /* instruction pointer */
    uint64_t data; /* additional data, depending on type */
} entry_t;

/**
 * Entry types.
 */
enum entry_type_t {
    /* Dummy types */
    A = 0,
    B = 1,
    C = 2,
    D = 3,

    MASK_NONE = 0,
    /* Instructions doing memory reads/writes */
    READ = MASK_NONE | A,
    WRITE = MASK_NONE | B,

    MASK_BRANCH = 4,
    /* Branching instructions */
    BRANCH = MASK_BRANCH | A,
    FUNC_ENTRY = MASK_BRANCH | B,
    FUNC_EXIT = MASK_BRANCH | C,
    FUNC_BBL = MASK_BRANCH | D,

    MASK_LEAK = 16,
    /* Dataleaks and Controlflow leaks, used for fast recording */
    DLEAK = MASK_LEAK | A,
    CFLEAK = MASK_LEAK | B,
};

std::vector<entry_t> trace; /* Contains all traced instructions */
ofstream imgfile;           /* Holds memory layout with function symbols */
ofstream vdsofile;          /* Holds vdso shared library */

/***********************************************************************/
/* Image tracking*/
typedef struct {
    string name;
    uint64_t baseaddr;
    uint64_t endaddr;
} imgobj_t;

typedef std::vector<imgobj_t> IMGVEC;
IMGVEC imgvec;

/***********************************************************************/
/* Heap tracking */

typedef struct {
    char const *type;
    size_t size;
    uint64_t base;
    string callstack;
    string hash;
} memobj_t;

typedef std::vector<memobj_t> HEAPVEC;
HEAPVEC heap;

std::unordered_map<std::string, uint64_t> hashmap;
std::unordered_map<uint64_t, uint64_t> allocmap;

imgobj_t heaprange;

/***********************************************************************/
/* Brk tracking*/
typedef struct {
    imgobj_t image;
    ADDRINT low;
    ADDRINT high;
} program_break_obj_t;

typedef std::vector<program_break_obj_t> BRKVEC;
BRKVEC brk_vec;
imgobj_t brk_range;

/***********************************************************************/
/* Stack tracking*/
imgobj_t stack;

/***********************************************************************/
/* Multithreading */

/* Global lock to protect trace buffer */
// PIN_MUTEX lock;

/***********************************************************************/
/* Allocation tracking */

typedef struct {
    char const *type;
    ADDRINT size;
    std::string callstack;
} alloc_state_t;

typedef struct {
    char const *type;
    ADDRINT old;
    ADDRINT size;
    std::string callstack;
} realloc_state_t;

typedef struct {
    /* allocation routines sometimes call themselves in a nested way during
     * initialization */
    std::vector<alloc_state_t> malloc_state;
    std::vector<alloc_state_t> calloc_state;
    std::vector<realloc_state_t> realloc_state;
    std::vector<alloc_state_t> mmap_state;
    std::vector<realloc_state_t> mremap_state;
    ADDRINT RetIP;
    int newbbl;
} thread_state_t;

std::vector<thread_state_t> thread_state;

/***********************************************************************
 * FAST RECORDING
 *
 * In contrast to normal recording, fast recording only traces those
 * instructions which were identified as leaks. The leaks to trace are
 * provided via a binary file via -leakin. This file can be created via
 * analyze.py --leakout.
 *
 * The -leakin binary format is as follows:
 *     1B        8B        1B    len * 8B
 *   [Type]     [ip]      [len] [val1, val2, ...]
 *
 * Type is one of FUNC_ENTRY, FUNC_EXIT, DLEAK, CFLEAK. Each type is
 * followed by the instruction and the length of subsequent optional
 * values.
 *
 *   FUNC_ENTRY ip-caller  1     ip-callee
 *   FUNC_EXIT  0          0
 *   DLEAK      ip         0
 *   CFLEAK     ip         n     mergepoint 1 ... mergepoint n
 *
 * Fast recording results are exported to the file, specified via
 * pintool argument -leakout. The binary format is as follows:
 *
 *   DLEAK      (1B) IP        (8B) len [evidence] (len*8B)
 *   CFEAK      (1B) IP        (8B) len [evidence] (len*8B)
 *   FUNC_ENTRY (1B) IP-Caller (8B) IP-Callee (8B)
 *   FUNC_EXIT  (1B)
 *
 * FUNC_ENTRY and FUNC_EXIT are only written if flag '-cs' is provided.
 ***********************************************************************/

/***********************************************************************/
/** Leaks, CallStack, Contexts                                         */
/***********************************************************************/

/**
 * Collect evidence for a specific data leak
 */
class DataLeak {
  private:
    std::vector<uint64_t> data; /* Holds evidences */
    uint64_t ip;                /* The leaking instruction */

  public:
    DataLeak(uint64_t ip = 0) : ip(ip) {}

    /**
     * Add evidence
     * @param d The evidence to add
     */
    void append(uint64_t d) {
        ASSERT(ip, "[pintool] Error: IP not set");
        DEBUG(1)
        printf("[pintool] DLEAK@%" PRIx64 ": %" PRIx64 " appended\n", ip, d);
        data.push_back(d);
    }

    void print() {
        for (std::vector<uint64_t>::iterator it = data.begin();
             it != data.end(); it++) {
            printf("         %" PRIx64 " ", *it);
        }
        printf("\n");
    }

    /**
     * Export evidence to binary format
     * @param f The file to export to
     */
    void doexport(FILE *f) {
        uint8_t type = DLEAK;
        uint64_t len = data.size();
        uint8_t res = 0;
        res += fwrite(&type, sizeof(type), 1, f) != 1;
        res += fwrite(&ip, sizeof(ip), 1, f) != 1;
        res += fwrite(&len, sizeof(len), 1, f) != 1;
        res += fwrite(&data[0], sizeof(uint64_t), len, f) != len;
        ASSERT(!res, "[pintool] Error: Unable to write file");
    }
};

/**
 * Collect evidence for a specific control-flow leak
 */
class CFLeak {
  private:
    std::vector<uint64_t> targets;     /* Holds evidences */
    std::vector<uint64_t> mergepoints; /* unused */
    uint64_t bp;                       /* The leaking instruction */

  public:
    CFLeak(uint64_t bp = 0) : bp(bp) {}

    /**
     * Add evidence
     * @param ip The evidence to add
     */
    void append(uint64_t ip) {
        ASSERT(bp, "[pintool] Error: BP not set");
        DEBUG(1)
        printf("[pintool] CFLEAK@%" PRIx64 ": %" PRIx64 " appended\n", bp, ip);
        targets.push_back(ip);
    }

    void print() {
        for (std::vector<uint64_t>::iterator it = targets.begin();
             it != targets.end(); it++) {
            printf("         %" PRIx64 " ", *it);
        }
        printf("\n");
    }

    /**
     * Export evidence to binary format
     * @param f The file to export to
     */
    void doexport(FILE *f) {
        uint8_t type = CFLEAK;
        uint64_t len = targets.size();
        uint8_t res = 0;
        res += fwrite(&type, sizeof(type), 1, f) != 1;
        res += fwrite(&bp, sizeof(bp), 1, f) != 1;
        res += fwrite(&len, sizeof(len), 1, f) != 1;
        res += fwrite(&targets[0], sizeof(uint64_t), len, f) != len;
        ASSERT(!res, "[pintool] Error: Unable to write file");
    }
};

typedef std::map<uint64_t, DataLeak> dleaks_t;
typedef std::map<uint64_t, CFLeak> cfleaks_t;

/**
 * Holds a single context of the call hierarchy,
 * holding leaks which shall be recorded at precisely this context.
 */
class Context {
  private:
    dleaks_t dleaks;
    cfleaks_t cfleaks;

  public:
    Context() {}

    /**
     * Add a new dataleak to trace during execution
     * @param ip The instruction to trace
     */
    virtual void dleak_create(uint64_t ip) {
        if (dleaks.find(ip) == dleaks.end()) {
            dleaks.insert(std::pair<uint64_t, DataLeak>(ip, DataLeak(ip)));
        } else {
            DEBUG(1)
            printf("[pintool] Warning: DLEAK: %" PRIx64 " not created\n", ip);
        }
    }

    /**
     * Add a new cfleak to trace during execution
     * @param ip The instruction to trace (branch point)
     * @param mp The merge point (unused)
     * @param len The length of the branch (branch point-> merge point) (unused)
     */
    virtual void cfleak_create(uint64_t ip, uint64_t *mp, uint8_t len) {
        if (cfleaks.find(ip) == cfleaks.end()) {
            cfleaks.insert(std::pair<uint64_t, CFLeak>(ip, CFLeak(ip)));
        } else {
            DEBUG(1)
            printf("[pintool] Warning: CFLEAK: %" PRIx64 " not created\n", ip);
        }
    }

    /**
     * Record evidence for a data leak
     * @param ip The leaking instruction
     * @param data The accessed memory (the evidence).
     *             We do not (need to) distinguish between read and write here.
     */
    virtual void dleak_append(uint64_t ip, uint64_t data) {
        if (dleaks.find(ip) == dleaks.end()) {
            DEBUG(1)
            printf("[pintool] Warning: DLEAK: %" PRIx64 " not appended\n", ip);
        } else {
            dleaks[ip].append(data);
        }
    }

    /**
     * Record evidence for a control-flow leak
     * @param bbl The basic block which contains the cf-leak
     * @param target The taken branch target (the evidence)
     */
    virtual void cfleak_append(uint64_t bbl, uint64_t target) {
        if (cfleaks.find(bbl) == cfleaks.end()) {
            DEBUG(1)
            printf("[pintool] Warning: CFLEAK: %" PRIx64 " not appended\n",
                   bbl);
        } else {
            cfleaks[bbl].append(target);
        }
    }

    virtual void print() {
        for (dleaks_t::iterator it = dleaks.begin(); it != dleaks.end(); it++) {
            printf("[pintool]  DLEAK %" PRIx64 ": ", it->first);
            it->second.print();
        }
        for (cfleaks_t::iterator it = cfleaks.begin(); it != cfleaks.end();
             it++) {
            printf("[pintool]  CFLEAK %" PRIx64 ": ", it->first);
            it->second.print();
        }
    }

    /**
     * Export evidence to binary format
     * @param f The file to export to
     */
    virtual void doexport(FILE *f) {
        for (dleaks_t::iterator it = dleaks.begin(); it != dleaks.end(); it++) {
            it->second.doexport(f);
        }
        for (cfleaks_t::iterator it = cfleaks.begin(); it != cfleaks.end();
             it++) {
            it->second.doexport(f);
        }
    }
};

class CallContext;
class CallStack;
typedef std::map<uint64_t, CallContext *> children_t;

/**
 * Wraps class Context for use in class CallStack
 */
class CallContext : public Context {
    friend class CallStack;

  private:
    uint64_t caller;
    uint64_t callee;
    CallContext *parent;
    children_t children;
    int unknown_child_depth;
    bool used;

  public:
    CallContext(uint64_t caller = 0, uint64_t callee = 0)
        : Context(), caller(caller), callee(callee), parent(NULL),
          unknown_child_depth(0), used(false) {}

    virtual void dleak_append(uint64_t ip, uint64_t data) {
        if (used == false || unknown_child_depth) {
            DEBUG(1)
            printf("[pintool] Warning: DLEAK %" PRIx64
                   ": skipping due to %d %d\n",
                   ip, used, unknown_child_depth);
        } else {
            Context::dleak_append(ip, data);
        }
    }

    virtual void cfleak_append(uint64_t bbl, uint64_t target) {
        if (used == false || unknown_child_depth) {
            DEBUG(1)
            printf("[pintool] Warning: CFLEAK %" PRIx64
                   ": skipping due to %d %d\n",
                   bbl, used, unknown_child_depth);
        } else {
            Context::cfleak_append(bbl, target);
        }
    }

    virtual void print(Context *currentContext = NULL) {
        if (this == currentContext) {
            printf("*");
        }
        printf("%" PRIx64 "-->%" PRIx64 " (%d)(%d)\n", this->caller,
               this->callee, this->unknown_child_depth, this->used);
        Context::print();
        for (children_t::iterator it = children.begin(); it != children.end();
             it++) {
            it->second->print(currentContext);
        }
        printf("<\n");
    }

    /**
     * Export evidence to binary format
     * @param f The file to export to
     */
    virtual void doexport(FILE *f) {
        uint8_t type = FUNC_ENTRY;
        uint8_t res = 0;
        res += fwrite(&type, sizeof(type), 1, f) != 1;
        res += fwrite(&caller, sizeof(caller), 1, f) != 1;
        res += fwrite(&callee, sizeof(callee), 1, f) != 1;
        ASSERT(!res, "[pintool] Error: Unable to write file");
        Context::doexport(f);
        for (children_t::iterator it = children.begin(); it != children.end();
             it++) {
            it->second->doexport(f);
        }
        type = FUNC_EXIT;
        res = fwrite(&type, sizeof(type), 1, f) != 1;
        ASSERT(!res, "[pintool] Error: Unable to write file");
    }
};

/**
 * Container for managing fast-recording
 */
class AbstractLeakContainer {
  protected:
    std::set<uint64_t>
        traced_dataleaks; /* List of data leaks which shall be instrumented */
    std::set<uint64_t> traced_cfleaks; /* List of control-flow leaks which shall
                                          be instrumented */
    std::set<uint64_t> erased_dataleaks; /* List of data leaks which are already
                                            instrumented */
    std::set<uint64_t> erased_cfleaks;   /* List of control-flow leaks which are
                                            already instrumented */
    Context *currentContext;

  public:
    size_t get_uninstrumented_dleak_size() { return traced_dataleaks.size(); }

    size_t get_uninstrumented_cfleak_size() { return traced_cfleaks.size(); }

    /**
     * Checks whether an instruction shall be instrumented and if yes,
     * removes it from the list of uninstrumented instructions.
     * @param ip The instruction to test
     * @return a value != 0 if successful
     */
    size_t get_erase_dleak(uint64_t ip) {
        size_t er = traced_dataleaks.erase(ip);
        if (er) {
            erased_dataleaks.insert(ip);
        }
        return er;
    }

    /**
     * Returns whether an instruction was previously
     * instrumented and, thus, erased.
     */
    bool was_erased_dleak(uint64_t ip) { return erased_dataleaks.count(ip); }

    /**
     * Checks whether an instruction shall be instrumented and if yes,
     * removes it from the list of uninstrumented instructions.
     * @param ip The instruction to test
     * @return a value != 0 if successful
     */
    size_t get_erase_cfleak(uint64_t ip) {
        size_t er = traced_cfleaks.erase(ip);
        if (er) {
            erased_cfleaks.insert(ip);
        }
        return er;
    }

    /**
     * Returns whether an instruction was previously
     * instrumented and, thus, erased.
     */
    bool was_erased_cfleak(uint64_t ip) { return erased_cfleaks.count(ip); }

    void print_uninstrumented_leaks() {
        if (traced_dataleaks.size() > 0) {
            printf("[pintool] Uninstrumented DLEAKS:\n");
            for (std::set<uint64_t>::iterator it = traced_dataleaks.begin();
                 it != traced_dataleaks.end(); it++) {
                printf(" %" PRIx64 "\n", *it);
            }
        }
        if (traced_cfleaks.size() > 0) {
            printf("[pintool] Uninstrumented CFLEAKS:\n");
            for (std::set<uint64_t>::iterator it = traced_cfleaks.begin();
                 it != traced_cfleaks.end(); it++) {
                printf(" %" PRIx64 "\n", *it);
            }
        }
    }

    /**
     * Can be used to build a call stack. Is called for every function
     * call in the leakage file
     * @param caller The caller
     * @param callee The callee
     */
    virtual void call_create(uint64_t caller, uint64_t callee) = 0;

    /**
     * Can be used to build a call stack. Is called for every function
     * return in the leakage file
     * @param ip The return instruction
     */
    virtual void ret_create(uint64_t ip) = 0;

    /**
     * Can be used to traverse the call stack during recording.
     * Is called for every function call during recording.
     * @param caller The caller
     * @param callee The callee
     */
    virtual void call_consume(uint64_t caller, uint64_t callee) = 0;

    /**
     * Can be used to traverse the call stack during recording.
     * Is called for every function return during recording.
     * @param ip The return instruction
     */
    virtual void ret_consume(uint64_t ip) = 0;

    /**
     * Add a new dataleak to trace during execution
     * @param ip The instruction to trace
     */
    virtual void dleak_create(uint64_t ip) {
        ASSERT(currentContext, "[pintool] Error: Context not initialized");
        traced_dataleaks.insert(ip);
        currentContext->dleak_create(ip);
    }

    /**
     * Add a new cfleak to trace during execution
     * @param ip The instruction to trace (branch point)
     * @param mp The merge point (unused)
     * @param len The length of the branch (branch point-> merge point) (unused)
     */
    virtual void cfleak_create(uint64_t bp, uint64_t *mp, uint8_t len) {
        ASSERT(currentContext, "[pintool] Error: Context not initialized");
        traced_cfleaks.insert(bp);
        currentContext->cfleak_create(bp, mp, len);
    }

    /**
     * Record evidence for a data leak
     * @param ip The leaking instruction
     * @param data The accessed memory (the evidence).
     *             We do not (need to) distinguish between read and write here.
     */
    virtual void dleak_consume(uint64_t ip, uint64_t data) {
        ASSERT(currentContext, "[pintool] Error: Context not initialized");
        DEBUG(1) printf("[pintool] Consuming DLEAK %" PRIx64 "\n", ip);
        currentContext->dleak_append(ip, data);
    }

    /**
     * Record evidence for a control-flow leak
     * @param bbl The basic block which contains the cf-leak
     * @param target The taken branch target (the evidence)
     */
    virtual void cfleak_consume(uint64_t bbl, uint64_t target) {
        ASSERT(currentContext, "[pintool] Error: Context not initialized");
        DEBUG(1) printf("[pintool] Consuming CFLEAK %" PRIx64 "\n", bbl);
        currentContext->cfleak_append(bbl, target);
    }

    virtual void print_all() = 0;

    /**
     * Export evidence to binary format
     * @param f The file to export to
     */
    virtual void doexport(FILE *f) {
        ASSERT(currentContext, "[pintool] Error: Context not initialized");
        currentContext->doexport(f);
    }
};

/**
 * This class is used to report leaks.
 * It does not keep track of the actual calling context.
 * It is used to trace leaking instructions at any calling context.
 */
class Flat : public AbstractLeakContainer {

  public:
    Flat() { currentContext = new Context(); }

    virtual void call_create(uint64_t caller, uint64_t callee) {}

    virtual void ret_create(uint64_t ip) {}

    virtual void call_consume(uint64_t caller, uint64_t callee) {}

    virtual void ret_consume(uint64_t ip) {}

    virtual void print_all() { currentContext->print(); }
};

/**
 * This class is used to report leaks at certain instructions only.
 * It keeps track of the call-stack. It is used to trace leaking
 * instructions only in the calling context where the leakage
 * occured.
 *
 * To initially build the callstack, sequentially traverse the leakage
 * bin-file and use call_create and ret_consume as well as dleak_create
 * and cfleak_create.
 *
 * During binary instrumentation, use call_consume and ret_consume to
 * move to the current calling context. Then, use isdleaking and
 * iscfleaking to determine whether the current instruction shall be
 * traced or not.
 */
class CallStack : public AbstractLeakContainer {

  protected:
    /* Generate a hash of caller and callee by swapping callee's DWORDS and
     * XORING both. */
    uint64_t get_call_id(uint64_t caller, uint64_t callee) {
        uint64_t id = caller;
        uint32_t lower = callee & 0x00000000FFFFFFFFULL;
        uint32_t upper = callee >> 32ULL;
        id ^= upper | ((uint64_t)lower << 32ULL);
        return id;
    }

  public:
    CallStack() {}

    void call_create(uint64_t caller, uint64_t callee) {
        ASSERT(use_callstack, "[pintool] Error: Wrong usage of callstack");
        DEBUG(2)
        printf("[pintool] Building callstack %" PRIx64 " --> %" PRIx64 "\n",
               caller, callee);
        uint64_t id = get_call_id(caller, callee);
        if (currentContext == NULL) {
            currentContext = new CallContext(caller, callee);
        } else {
            CallContext *top = static_cast<CallContext *>(currentContext);
            if (top->children.find(id) == top->children.end()) {
                CallContext *newcs = new CallContext(caller, callee);
                newcs->used = true;
                newcs->parent = top;
                top->children[id] = newcs;
            }
            CallContext *move = top->children[id];
            currentContext = top = move;
        }
    }

    void call_consume(uint64_t caller, uint64_t callee) {
        ASSERT(use_callstack, "[pintool] Error: Wrong usage of callstack");
        ASSERT(currentContext, "[pintool] Error: Callstack is not initialized");
        DEBUG(3) print_all();
        DEBUG(2)
        printf("[pintool] Calling %" PRIx64 " --> %" PRIx64 "\n", caller,
               callee);
        uint64_t id = get_call_id(caller, callee);
        CallContext *top = static_cast<CallContext *>(currentContext);
        if (!top->used) {
            if (top->caller == caller && top->callee == callee) {
                DEBUG(2) printf("[pintool] Entered first leaking callstack\n");
                top->used = true;
            }
        } else {
            if (top->unknown_child_depth ||
                top->children.find(id) == top->children.end()) {
                top->unknown_child_depth++;
            } else {
                CallContext *move = top->children[id];
                currentContext = top = move;
            }
        }
        DEBUG(3) print_all();
    }

    void ret_consume(uint64_t ip) {
        ASSERT(use_callstack, "[pintool] Error: Wrong usage of callstack");
        ASSERT(currentContext, "[pintool] Error: Callstack is not initialized");
        DEBUG(2) printf("[pintool] Returning %" PRIx64 "\n", ip);
        CallContext *top = static_cast<CallContext *>(currentContext);
        if (top->unknown_child_depth) {
            top->unknown_child_depth--;
        } else {
            if (top->parent) {
                ASSERT(top->parent,
                       "[pintool] Error: Callstack parent is empty");
                currentContext = top = top->parent;
            } else {
                DEBUG(2) printf("[pintool] Warning: Ignoring return\n");
            }
        }
    }

    void ret_create(uint64_t ip) { ret_consume(ip); }

    bool empty() {
        ASSERT(use_callstack, "[pintool] Error: Wrong usage of callstack");
        CallContext *top = static_cast<CallContext *>(currentContext);
        return top == NULL || top->used == false;
    }

    CallContext *get_begin() {
        ASSERT(use_callstack, "[pintool] Error: Wrong usage of callstack");
        CallContext *c = static_cast<CallContext *>(currentContext);
        while (c && c->parent) {
            c = c->parent;
        }
        return c;
    }

    /**
     * After loading leakage file, use this function to rewind to the
     * initial context
     */
    void rewind() {
        ASSERT(use_callstack, "[pintool] Error: Wrong usage of callstack");
        CallContext *top = get_begin();
        ASSERT(top, "[pintool] Error: Leaks not initialized");
        top->used = false;
        currentContext = top;
    }

    void print_all() {
        ASSERT(use_callstack, "[pintool] Error: Wrong usage of callstack");
        CallContext *top = get_begin();
        if (top) {
            printf("[pintool] Callstack:\n");
            top->print(currentContext);
        }
    }
};

AbstractLeakContainer *leaks = NULL;

/***********************************************************************/
/** Thread/Main recording and initialization                           */
/***********************************************************************/

void init() {
    // ASSERT(PIN_MutexInit(&lock), "[pintool] Error: Mutex init failed");
}

/**
 * Add an entry to the trace
 * This function is not thread-safe. Lock first.
 */
VOID record_entry(entry_t entry) { trace.push_back(entry); }

/**
 * Start recording.
 * @param threadid The thread
 * @param ins The first recorded instruction
 */
VOID RecordMainBegin(THREADID threadid, ADDRINT ins) {
    Record = true;
    DEBUG(1) printf("[pintool] Start main() %lx\n", (long unsigned int)ins);
    RecordFunctionEntry(threadid, 0, 0, false, ins, false);
}

/**
 * Stop recording.
 * @param threadid The thread
 * @param ins The last recorded instruction
 */
VOID RecordMainEnd(THREADID threadid, ADDRINT ins) {
    Record = false;
    DEBUG(1) printf("[pintool] End main()\n");
    RecordFunctionExit(threadid, ins, ins, NULL, false);
}

/**
 * Track thread creation.
 * Creates a separate recording context per thread.
 * Note: currently all threads report to the same trace
 * @param threadid The thread
 * @param ctxt Unused
 * @param flags Unused
 * @param v Unused
 */
VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v) {
    ASSERT(threadid == 0,
           "[pintool] Error: Multithreading detected but not supported!");
    DEBUG(1) printf("[pintool] Thread begin %d\n", threadid);
    // PIN_MutexLock(&lock);
    if (thread_state.size() <= threadid) {
        thread_state_t newstate;
        newstate.RetIP = 0;
        newstate.newbbl = 0;
        thread_state.push_back(newstate);
    } else {
        thread_state[threadid].RetIP = 0;
        thread_state[threadid].newbbl = 0;
    }
    ASSERT(thread_state.size() > threadid,
           "[pintool] Error: thread_state corrupted");
    // PIN_MutexUnlock(&lock);
}

/**
 * Track thread destruction.
 * @param threadid The thread
 * @param ctxt Unused
 * @param code Unused
 * @param v Unused
 */
VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v) {
    // PIN_MutexLock(&lock);
    DEBUG(1) printf("[pintool] Thread end %d code %d\n", threadid, code);
    // PIN_MutexUnlock(&lock);
}

/***********************************************************************/
/**Calculating the Logical Address from the Virtual Address
 * Every Logical Address is 64 bit = 32 bit MemoryIndex + 32 bit Offset*/
/***********************************************************************/

void printAllocmap() {
    if (allocmap.size() == 0) {
        return;
    }
    PT_INFO("allocmap:");
    for (auto &it : allocmap) {
        cout << it.first << " - " << it.second << endl;
    }
}

void printHeap() {
    if (heap.size() == 0) {
        return;
    }
    PT_INFO("heap:");
    for (HEAPVEC::iterator it = heap.begin(); it != heap.end(); ++it) {
        std::cout << it->base << "-" << it->size << std::endl;
    }
}

uint64_t getIndex(string hash) {
    uint64_t to_shift;
    sscanf(hash.c_str(), "%llx", (long long unsigned int *)&to_shift);
    return (to_shift << 32);
}

void *getLogicalAddress(void *virt_addr, void *ip) {
    PT_DEBUG(3, "get log_addr for virt_addr of " << virt_addr);

    if (virt_addr == nullptr) {
        PT_WARN("dereferenced a nullptr");
        return virt_addr;
    }
    // Is the Virtual Address in the Heap address space?
    /* Set heap start and end markers */
    if (heap.size() &&
        (heaprange.baseaddr != heap.front().base ||
         heaprange.endaddr != heap.back().base + heap.back().size)) {
        heaprange.baseaddr = heap.front().base;
        heaprange.endaddr = heap.back().base + heap.back().size;
        PT_DEBUG(3, "heap.baseaddr: " << heaprange.baseaddr);
        PT_DEBUG(3, "heap.endaddr: " << heaprange.endaddr);
    }
    // Does the Virtual Address belong to any heap object?
    if ((uint64_t)virt_addr >= heaprange.baseaddr &&
        (uint64_t)virt_addr <= heaprange.endaddr) {
        uint64_t *log_addr = static_cast<uint64_t *>(virt_addr);
        for (auto i : heap) {
            if ((uint64_t)virt_addr < i.base ||
                (uint64_t)virt_addr >= (i.base + i.size)) {
                continue;
            }
            auto offset = (uint64_t)virt_addr - i.base;
            log_addr = (uint64_t *)(allocmap[i.base] | offset);
            PT_DEBUG(4, "found addr in heap vector, log_addr: "
                            << std::hex << (uint64_t)log_addr);
            return log_addr;
        }
    }
    // Is the Virtual Address in the Stack address space?
    if ((uint64_t)virt_addr >= stack.baseaddr &&
        (uint64_t)virt_addr < stack.endaddr) {
        PT_DEBUG(4, "found addr in stack " << std::hex << (uint64_t)virt_addr);
        return virt_addr;
    }
    // Is the Virtual Address in the IMG/Code address space?
    for (auto i : imgvec) {
        if ((uint64_t)virt_addr < i.baseaddr ||
            (uint64_t)virt_addr >= i.endaddr) {
            continue;
        }
        PT_DEBUG(4, "found addr in image " << std::hex << (uint64_t)virt_addr);
        return virt_addr;
    }
    // Is the Virtual Address in the Program Break address space?
    if ((uint64_t)virt_addr >= brk_range.baseaddr &&
        (uint64_t)virt_addr < brk_range.endaddr) {
        PT_DEBUG(2, "found addr in brk " << std::hex << (uint64_t)virt_addr
                                         << " called from " << std::hex
                                         << (uint64_t)ip);
        for (auto brk : brk_vec) {
            if ((uint64_t)virt_addr < brk.low ||
                (uint64_t)virt_addr >= brk.high) {
                continue;
            }
            PT_ASSERT(((uint64_t)ip >= brk.image.baseaddr &&
                       (uint64_t)ip < brk.image.endaddr),
                      "brk access within different image than brk "
                      "syscall originated.");
            return virt_addr;
        }
        PT_WARN("found addr in brk " << std::hex << (uint64_t)virt_addr
                                     << " called from " << std::hex
                                     << (uint64_t)ip);
        for (auto brk : brk_vec) {
            PT_WARN("brk from " << brk.low << " to " << brk.high);
        }
        PT_ERROR("brk access cannot be matched to any brk section");
    }

    PT_WARN("not found addr " << std::hex << (uint64_t)virt_addr);
    // TODO
    // PT_ASSERT(fast_recording == false,
    //           "virt_addr was not found despite being in fast_recording
    //           mode");
    DEBUG(3) printHeap();
    DEBUG(4) printProcMap();
    return virt_addr;
}

/***********************************************************************/
/** Heap recording                                                     */
/***********************************************************************/

/**
 * Calculate sha1-hash and use the 4 bytes of the hash as the memory Index
 */
void calculateSha1Hash(memobj_t *obj) {
    PT_DEBUG(2, "HashMap callstack " << obj->callstack);

    /* Hash shall be unique wrt. calling location */
    std::stringstream to_hash(obj->type, ios_base::app | ios_base::out);
    to_hash << obj->callstack;

    /**
     * A hash, i.e. logical base address, shall only occur once.
     * For variation the occurence of a hash is counted within hashmap.
     * This count is used together with the calling location to create an
     * unique hash.
     */
    std::stringstream count;
    count << hex << hashmap[to_hash.str()];
    hashmap[to_hash.str()] += 1;

    SHA1 hash;
    to_hash << count.str();
    hash.update(to_hash.str());
    obj->hash = hash.final();

    PT_DEBUG(1, "HashMap for    " << to_hash.str());
    PT_DEBUG(1, "HashMap count  0x" << count.str());
    PT_DEBUG(1, "Object hash    " << hex << obj->hash);
}

/**
 * Fetch callstack for debugging purpose and to diversify the logical base
 * addresses.
 */

void fetchCallStack(THREADID threadid, vector<string> &out,
                    CALLSTACK::IPVEC &ipvec) {
    auto mngr = CALLSTACK::CallStackManager::get_instance();
    auto cs = mngr->get_stack(threadid);
    cs.emit_stack(cs.depth(), out, ipvec);
}

void printCallStack(THREADID threadid) {
    vector<string> out;
    CALLSTACK::IPVEC ipvec;
    fetchCallStack(threadid, out, ipvec);

    for (uint32_t i = 0; i < out.size(); i++) {
        cout << out[i];
    }
}

string getCallStack(THREADID threadid) {
    vector<string> out;
    CALLSTACK::IPVEC ipvec;
    fetchCallStack(threadid, out, ipvec);

    DEBUG(2) for (uint32_t i = 0; i < out.size(); i++) { cout << out[i]; }

    stringstream unique_cs(ios_base::app | ios_base::out);
    for (auto i : ipvec) {
        unique_cs << " 0x" << hex << i.ipaddr;
    }
    PT_DEBUG(2, "callstack " << unique_cs.str());

    return unique_cs.str();
}

/**
 * Handle calls to free by maintaining a list of all heap objects
 * This function is not thread-safe. Lock first.
 */
void dofree(ADDRINT addr) {
    PT_DEBUG(1, "dofree 0x" << std::hex << addr);

    if (!addr) {
        PT_DEBUG(3, "dofree called with NULL");
        return;
    }

    if (allocmap.find(addr) == allocmap.end()) {
        PT_ERROR("dofree didnot found an element in allocmap");
    }
    allocmap.erase(addr);

    for (HEAPVEC::iterator it = heap.begin(); it != heap.end(); ++it) {
        if (it->base != addr) {
            continue;
        }
        heap.erase(it);
        return;
    }

    PT_ERROR("dofree didnot found an element in heap");
}

/**
 * Handle calls to [m|re|c]alloc by keeping a list of all heap objects
 * This function is not thread-safe. Lock first.
 */
void doalloc(ADDRINT addr, alloc_state_t *alloc_state,
             realloc_state_t *realloc_state) {
    if (alloc_state == nullptr && realloc_state == nullptr) {
        PT_ERROR("doalloc failed as only NULL states were passed");
    }
    if (alloc_state != nullptr && realloc_state != nullptr) {
        PT_ERROR("doalloc failed as multiple states were passed");
    }

    /* Convert (re)alloc_state to memobj */
    memobj_t obj;
    obj.base = addr;
    obj.size = (alloc_state) ? alloc_state->size : realloc_state->size;
    obj.type = (alloc_state) ? alloc_state->type : realloc_state->type;
    obj.callstack =
        (alloc_state) ? alloc_state->callstack : realloc_state->callstack;

    PT_DEBUG(1, "doalloc " << hex << addr << " " << hex << obj.size << " type "
                           << obj.type);

    /* Edit object in heap vector, if in-place reallocation */
    /* allocmap does not require any update, as base address is not changed */
    if (realloc_state && addr == realloc_state->old) {
        for (HEAPVEC::iterator it = heap.begin(); it != heap.end(); it++) {
            if (obj.base != it->base) {
                continue;
            }
            it->size = obj.size;
            PT_DEBUG(2, "in-place reallocation addr " << std::hex << addr);
            return;
        }
        PT_ERROR("in-place reallocation failed");
    }

    /* Write allocmap */
    ADDRINT log_addr = 0;
    if (alloc_state) {
        /* Create log_addr, if allocation */
        calculateSha1Hash(&obj);
        log_addr = getIndex(obj.hash.substr(32, 8));
    } else {
        /* Read log_addr, if not in-place reallocation */
        if (allocmap.find(realloc_state->old) == allocmap.end()) {
            PT_ERROR("doalloc used invalid allocmap addr "
                     << std::hex << realloc_state->old);
        }
        log_addr = allocmap[realloc_state->old];
        dofree(realloc_state->old);
    }
    allocmap[addr] = log_addr;

    /* Insert object into heap vector for allocation or not-inplace reallocation
     */
    /* Keep heap vector sorted */
    HEAPVEC::iterator below = heap.begin();
    HEAPVEC::iterator above = heap.end();
    for (HEAPVEC::iterator it = heap.begin(); it != heap.end(); it++) {
        if (obj.base < it->base) {
            above = it;
            break;
        }
        below = it;
    }

    if (!heap.size() || (below == &heap.back() &&
                         obj.base >= heap.back().base + heap.back().size)) {
        /* No inbetween slot found, thus append to the end */
        PT_INFO("Push to heap end");
        heap.push_back(obj);
    } else if (
        /* Insert in front, if obj does not overlap first element */
        (above == heap.begin() && obj.base + obj.size <= above->base)
        /* Valid inbetween slot found, thus insert before 'above' */
        || (obj.base >= below->base + below->size &&
            obj.base + obj.size <= above->base)) {
        heap.insert(above, obj);
    } else if (
        /* Insert in front, if below is of type MMAP/MREMAP and spans over obj
         */
        (below->type == std::string(MMAP) ||
         below->type == std::string(MREMAP)) &&
        (obj.base >= below->base) &&
        (obj.base + obj.size <= below->base + below->size)) {
        heap.insert(below, obj);
    } else {
        /* Invalid inbetween slot found, thus quit */
        printHeap();
        PT_INFO("below.base " << below->base);
        PT_INFO("above.base " << above->base);
        PT_INFO("obj.base   " << obj.base);
        PT_INFO("obj.size   " << obj.size);
        PT_ASSERT(false, "Corrupted heap?!");
    }
    DEBUG(3) printHeap();
    DEBUG(3) printAllocmap();
}

/**
 * Record malloc
 * @param threadid The thread
 * @param size The size parameter passed to malloc
 */
VOID RecordMallocBefore(THREADID threadid, VOID *ip, ADDRINT size) {
    PT_DEBUG(1, "malloc called with 0x" << std::hex << size << " at " << ip);
    // PIN_MutexLock(&lock);
    if (thread_state[threadid].realloc_state.size() == 0) {
        SHA1 hash;
        hash.update(getCallStack(threadid)); /* calculate the hash of the set of
                                                IPs in the Callstack */
        alloc_state_t state = {
            .type = MALLOC,
            .size = size,
            .callstack = hash.final().substr(28, 12), /* 6 byte SHA1 hash */
        };
        thread_state[threadid].malloc_state.push_back(state);
    } else {
        PT_DEBUG(1, "malloc ignored due to realloc_pending (size= "
                        << std::hex << size << ") at " << ip);
    }
    if (StopTrace)
        Trace = false;
    // PIN_MutexUnlock(&lock);
}

/**
 * Record malloc's result
 * @param threadid The thread
 * @param addr The allocated heap pointer
 */
VOID RecordMallocAfter(THREADID threadid, VOID *ip, ADDRINT addr) {
    PT_DEBUG(1, "malloc returned " << std::hex << addr);
    // PIN_MutexLock(&lock);
    PT_ASSERT(thread_state[threadid].malloc_state.size() > 0,
              "malloc returned but not called");
    alloc_state_t state = thread_state[threadid].malloc_state.back();
    thread_state[threadid].malloc_state.pop_back();
    doalloc(addr, &state, nullptr);
    Trace = true;
    // PIN_MutexUnlock(&lock);
}

/**
 * Record realloc
 * @param threadid The thread
 * @param addr The heap pointer param of realloc
 * @param size The size parameter passed to realloc
 */
VOID RecordReallocBefore(THREADID threadid, VOID *ip, ADDRINT addr,
                         ADDRINT size) {
    PT_DEBUG(1, "realloc called with " << std::hex << addr << " " << size
                                       << " at " << ip);
    // PIN_MutexLock(&lock);
    SHA1 hash;
    hash.update(getCallStack(
        threadid)); /* calculate the hash of the set of IPs in the Callstack */
    realloc_state_t state = {
        .type = REALLOC,
        .old = addr,
        .size = size,
        .callstack = hash.final().substr(28, 12), /* 6 byte SHA1 hash */
    };
    thread_state[threadid].realloc_state.push_back(state);
    if (StopTrace)
        Trace = false;
    // PIN_MutexUnlock(&lock);
}

/**
 * Record realloc's result
 * @param threadid The thread
 * @param addr The allocated heap pointer
 */
VOID RecordReallocAfter(THREADID threadid, VOID *ip, ADDRINT addr) {
    PT_DEBUG(1, "realloc returned " << std::hex << addr << " at " << ip);
    // PIN_MutexLock(&lock);
    PT_ASSERT(thread_state[threadid].realloc_state.size() > 0,
              "realloc returned but not called");
    realloc_state_t state = thread_state[threadid].realloc_state.back();
    thread_state[threadid].realloc_state.pop_back();

    doalloc(addr, nullptr, &state);
    Trace = true;
    // PIN_MutexUnlock(&lock);
}

/**
 * Record calloc
 * @param threadid The thread
 * @param nelem The number of elements parameter passed to calloc
 * @param size The size parameter passed to calloc
 */
VOID RecordCallocBefore(THREADID threadid, VOID *ip, ADDRINT nelem,
                        ADDRINT size) {
    PT_DEBUG(1, "calloc called with " << std::hex << nelem << "*" << std::hex
                                      << size);
    // PIN_MutexLock(&lock);
    if (thread_state[threadid].calloc_state.size() == 0) {
        SHA1 hash;
        hash.update(getCallStack(threadid)); /* calculate the hash of the set of
                                                IPs in the Callstack */
        alloc_state_t state = {
            .type = CALLOC,
            .size = nelem * size,
            .callstack = hash.final().substr(28, 12), /* 6 byte SHA1 hash */
        };

        thread_state[threadid].calloc_state.push_back(state);
    }
    if (StopTrace)
        Trace = false;
    // PIN_MutexUnlock(&lock);
}

/**
 * Record calloc's result
 * @param threadid The thread
 * @param addr The allocated heap pointer
 */
VOID RecordCallocAfter(THREADID threadid, VOID *ip, ADDRINT addr) {
    PT_DEBUG(1, "calloc returned " << std::hex << addr);
    // PIN_MutexLock(&lock);
    PT_ASSERT(thread_state[threadid].calloc_state.size() != 0,
              "calloc returned but not called");
    alloc_state_t state = thread_state[threadid].calloc_state.back();
    thread_state[threadid].calloc_state.pop_back();
    doalloc(addr, &state, nullptr);
    Trace = true;
    // PIN_MutexUnlock(&lock);
}

/**
 * Record free
 * @param threadid The thread
 * @param addr The heap pointer which is freed
 */
VOID RecordFreeBefore(THREADID threadid, VOID *ip, ADDRINT addr) {
    PT_DEBUG(1, "free called with " << std::hex << addr << " at " << ip);
    DEBUG(2) printCallStack(threadid);
    // PIN_MutexLock(&lock);
    dofree(addr);
    if (StopTrace)
        Trace = false;
    // PIN_MutexUnlock(&lock);
}

/**
 * Record free
 * @param threadid The thread
 * @param addr The heap pointer which is freed
 */
VOID RecordFreeAfter(VOID) {
    PT_DEBUG(1, "free returned");
    Trace = true;
}

/**
 * Record mmap
 * @param threadid      thread
 * @param size          size parameter passed to mmap
 * @param ret           TODO
 * @param force
 */
VOID RecordMmapBefore(THREADID threadid, ADDRINT size) {
    PT_DEBUG(1, "mmap called with " << std::hex << size);
    if (thread_state[threadid].mremap_state.size() != 0) {
        PT_DEBUG(1, "mmap ignored due to mremap_pending (size= "
                        << std::hex << size << ")");
        return;
    }
    if (thread_state[threadid].malloc_state.size() != 0) {
        PT_DEBUG(1, "nested mmap stemming from pending malloc"
                        << " (size= " << std::hex << size << ")");
    }
    if (thread_state[threadid].realloc_state.size() != 0) {
        PT_DEBUG(1, "nested mmap stemming from pending realloc"
                        << " (size= " << std::hex << size << ")");
    }
    // PIN_MutexLock(&lock);
    SHA1 hash;
    hash.update(getCallStack(threadid)); /* calculate the hash of the set of
                                            IPs in the Callstack */
    alloc_state_t state = {
        .type = MMAP,
        .size = size,
        .callstack = hash.final().substr(28, 12), /* 6 byte SHA1 hash */
    };

    thread_state[threadid].mmap_state.push_back(state);
    // PIN_MutexUnlock(&lock);
}

/**
 * Record mmap's result
 *@param threadid The thread
 * @param addr The allocated heap pointer
 */
VOID RecordMmapAfter(THREADID threadid, ADDRINT addr) {
    PT_DEBUG(1, "mmap returned " << std::hex << addr);
    if (thread_state[threadid].mremap_state.size() != 0) {
        PT_DEBUG(1, "mmap ignored due to mremap_pending");
        return;
    }
    if (thread_state[threadid].malloc_state.size() != 0 ||
        thread_state[threadid].realloc_state.size() != 0) {
        PT_DEBUG(1, "nested mmap due to [m,re]alloc pending");
    }
    // PIN_MutexLock(&lock);

    PT_ASSERT(thread_state[threadid].mmap_state.size() != 0,
              "mmap returned but not called");

    alloc_state_t state = thread_state[threadid].mmap_state.back();
    thread_state[threadid].mmap_state.pop_back();

    doalloc(addr, &state, nullptr);

    //  PIN_MutexUnlock(&lock);
}

/**
 * Record mremap
 * @param threadid The thread
 * @param addr The heap pointer param of mremap
 * @param size The size parameter passed to mremap
 */
VOID RecordMremapBefore(THREADID threadid, ADDRINT addr, ADDRINT old_size,
                        ADDRINT new_size) {
    PT_DEBUG(1, "mremap called with " << std::hex << addr << " " << new_size);
    // PIN_MutexLock(&lock);

    SHA1 hash;
    hash.update(getCallStack(
        threadid)); /* calculte the hash of the set of IPs in the Callstack */
    realloc_state_t state = {
        .type = MREMAP,
        .old = addr,
        .size = new_size,
        .callstack = hash.final().substr(28, 12), /* 6 byte SHA1 hash */
    };
    thread_state[threadid].mremap_state.push_back(state);

    //  PIN_MutexUnlock(&lock);
}

/**
 * Record mremap's result
 * @param threadid The thread
 * @param addr The allocated heap pointer
 */
VOID RecordMremapAfter(THREADID threadid, ADDRINT addr) {
    PT_DEBUG(1, "mremap returned " << std::hex << addr);
    // PIN_MutexLock(&lock);
    PT_ASSERT(thread_state[threadid].mremap_state.size() != 0,
              "mremap returned but not called");

    realloc_state_t state = thread_state[threadid].mremap_state.back();
    thread_state[threadid].mremap_state.pop_back();

    doalloc(addr, nullptr, &state);
    // PIN_MutexUnlock(&lock);
}

/**
 * Record munmap
 * @param threadid The thread
 * @param addr The heap pointer which is munmapped
 */
VOID RecordMunmapBefore(THREADID threadid, ADDRINT addr) {
    PT_DEBUG(1, "munmap called with " << std::hex << addr);
    DEBUG(2) printCallStack(threadid);
    // PIN_MutexLock(&lock);
    dofree(addr);
    //  PIN_MutexUnlock(&lock);
}

/**
 * Record brk's call
 *@param threadid The thread
 * @param addr The returned program break end address
 */
VOID RecordBrkBefore(THREADID threadid, ADDRINT addr) {
    PT_DEBUG(1, "brk called with " << std::hex << addr);
    DEBUG(3) printCallStack(threadid);

    // In case addr == 0 a new image "owns" brk
    if (addr != 0) {
        return;
    }
    // PIN_MutexLock(&lock);

    program_break_obj_t program_break;
    brk_vec.push_back(program_break);

    // PIN_MutexUnlock(&lock);
}

/**
 * Record brk's result
 *@param threadid The thread
 * @param addr The returned program break end address
 */
VOID RecordBrkAfter(THREADID threadid, ADDRINT addr, ADDRINT ret) {
    PT_DEBUG(1, "brk returned from " << std::hex << ret << " with " << std::hex
                                     << addr);
    // PIN_MutexLock(&lock);

    imgobj_t img;
    for (auto i : imgvec) {
        if ((uint64_t)ret < i.baseaddr || (uint64_t)ret >= i.endaddr) {
            continue;
        }
        img = i;
        break;
    }

    program_break_obj_t program_break = brk_vec.back();
    brk_vec.pop_back();

    program_break.high = addr;
    brk_range.endaddr = addr;
    if (program_break.image.name.empty()) {
        program_break.image = img;
        program_break.low = addr;
        PT_INFO("new brk owned by image: " << img.name);
        PT_DEBUG(1, "ranging from " << program_break.low << " to "
                                    << program_break.high);
    } else if (program_break.image.name.compare(img.name) != 0) {
        PT_INFO("brk called before from image: " << program_break.image.name);
        PT_INFO("brk called now from image: " << img.name);
        PT_ASSERT(false, "brk syscalls called within different images");
    }

    if (brk_range.baseaddr == 0) {
        brk_range.baseaddr = addr;
    }

    brk_vec.push_back(program_break);

    // PIN_MutexUnlock(&lock);
}

/***********************************************************************/
/** Instruction recording                                              */
/***********************************************************************/

/**
 * Record memory reads.
 * @param threadid The thread
 * @param ip The instruction issuing read
 * @param addr The data address being read
 * @param fast_recording For fast recording
 */
VOID RecordMemRead(THREADID threadid, VOID *ip, VOID *addr,
                   bool fast_recording) {
    if (!Record || !Trace)
        return;
    // PIN_MutexLock(&lock);
    entry_t entry;
    entry.type = READ;
    entry.ip = (uint64_t)((uintptr_t)ip);
    entry.data = (uint64_t)((uintptr_t)getLogicalAddress(addr, ip));
    DEBUG(3)
    printf("[pintool] Read %" PRIx64 " to %" PRIx64 "\n", (uint64_t)entry.ip,
           (uint64_t)entry.data);
    if (fast_recording) {
        leaks->dleak_consume((uint64_t)entry.ip, (uint64_t)entry.data);
    } else {
        record_entry(entry);
    }
    // PIN_MutexUnlock(&lock);
}

/**
 * Record memory writes.
 * @param threadid The thread
 * @param ip The instruction issuing write
 * @param addr The data address being written
 * @param fast_recording For fast recording
 */
VOID RecordMemWrite(THREADID threadid, VOID *ip, VOID *addr,
                    bool fast_recording) {
    if (!Record || !Trace)
        return;
    // PIN_MutexLock(&lock);
    entry_t entry;
    entry.type = WRITE;
    entry.ip = (uint64_t)((uintptr_t)ip);
    entry.data = (uint64_t)((uintptr_t)getLogicalAddress(addr, ip));
    DEBUG(3)
    printf("[pintool] Write %" PRIx64 " to %" PRIx64 "\n", (uint64_t)entry.ip,
           (uint64_t)entry.data);
    if (fast_recording) {
        leaks->dleak_consume((uint64_t)entry.ip, (uint64_t)entry.data);
    } else {
        record_entry(entry);
    }
    // PIN_MutexUnlock(&lock);
}

/**
 * Record conditional and unconditional branches.
 * This function is not thread-safe! Lock first.
 *
 * @param threadid The thread
 * @param ins The branching instruction
 * @param target The next instruction (e.g. branch target)
 */
VOID RecordBranch_unlocked(THREADID threadid, ADDRINT ins, ADDRINT target) {
    if (!Record || !Trace)
        return;
    entry_t entry;
    entry.type = BRANCH;
    entry.ip = ins;
    entry.data = target;
    record_entry(entry);
}

/**
 * Record conditional and unconditional branches.
 * @param threadid The thread
 * @param bbl The basic block containing the branch
 * @param bp The branching instruction
 * @param ctxt The CPU context of bp
 * @param fast_recording For fast recording
 */
VOID RecordBranch(THREADID threadid, ADDRINT bbl, ADDRINT bp,
                  const CONTEXT *ctxt, bool fast_recording) {
    // PIN_MutexLock(&lock);
    ADDRINT target = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    DEBUG(3)
    std::cout << "[pintool] Branch " << std::hex << bp << " to " << target
              << std::endl;
    RecordBranch_unlocked(threadid, bp, target);
    if (fast_recording) {
        leaks->cfleak_consume(bp, target);
    }
    // PIN_MutexUnlock(&lock);
}

/**
 * Record conditional branch due to REP-prefix.
 * @param threadid The thread
 * @param bbl The basic block containing the branch
 * @param bp The branching instruction
 * @param ctxt The CPU context of bp
 * @param fast_recording For fast recording
 */
VOID RecordRep(THREADID threadid, ADDRINT bbl, ADDRINT bp, const CONTEXT *ctxt,
               bool fast_recording) {
    // PIN_MutexLock(&lock);
    ADDRINT target = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    DEBUG(3)
    std::cout << "[pintool] REP-branch " << std::hex << bp << " to " << target
              << std::endl;
    RecordBranch_unlocked(threadid, bp, target);
    if (fast_recording) {
        leaks->cfleak_consume(bp, target);
    }
    // PIN_MutexUnlock(&lock);
}

/**
 * Record call instructions.
 * This function is not thread-safe! Lock first.
 *
 * @param threadid The thread
 * @param ins The call instruction
 * @param indirect For indirect calls
 * @param target The called function's entry
 */
VOID RecordFunctionEntry_unlocked(THREADID threadid, ADDRINT ins, BOOL indirect,
                                  ADDRINT target) {
    if (!Record || !Trace)
        return;
    entry_t entry;
    entry.type = FUNC_ENTRY;
    entry.ip = ins;
    entry.data = target;
    DEBUG(3)
    std::cout << "[pintool] Call " << std::hex << ins << " to " << target
              << std::endl;
    leaks->call_consume(ins, target);
    record_entry(entry);
}

/**
 * Record call instructions.
 *
 * @param threadid The thread
 * @param bbl The basic block containing the call
 * @param ins The call instruction
 * @param indirect For indirect calls
 * @param target The called function's entry
 * @param fast_recording For fast recording
 */
VOID RecordFunctionEntry(THREADID threadid, ADDRINT bbl, ADDRINT ins,
                         BOOL indirect, ADDRINT target, bool fast_recording) {
    if (WaitForFirstFunction) {
        Record = true;
        WaitForFirstFunction = false;
    }
    if (!Record || !Trace)
        return;
    // PIN_MutexLock(&lock);
    if (indirect) {
        DEBUG(2)
        std::cout << "[pintool] Icall to  " << std::hex << target << std::endl;
    }
    if (KnobFunc.Value()) {
        RecordFunctionEntry_unlocked(threadid, ins, indirect, target);
    }
    if (fast_recording) {
        leaks->cfleak_consume(ins, target);
    }
    // PIN_MutexUnlock(&lock);
}

/**
 * Record ret instructions.
 * This function is not thread-safe! Lock first.
 *
 * @param threadid The thread
 * @param ins The ret instruction
 * @param target The instruction to continue after ret
 */
VOID RecordFunctionExit_unlocked(THREADID threadid, ADDRINT ins,
                                 ADDRINT target) {
    if (!Record || !Trace)
        return;
    entry_t entry;
    entry.type = FUNC_EXIT;
    entry.ip = ins;
    entry.data = target;
    DEBUG(2)
    std::cout << "[pintool] Ret " << std::hex << ins << " to " << target
              << std::endl;
    leaks->ret_consume(ins);
    record_entry(entry);
}

/**
 * Record ret instructions.
 *
 * @param threadid The thread
 * @param bbl The basic block containing the call
 * @param ins The call instruction
 * @param ctxt The CPU context of ins
 * @param fast_recording For fast recording
 */
VOID RecordFunctionExit(THREADID threadid, ADDRINT bbl, ADDRINT ins,
                        const CONTEXT *ctxt, bool fast_recording) {
    if (!Record || !Trace)
        return;
    ADDRINT target =
        ctxt != NULL ? (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR) : 0;
    // PIN_MutexLock(&lock);
    if (KnobFunc.Value()) {
        RecordFunctionExit_unlocked(threadid, ins, target);
    }
    if (fast_recording) {
        leaks->cfleak_consume(ins, target);
    }
    // PIN_MutexUnlock(&lock);
}

/***********************************************************************/
/** Instrumentation Code                                               */
/***********************************************************************/

/**
 * Instruments program entry and exit as well as heap functions of libc.
 * @param img The loaded image
 * @param v UNUSED
 */
VOID instrumentMainAndAlloc(IMG img, VOID *v) {
    if (!IMG_Valid(img)) {
        PT_ERROR("loaded image is invalid");
    }

    string name = IMG_Name(img);
    PT_DEBUG(1, "instrumenting " << name);

    if (imgfile.is_open()) {
        uint64_t high = IMG_HighAddress(img);
        uint64_t low = IMG_LowAddress(img);

        if (vdsofile.is_open() && IMG_IsVDSO(img)) {
            /* For VDSO, the HighAddress does not point to end of ELF file,
             * leading to a truncated ELF file. We over-approximate the ELF size
             * with IMG_SizeMapped instead.
             */
            high = low + IMG_SizeMapped(img);
            PT_DEBUG(1, "vdso low:   0x" << hex << low);
            PT_DEBUG(1, "vdso high:  0x" << hex << high);
            PT_DEBUG(1, "vdso size mapped:  0x" << hex << IMG_SizeMapped(img));
            vdsofile.write((const char *)low, IMG_SizeMapped(img));
            vdsofile.close();
            name = KnobVDSO.Value();
        }

        PT_DEBUG(1, "image name: " << name);
        PT_DEBUG(1, "image low:  0x " << hex << low);
        PT_DEBUG(1, "image high: 0x " << hex << high);
        imgfile << "Image:" << endl;
        imgfile << name << endl;
        imgfile << hex << low << ":" << hex << high << endl;

        imgobj_t imgdata;
        imgdata.name = name;
        imgdata.baseaddr = low;
        imgdata.endaddr = high;

        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
            string sec_name = SEC_Name(sec);
            low = SEC_Address(sec);
            high = SEC_Address(sec) + SEC_Size(sec);

            PT_DEBUG(1, "sec name: " << sec_name);
            PT_DEBUG(1, "sec low:  0x " << hex << low);
            PT_DEBUG(1, "sec high: 0x " << hex << high);
            if (!SEC_Mapped(sec)) {
                PT_INFO("unmapped sec dropped: " << sec_name);
                continue;
            }
            imgdata.baseaddr =
                (imgdata.baseaddr > low) ? low : imgdata.baseaddr;
            imgdata.endaddr = (imgdata.endaddr < high) ? high : imgdata.endaddr;
        }

        PT_DEBUG(1, "image low:  0x " << hex << imgdata.baseaddr);
        PT_DEBUG(1, "image high: 0x " << hex << imgdata.endaddr);
        imgvec.push_back(imgdata);

        for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym);
             sym = SYM_Next(sym)) {
            imgfile << hex << SYM_Address(sym)
                    << ":" + PIN_UndecorateSymbolName(SYM_Name(sym),
                                                      UNDECORATION_NAME_ONLY)
                    << endl;
        }
    }

    PT_DEBUG(1, "KnobMain: " << KnobMain.Value());
    if (KnobMain.Value().compare("ALL") != 0) {
        RTN mainRtn = RTN_FindByName(img, KnobMain.Value().c_str());
        if (mainRtn.is_valid()) {
            PT_DEBUG(1, "KnobMain is valid");
            RTN_Open(mainRtn);
            RTN_InsertCall(mainRtn, IPOINT_BEFORE, (AFUNPTR)RecordMainBegin,
                           IARG_THREAD_ID, IARG_ADDRINT, RTN_Address(mainRtn),
                           IARG_END);
            RTN_InsertCall(mainRtn, IPOINT_AFTER, (AFUNPTR)RecordMainEnd,
                           IARG_THREAD_ID, IARG_ADDRINT, RTN_Address(mainRtn),
                           IARG_END);
            RTN_Close(mainRtn);
        }
    } else {
        PT_DEBUG(1, "recording all");
        if (!Record) {
            WaitForFirstFunction = true;
        }
    }

    if (!KnobTrackHeap.Value()) {
        PT_INFO("heap tracking inactive");
        return;
    }

    if (alloc_instrumented) {
        PT_DEBUG(1, "allocation already instrumented");
        return;
    }

    if (name.find("alloc.so") == std::string::npos &&
        name.find("libc.so") == std::string::npos) {
        PT_DEBUG(3, "image (" << name << ") is not named alloc.so or libc.so");
        return;
    }
    /* If alloc.so is pre-loaded, it will always be before libc
     * We only instrument once
     */
    PT_DEBUG(1, "instrumenting allocation in " << name);
    alloc_instrumented = 1;

    RTN mallocRtn = RTN_FindByName(img, MALLOC);
    if (!mallocRtn.is_valid()) {
        PT_ERROR("malloc not found");
    }
    PT_DEBUG(1, "malloc found in " << IMG_Name(img));
    RTN_Open(mallocRtn);
    RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)RecordMallocBefore,
                   IARG_THREAD_ID, IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE,
                   0, IARG_END);
    RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)RecordMallocAfter,
                   IARG_THREAD_ID, IARG_INST_PTR, IARG_FUNCRET_EXITPOINT_VALUE,
                   IARG_END);
    RTN_Close(mallocRtn);

    RTN reallocRtn = RTN_FindByName(img, REALLOC);
    if (!reallocRtn.is_valid()) {
        PT_ERROR("realloc not found");
    }
    PT_DEBUG(1, "realloc found in " << IMG_Name(img));
    RTN_Open(reallocRtn);
    RTN_InsertCall(reallocRtn, IPOINT_BEFORE, (AFUNPTR)RecordReallocBefore,
                   IARG_THREAD_ID, IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE,
                   0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
    RTN_InsertCall(reallocRtn, IPOINT_AFTER, (AFUNPTR)RecordReallocAfter,
                   IARG_THREAD_ID, IARG_INST_PTR, IARG_FUNCRET_EXITPOINT_VALUE,
                   IARG_END);
    RTN_Close(reallocRtn);

    RTN callocRtn = RTN_FindByName(img, CALLOC);
    if (!callocRtn.is_valid()) {
        PT_ERROR("calloc not found");
    }
    PT_DEBUG(1, "calloc found in " << IMG_Name(img));
    RTN_Open(callocRtn);
    RTN_InsertCall(callocRtn, IPOINT_BEFORE, (AFUNPTR)RecordCallocBefore,
                   IARG_THREAD_ID, IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE,
                   0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
    RTN_InsertCall(callocRtn, IPOINT_AFTER, (AFUNPTR)RecordCallocAfter,
                   IARG_THREAD_ID, IARG_INST_PTR, IARG_FUNCRET_EXITPOINT_VALUE,
                   IARG_END);
    RTN_Close(callocRtn);

    RTN freeRtn = RTN_FindByName(img, FREE);
    if (!freeRtn.is_valid()) {
        PT_ERROR("free not found");
    }
    PT_DEBUG(1, "free found in " << IMG_Name(img));
    RTN_Open(freeRtn);
    RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)RecordFreeBefore,
                   IARG_THREAD_ID, IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE,
                   0, IARG_END);
    RTN_InsertCall(freeRtn, IPOINT_AFTER, (AFUNPTR)RecordFreeAfter, IARG_END);
    RTN_Close(freeRtn);
}

/**
 * Handle syscall entry
 * We only trace allocation-related syscalls.
 * If syscall is not traced SYSCALL_NUMBER is set to -1.
 */
VOID SyscallEntry(THREADID threadid, CONTEXT *ctxt, SYSCALL_STANDARD std,
                  VOID *v) {
    SYSCALL_NUMBER = PIN_GetSyscallNumber(ctxt, std);

    PT_DEBUG(1, "syscall " << hex << PIN_GetContextReg(ctxt, REG_INST_PTR)
                           << " " << hex << SYSCALL_NUMBER << " " << hex
                           << PIN_GetSyscallArgument(ctxt, std, 0) << " " << hex
                           << PIN_GetSyscallArgument(ctxt, std, 1) << " " << hex
                           << PIN_GetSyscallArgument(ctxt, std, 2) << " " << hex
                           << PIN_GetSyscallArgument(ctxt, std, 3) << " " << hex
                           << PIN_GetSyscallArgument(ctxt, std, 4) << " " << hex
                           << PIN_GetSyscallArgument(ctxt, std, 5));

    // https://filippo.io/linux-syscall-table/
    switch (SYSCALL_NUMBER) {
    case 9:
        if (PIN_GetSyscallArgument(ctxt, std, 0)) {
            PT_INFO("mmap syscall dropped.");
            SYSCALL_NUMBER = -1;
            break;
        }
        RecordMmapBefore(threadid, PIN_GetSyscallArgument(ctxt, std, 1));
        break;
    case 11:
        RecordMunmapBefore(threadid, PIN_GetSyscallArgument(ctxt, std, 0));
        break;
    case 12:
        RecordBrkBefore(threadid, PIN_GetSyscallArgument(ctxt, std, 0));
        break;
    case 25:
        RecordMremapBefore(threadid, PIN_GetSyscallArgument(ctxt, std, 0),
                           PIN_GetSyscallArgument(ctxt, std, 1),
                           PIN_GetSyscallArgument(ctxt, std, 2));
        break;
    default:
        SYSCALL_NUMBER = -1;
        PT_INFO("Syscall not catched. syscall number: "
                << std::hex << PIN_GetSyscallNumber(ctxt, std));
        break;
    }
}

/**
 * Handle syscall exit
 */
VOID SyscallExit(THREADID threadid, CONTEXT *ctxt, SYSCALL_STANDARD std,
                 VOID *v) {
    PT_DEBUG(1, "returns: " << hex << PIN_GetSyscallReturn(ctxt, std));

    // https://filippo.io/linux-syscall-table/
    switch (SYSCALL_NUMBER) {
    case -1:
        // Syscall will be dropped, as its number is set to -1 in SyscallEntry
        break;
    case 9:
        RecordMmapAfter(threadid, PIN_GetSyscallReturn(ctxt, std));
        break;
    case 11:
        // Handling of munmap exit is not needed.
        break;
    case 12:
        RecordBrkAfter(threadid, PIN_GetSyscallReturn(ctxt, std),
                       PIN_GetContextReg(ctxt, REG_INST_PTR));
        break;
    case 25:
        RecordMremapAfter(threadid, PIN_GetSyscallReturn(ctxt, std));
        break;
    default:
        PT_ERROR("syscall unknown. syscall number: " << SYSCALL_NUMBER);
        break;
    }
    SYSCALL_NUMBER = -1;
}

/**
 * Instruments instructions operating on memory
 * @param ins The instruction
 * @param fast_recording Fast recording
 * @return True if the instruction could be instrumented
 */
BOOL instrumentMemIns(INS ins, bool fast_recording) {
    if (KnobMem.Value()) {
        UINT32 memOperands = INS_MemoryOperandCount(ins);
        bool found = false;
        ADDRINT ip = INS_Address(ins);
        DEBUG(1)
        printf("[pintool] Adding %lx to instrumentation\n",
               (long unsigned int)ip);

        for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
            if (INS_MemoryOperandIsRead(ins, memOp)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                               IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYOP_EA,
                               memOp, IARG_BOOL, fast_recording, IARG_END);
                found = true;
            }
            if (INS_MemoryOperandIsWritten(ins, memOp)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                               IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYOP_EA,
                               memOp, IARG_BOOL, fast_recording, IARG_END);
                found = true;
            }
        }
        return found;
    } else {
        return false;
    }
}

/**
 * Instruments control-flow instructions
 * @param bbl The start of a new basic block
 * @param bp The branch point. Same as bbl, except for fast_recording
 * @param fast_recording Fast recording
 */
bool instrumentCallBranch(INS bbl, INS bp, bool fast_recording) {
    bool instrumented = false;
    if (INS_IsCall(bp)) {
        if (KnobFunc.Value() || KnobBbl.Value()) {
            INS_InsertCall(bp, IPOINT_BEFORE, AFUNPTR(RecordFunctionEntry),
                           IARG_THREAD_ID, IARG_ADDRINT, INS_Address(bbl),
                           IARG_ADDRINT, INS_Address(bp), IARG_BOOL,
                           INS_IS_INDIRECT(bp), IARG_BRANCH_TARGET_ADDR,
                           IARG_BOOL, fast_recording, IARG_END);
            DEBUG(1)
            printf("[pintool] Instrumented call@%lx\n",
                   (long unsigned int)INS_Address(bp));
            instrumented = true;
        }
    } else if (INS_IsRet(bp)) {
        /* RET would be also detected as branch, therefore we use 'else if' */
        if (KnobFunc.Value() || KnobBbl.Value()) {
            ASSERT(INS_HAS_TAKEN_BRANCH(bp),
                   "[pintool] Error: Return instruction should support taken "
                   "branch.");
            INS_InsertCall(bp, IPOINT_TAKEN_BRANCH, AFUNPTR(RecordFunctionExit),
                           IARG_THREAD_ID, IARG_ADDRINT, INS_Address(bbl),
                           IARG_ADDRINT, INS_Address(bp), IARG_CONTEXT,
                           IARG_BOOL, fast_recording, IARG_END);
            DEBUG(1)
            printf("[pintool] Instrumented ret@%lx\n",
                   (long unsigned int)INS_Address(bp));
            instrumented = true;
        }
    } else if (INS_IsBranch(bp)) {
        if (KnobBbl.Value()) {
            if (!INS_HAS_TAKEN_BRANCH(bp)) {
                std::cout << "[pintool] Warning: Branch instruction "
                          << INS_Mnemonic(bp) << "@ 0x" << std::hex
                          << INS_Address(bp)
                          << " does not support taken branch. Ignoring."
                          << std::endl;
                // TODO: test for leaks in XBEGIN/XEND/XABORT
            } else {
                /* unconditional jumps */
                INS_InsertCall(bp, IPOINT_TAKEN_BRANCH, AFUNPTR(RecordBranch),
                               IARG_THREAD_ID, IARG_ADDRINT, INS_Address(bbl),
                               IARG_ADDRINT, INS_Address(bp), IARG_CONTEXT,
                               IARG_BOOL, fast_recording, IARG_END);
                DEBUG(1)
                printf("[pintool] Instrumented jump@%lx\n",
                       (long unsigned int)INS_Address(bp));
                instrumented = true;
            }

            if (INS_HAS_IPOINT_AFTER(bp)) {
                /* conditional/indirect jumps */
                INS_InsertCall(bp, IPOINT_AFTER, AFUNPTR(RecordBranch),
                               IARG_THREAD_ID, IARG_ADDRINT, INS_Address(bbl),
                               IARG_ADDRINT, INS_Address(bp), IARG_CONTEXT,
                               IARG_BOOL, fast_recording, IARG_END);
                DEBUG(1)
                printf("[pintool] Instrumented indirect jump@%lx\n",
                       (long unsigned int)INS_Address(bp));
                instrumented = true;
            }
        }
    } else if (INS_RepPrefix(bp)) {
        ADDRINT ip = INS_Address(bp);
        DEBUG(2)
        printf("[pintool] REP@%lx: REP-predicated instruction\n",
               (long unsigned int)ip);

        /* Rep-prefix does not necessarily show architectural effect
         * E.g. repz retq (see http://pages.cs.wisc.edu/~lena/repzret.php)
         */

        if (INS_HAS_IPOINT_AFTER(bp)) {
            DEBUG(2)
            printf("[pintool] REP@%lx has fall-through\n",
                   (long unsigned int)ip);
            /* REP-prefixed instruction where REP is in effect (e.g. rep stos)
             */
            INS_InsertCall(bp, IPOINT_AFTER, AFUNPTR(RecordRep), IARG_THREAD_ID,
                           IARG_ADDRINT, INS_Address(bbl), IARG_ADDRINT,
                           INS_Address(bp), IARG_CONTEXT, IARG_BOOL,
                           fast_recording, IARG_END);
            instrumented = true;
            DEBUG(1)
            printf("[pintool] Instrumented rep@%lx\n",
                   (long unsigned int)INS_Address(bp));
        }
    }
    return instrumented;
}

/**
 * Instrument any instructions according to the knobs
 * @param ins The instruction to trace
 * @param v UNUSED
 */
VOID instrumentAnyInstructions(INS ins, VOID *v) {
    instrumentMemIns(ins, false);
    instrumentCallBranch(ins, ins, false);
}

/**
 * Instrument only those instructions which were reported as leaking,
 * i.e. for which an entry in leaks exists.
 * @param ins The instruction to trace
 * @param v UNUSED
 */
VOID instrumentLeakingInstructions(INS ins, VOID *v) {
    ADDRINT ip = INS_Address(ins);

    if (leaks->get_erase_dleak(ip) || leaks->was_erased_dleak(ip)) {
        /* Instrument dataleaking instruction */
        DEBUG(1) printf("[pintool] Tracing DLEAK %lx\n", (long unsigned int)ip);
        bool found = instrumentMemIns(ins, true);
        ASSERT(found, "[pintool] Error: Memory instruction to instument not "
                      "found. Have you provided the flag -mem?");
    }

    if (KnobFunc.Value()) {
        /* Instrument call/ret for generating call stack */
        if (INS_IsCall(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(RecordFunctionEntry),
                           IARG_THREAD_ID, IARG_ADDRINT, INS_Address(ins),
                           IARG_ADDRINT, INS_Address(ins), IARG_BOOL,
                           INS_IS_INDIRECT(ins), IARG_BRANCH_TARGET_ADDR,
                           IARG_BOOL, false, IARG_END);
            DEBUG(1)
            printf("[pintool] Instrumented call stack call@%lx\n",
                   (long unsigned int)INS_Address(ins));
        } else if (INS_IsRet(ins)) {
            ASSERT(INS_HAS_TAKEN_BRANCH(ins),
                   "[pintool] Error: Return instruction should support taken "
                   "branch.");
            INS_InsertCall(
                ins, IPOINT_TAKEN_BRANCH, AFUNPTR(RecordFunctionExit),
                IARG_THREAD_ID, IARG_ADDRINT, INS_Address(ins), IARG_ADDRINT,
                INS_Address(ins), IARG_CONTEXT, IARG_BOOL, false, IARG_END);
            DEBUG(1)
            printf("[pintool] Instrumented call stack ret@%lx\n",
                   (long unsigned int)INS_Address(ins));
        }
    }

    if (leaks->get_erase_cfleak(ip) || leaks->was_erased_cfleak(ip)) {
        /* Instrument cfleaking instruction */
        DEBUG(1)
        printf("[pintool] Tracing CFLEAK %lx\n", (long unsigned int)ip);

        /* Need to find actual branch inside BBL, since ins is start address of
         * the whole BBL Therefore, we assume that the *first* branch/call
         * inside the BBL is our conditional branch/call of interest.
         * Unconditional branches must therefore have started a new BBL.
         */
        INS bp = ins;
        bool found = false;
        while (bp != INS_Invalid()) {
            DEBUG(2)
            printf("[pintool] Testing ins %lx\n",
                   (long unsigned int)INS_Address(bp));
            if (instrumentCallBranch(ins, bp, true)) {
                DEBUG(2)
                printf("[pintool] Found bp %lx\n",
                       (long unsigned int)INS_Address(bp));
                /* We instrument the actual branch point (bp) but report leaks
                 * with respect to the BBL (ins)
                 */
                found = true;
                break;
            }
            bp = INS_Next(bp);
        }
        ASSERT(found, "[pintool] Error: Instruction to instument not found");
    }
}

/***********************************************************************/
/** CLI and Pin framework functions                                    */
/***********************************************************************/
typedef struct __attribute__((packed)) {
    uint8_t type;
    uint64_t ip;
    uint8_t nopt;
} leakfmt_t;

/**
 *  Loads leaks as exported by analyze.py show --leakout
 */
VOID loadLeaks(VOID *v) {
    FILE *f = NULL;
    f = fopen(KnobLeakIn.Value().c_str(), "r");
    ASSERT(f, "[pintool] Error: Leak file does not exist");
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    DEBUG(1)
    printf("[pintool] Reading leaks from %s, size %ld bytes\n",
           KnobLeakIn.Value().c_str(), len);
    ASSERT(leaks, "[pintool] Error: Leaks not initialized");
    while (ftell(f) < len) {
        leakfmt_t elem;
        ASSERT(fread(&elem, sizeof(elem), 1, f) == 1,
               "[pintool] Error: Failed reading leak file");
        uint64_t callee = 0;
        DEBUG(1)
        printf("[pintool] Loading leak element %x, %" PRIx64 ", %d\n",
               elem.type, elem.ip, elem.nopt);
        switch (elem.type) {
        case FUNC_ENTRY:
            ASSERT(elem.nopt == 1, "[pintool] Error: Trace format corrupt");
            ASSERT(fread(&callee, sizeof(callee), 1, f) == 1,
                   "[pintool] Error: Failed reading leak file");
            if (KnobCallstack.Value()) {
                leaks->call_create(elem.ip, callee);
            }
            DEBUG(1) printf("[pintool] Func entry %" PRIx64 "\n", callee);
            break;
        case FUNC_EXIT:
            ASSERT(fseek(f, elem.nopt * sizeof(uint64_t), SEEK_CUR) == 0,
                   "[pintool] Error: Failed reading leak file");
            if (KnobCallstack.Value()) {
                leaks->ret_create(elem.ip);
            }
            DEBUG(1) printf("[pintool] Func exit\n");
            break;
        case DLEAK:
            ASSERT(elem.nopt == 0, "[pintool] Error: Trace format corrupt");
            leaks->dleak_create(elem.ip);
            DEBUG(1) printf("[pintool] Adding Dleak: %" PRIx64 "\n", elem.ip);
            break;
        case CFLEAK:
            ASSERT(elem.nopt > 0, "[pintool] Error: Trace format corrupt");
            ASSERT(fseek(f, elem.nopt * sizeof(uint64_t), SEEK_CUR) == 0,
                   "[pintool] Error: Failed reading leak file");
            leaks->cfleak_create(elem.ip, NULL, 0);
            DEBUG(1) printf("[pintool] Adding CFleak: %" PRIx64 "\n", elem.ip);
            break;
        default:
            ASSERT(false, "[pintool] Error: Invalid leak type");
        }
    }
    ASSERT(ftell(f) == len, "[pintool] Error: Trace format corrupt");
    DEBUG(2) leaks->print_all();
    fflush(stdout);

    if (use_callstack) {
        static_cast<CallStack *>(leaks)->rewind();
    }
}

/**
 * Write traces to files
 */
VOID Fini(INT32 code, VOID *v) {
    if (!KnobLeaks.Value()) {
        if (!KnobRawFile.Value().empty()) {
            FILE *ftrace = fopen(KnobRawFile.Value().c_str(), "w");
            if (!ftrace) {
                std::cout << "[pintool] Error: Unable to open file "
                          << KnobRawFile.Value() << std::endl;
            } else {
                std::cout << "[pintool] Writing raw results to "
                          << KnobRawFile.Value() << std::endl;
                bool res;
                res = fwrite(&trace[0], sizeof(entry_t), trace.size(),
                             ftrace) == trace.size();
                fclose(ftrace);
                ASSERT(res, "[pintool] Error: Unable to write complete trace "
                            "file. Out of disk memory?");
            }
        }
        /* KnobLeaks is set */
    } else {
        DEBUG(1) leaks->print_all();
        DEBUG(1)
        printf("[pintool] Number of uninstrumented data leaks: %zu\n",
               leaks->get_uninstrumented_dleak_size());
        DEBUG(1)
        printf("[pintool] Number of uninstrumented cflow leaks: %zu\n",
               leaks->get_uninstrumented_cfleak_size());
        DEBUG(1) leaks->print_uninstrumented_leaks();

        if (!KnobLeakOut.Value().empty()) {
            ASSERT(!KnobLeakIn.Value().empty(),
                   "[pintool] Error: leakout requires leakin");
            ASSERT(leaks, "[pintool] Error: Leaks not initialized");
            FILE *fleaks = fopen(KnobLeakOut.Value().c_str(), "w");
            if (!fleaks) {
                std::cout << "[pintool] Unable to open file "
                          << KnobLeakOut.Value() << std::endl;
            } else {
                std::cout << "[pintool] Writing leak results to "
                          << KnobLeakOut.Value() << std::endl;
                if (use_callstack) {
                    static_cast<CallStack *>(leaks)->rewind();
                }
                leaks->doexport(fleaks);
                fclose(fleaks);
            }
        }
    }

    if (imgfile.is_open()) {
        imgfile.close();
    }
}

INT32 Usage() {
    PIN_ERROR("Address Leak Detector\n" + KNOB_BASE::StringKnobSummary() +
              "\n");
    return -1;
}

int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv))
        return Usage();

    PIN_InitSymbols();

    DEBUG_LEVEL = KnobDebug.Value();
    StopTrace = KnobStopTrace.Value();

    if (KnobLeaks.Value() && KnobCallstack.Value()) {
        leaks = new CallStack();
        use_callstack = true;
    } else {
        leaks = new Flat();
        use_callstack = false;
    }
    IMG_AddInstrumentFunction(instrumentMainAndAlloc, 0);
    if (!KnobSyms.Value().empty()) {
        imgfile.open(KnobSyms.Value().c_str());
    }
    if (!KnobVDSO.Value().empty()) {
        vdsofile.open(KnobVDSO.Value().c_str());
    }

    if (!KnobLeaks.Value()) {
        /* Traditional tracing */
        if (KnobBbl.Value() || KnobMem.Value() || KnobFunc.Value()) {
            INS_AddInstrumentFunction(instrumentAnyInstructions, 0);
        }
    } else {
        /* Tracing only leaks specified by leak file */
        DEBUG(1) std::cout << "[pintool] Tracing leaks" << std::endl;
        /* calling loadLeaks via PIN_AddApplicationStartFunction.
         * This ensures the program under instrumentation is already completely
         * loaded before loadLeaks is called, thus preserving the order (and
         * thus the memory layout) in which shared libraries are loaded.
         */
        PIN_AddApplicationStartFunction(loadLeaks, 0);
        INS_AddInstrumentFunction(instrumentLeakingInstructions, 0);
    }

    /* Syscall tracing */
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);

    /* Getting the stack and vvar address range for this process */
    stack.baseaddr = getAddrFromProcMap("stack", 1);
    stack.endaddr = getAddrFromProcMap("stack", 2);
    PT_DEBUG(1, "stack.baseaddr is " << hex << stack.baseaddr);
    PT_DEBUG(1, "stack.endaddr  is " << hex << stack.endaddr);

    imgobj_t imgdata = {
        .name = "vvar",
        .baseaddr = getAddrFromProcMap("vvar", 1),
        .endaddr = getAddrFromProcMap("vvar", 2),
    };
    imgvec.push_back(imgdata);
    PT_DEBUG(1, "vvar.baseaddr is " << hex << imgdata.baseaddr);
    PT_DEBUG(1, "vvar.endaddr  is " << hex << imgdata.endaddr);

    auto mngr = CALLSTACK::CallStackManager::get_instance();
    mngr->activate();

    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    PIN_AddFiniFunction(Fini, 0);

    init();
    PIN_StartProgram();

    return 0;
}
