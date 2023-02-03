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
#include "pin.H"
#include "sha1.hpp"
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

/**
 * Pin 3.11 Documentation:
 * https://software.intel.com/sites/landingpage/pintool/docs/97998/Pin/html
 */

// Pin above 3.7.97720 deprecates some functions
#if (PIN_PRODUCT_VERSION_MAJOR > 3) ||                                         \
    (PIN_PRODUCT_VERSION_MAJOR == 3 && PIN_PRODUCT_VERSION_MINOR > 7) ||       \
    (PIN_PRODUCT_VERSION_MAJOR == 3 && PIN_PRODUCT_VERSION_MINOR == 7 &&       \
     PIN_BUILD_NUMBER > 97720)
#define INS_DIRECT INS_DirectControlFlowTargetAddress
#define INS_IS_DIRECT INS_IsDirectControlFlow
#define INS_IS_INDIRECT INS_IsIndirectControlFlow
#define INS_HAS_TAKEN_BRANCH INS_IsValidForIpointTakenBranch
#define INS_HAS_IPOINT_AFTER INS_IsValidForIpointAfter
#else
#define INS_DIRECT INS_DirectBranchOrCallTargetAddress
#define INS_IS_DIRECT INS_IsDirectBranchOrCall
#define INS_IS_INDIRECT INS_IsIndirectBranchOrCall
#define INS_HAS_TAKEN_BRANCH INS_IsBranchOrCall
#define INS_HAS_IPOINT_AFTER INS_HasFallThrough
#endif

using namespace std;

/***********************************************************************/

VOID RecordFunctionEntry(THREADID threadid, ADDRINT bbl, ADDRINT bp,
                         BOOL indirect, ADDRINT target, const CONTEXT *ctxt,
                         bool report_as_cfleak);
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

KNOB<string> KnobHeapData(KNOB_MODE_WRITEONCE, "pintool", "heapData", "",
                          "Output file for storing heap related information.");

KNOB<string> Knoblogaddr(KNOB_MODE_WRITEONCE, "pintool", "logaddr", "",
                         "Output file for storing the logical address of the "
                         "Instrumented instructions.");

KNOB<string> Knoballocmap(KNOB_MODE_WRITEONCE, "pintool", "allocmap", "",
                          "Output file for Realloc invariance.");

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
#define DEBUG(x) if (KnobDebug.Value() >= x)
#define MESSAGE(x, y) std::cout << x << y << std::endl

#define PT_DEBUG(x, msg) DEBUG(x) MESSAGE("[pt-dbg" << x << "] ", msg)
#define PT_INFO(msg) MESSAGE("[pt-info] ", msg)
#define PT_WARN(msg) MESSAGE("[pt-warn] ", msg)
#define PT_ASSERT(x, msg)                                                      \
    {                                                                          \
        if (!(x)) {                                                            \
            MESSAGE("[pt-error] ", msg);                                       \
            ASSERT(false, "pintool failed.");                                  \
        }                                                                      \
    }
#define PT_ERROR(msg) PT_ASSERT(false, msg)

int alloc_instrumented = 0;

/* When using '-main ALL', ensures recording starts at function call */
bool WaitForFirstFunction = false;
bool Record = false;
bool use_callstack = false;

/* Store the latest accessed SYSCALL */
int syscall_number = -1;

/**
 * Traces are stored in a binary format, containing a sequence of
 * entry_t entries.
 */
typedef struct __attribute__((packed)) {
    uint8_t type; /* holds values of entry_type_t */
    void *ip;     /* instruction pointer */
    void *data;   /* additional data, depending on type */
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

    MASK_HEAP = 8,
    /* Instructions doing memory reads/writes on heap objects */
    HREAD = MASK_HEAP | READ,
    HWRITE = MASK_HEAP | WRITE,
    /* Heap alloc/free calls */
    HALLOC = MASK_HEAP | C,
    HFREE = MASK_HEAP | D,

    MASK_LEAK = 16,
    /* Dataleaks and Controlflow leaks, used for fast recording */
    DLEAK = MASK_LEAK | A,
    CFLEAK = MASK_LEAK | B,
};

std::vector<entry_t> trace; /* Contains all traced instructions */
ofstream imgfile;           /* Holds memory layout with function symbols */
ofstream heapfile;          /* Holds heap information */
ofstream logaddrfile;       /* Holds heap information */
ofstream allocmapfile;      /* Holds Realloc invariance information */
ofstream vdsofile;          /* Holds vdso shared library */

/***********************************************************************/
/* Image tracking*/
typedef struct {
    string name;
    uint64_t baseaddr;
    uint64_t endaddr;
    string hash;
} imgobj_t;

typedef std::vector<imgobj_t> IMGVEC;
IMGVEC imgvec;

/* Image to function mapping*/
typedef struct {
    string name;
    uint64_t baseaddr;
    uint64_t endaddr;
    string funcname;
} funcobj_t;

typedef std::vector<funcobj_t> FUNCVEC;
FUNCVEC funcvec;

/***********************************************************************/
/* Heap tracking */

typedef struct {
    uint32_t id;
    char const *type;
    size_t size;
    uint64_t base;
    ADDRINT callsite;
    std::string callstack;
    std::string hash;
} memobj_t;

uint32_t nextheapid = 1;
typedef std::vector<memobj_t> HEAPVEC;
HEAPVEC heap;

std::unordered_map<std::string, std::vector<string>> hashmap;
std::unordered_map<uint64_t, std::vector<string>> allocmap;

imgobj_t heaprange;

int writecount = 0;

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

int pid = PIN_GetPid();

/***********************************************************************/
/* Multithreading */

/* Global lock to protect trace buffer */
// PIN_MUTEX lock;

typedef struct {
    char const *type;
    ADDRINT addr;
} free_state_t;

typedef struct {
    char const *type;
    ADDRINT size;
    ADDRINT callsite;
    std::string callstack;
} alloc_state_t;

typedef struct {
    char const *type;
    ADDRINT old;
    ADDRINT size;
    ADDRINT callsite;
    std::string callstack;
} realloc_state_t;

typedef struct {
    /* allocation routines sometimes call themselves in a nested way during
     * initialization */
    std::vector<free_state_t> free_state;
    std::vector<alloc_state_t> malloc_state;
    std::vector<alloc_state_t> calloc_state;
    std::vector<realloc_state_t> realloc_state;
    std::vector<alloc_state_t> mmap_state;
    std::vector<realloc_state_t> mremap_state;
    ADDRINT RetIP;
    int newbbl;
} thread_state_t;

std::vector<thread_state_t> thread_state;

/***********************************************************************/
/**Calculating the Logical Address from the Virtual Address
 * Every Logical Address is 64 bit = 32 bit MemoryIndex + 32 bit Offset*/
/***********************************************************************/

void printheap() {
    if (heap.size() == 0) {
        return;
    }
    PT_INFO("heap: ");
    for (HEAPVEC::iterator it = heap.begin(); it != heap.end(); ++it) {
        std::cout << std::setw(3) << std::hex << it->id << ":" << it->base
                  << "-" << it->size << std::endl;
    }
}

uint64_t getIndex(string hash) {
    uint64_t to_shift;
    sscanf(hash.c_str(), "%llx", (long long unsigned int *)&to_shift);
    /*std::cout << "shifted hash is " << (to_shift<<32) << std::endl;*/
    return (to_shift << 32);
}

VOID print_proc_map(VOID) {
    std::stringstream command_string;
    command_string << "cat /proc/" << pid << "/maps";
    const std::string to_pass(command_string.str());
    PT_INFO("print_proc_map with " << to_pass.c_str());

    FILE *fp;
    char buffer[64];
    const char *arg = to_pass.c_str();
    fp = popen(arg, "r");
    if (!fp) {
        PT_ERROR("command failed");
        return;
    }
    if (fp != NULL) {
        while (fgets(buffer, 64, fp) != NULL) {
            std::cout << buffer;
        }
        pclose(fp);
    }
}

ADDRINT execute_commands(const std::string command, short pos,
                         const std::string opt_command) {
    std::stringstream command_string;
    command_string << "cat /proc/" << pid << "/maps | grep '" << command
                   << "' | awk '{print $1}' | cut -f" << pos << " -d-"
                   << opt_command;
    const std::string to_pass(command_string.str());
    PT_DEBUG(1, "execute_commands " << to_pass.c_str());

    FILE *fp;
    char buffer[64];
    const char *arg = to_pass.c_str();
    fp = popen(arg, "r");
    if (!fp) {
        PT_ERROR("command failed");
        return 0;
    }
    if (fp != NULL) {
        while (fgets(buffer, 64, fp) != NULL) {
            pclose(fp);
        }
    }
    PT_DEBUG(3, " buf is " << buffer);
    std::string tmp = "0x" + (std::string)buffer;
    PT_DEBUG(3, " tmp is " << tmp);
    PT_DEBUG(3, " func is " << std::hex << strtol(tmp.c_str(), NULL, 0));

    return ((ADDRINT)strtol(tmp.c_str(), NULL, 0));
}

void *getLogicalAddress(void *virt_addr, void *ip) {
    PT_DEBUG(2, "get log_addr for virt_addr of " << virt_addr);

    if (virt_addr == nullptr) {
        // TODO assert false?
        PT_ERROR("dereferenced a nullptr");
        return nullptr;
    }
    // Is the Virtual Address in the Heap address space?
    /* Set heap start and end markers */
    if (heap.size() &&
        (heaprange.baseaddr != heap.front().base ||
         heaprange.endaddr != heap.back().base + heap.back().size)) {
        heaprange.baseaddr = heap.front().base;
        heaprange.endaddr = heap.back().base + heap.back().size;
        PT_DEBUG(2, "heap.baseaddr: " << heaprange.baseaddr);
        PT_DEBUG(2, "heap.endaddr: " << heaprange.endaddr);
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
            log_addr =
                (uint64_t *)(getIndex(allocmap[i.base].front()) | offset);
            logaddrfile << setw(25) << "HEAP"
                        << " " << setw(25) << (uint64_t)virt_addr << " "
                        << setw(25) << log_addr << " " << std::endl;
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
    DEBUG(1) printheap();
    DEBUG(2) print_proc_map();
    return virt_addr;
}

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
        PT_ASSERT(ip, "IP not set");
        DEBUG(1)
        printf("[pt-info] DLEAK@%" PRIx64 ": %" PRIx64 " appended\n", ip, d);
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
        PT_ASSERT(!res, "Unable to write file");
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
        PT_ASSERT(bp, "BP not set");
        DEBUG(1)
        printf("[pt-info] CFLEAK@%" PRIx64 ": %" PRIx64 " appended\n", bp, ip);
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
        PT_ASSERT(!res, "Unable to write file");
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
        PT_ASSERT(!res, "Unable to write file");
        Context::doexport(f);
        for (children_t::iterator it = children.begin(); it != children.end();
             it++) {
            it->second->doexport(f);
        }
        type = FUNC_EXIT;
        res = fwrite(&type, sizeof(type), 1, f) != 1;
        PT_ASSERT(!res, "Unable to write file");
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
        PT_ASSERT(currentContext, "Context not initialized");
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
        PT_ASSERT(currentContext, "Context not initialized");
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
        PT_ASSERT(currentContext, "Context not initialized");
        DEBUG(1) printf("[pintool] Consuming DLEAK %" PRIx64 "\n", ip);
        currentContext->dleak_append(ip, data);
    }

    /**
     * Record evidence for a control-flow leak
     * @param bbl The basic block which contains the cf-leak
     * @param target The taken branch target (the evidence)
     */
    virtual void cfleak_consume(uint64_t bbl, uint64_t target) {
        PT_ASSERT(currentContext, "Context not initialized");
        DEBUG(1) printf("[pintool] Consuming CFLEAK %" PRIx64 "\n", bbl);
        currentContext->cfleak_append(bbl, target);
    }

    virtual void print_all() = 0;

    /**
     * Export evidence to binary format
     * @param f The file to export to
     */
    virtual void doexport(FILE *f) {
        PT_ASSERT(currentContext, "Context not initialized");
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
        PT_ASSERT(use_callstack, "Wrong usage of callstack");
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
        PT_ASSERT(use_callstack, "Wrong usage of callstack");
        PT_ASSERT(currentContext, "Callstack is not initialized");
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
        PT_ASSERT(use_callstack, "Wrong usage of callstack");
        PT_ASSERT(currentContext, "Callstack is not initialized");
        DEBUG(2) printf("[pintool] Returning %" PRIx64 "\n", ip);
        CallContext *top = static_cast<CallContext *>(currentContext);
        if (top->unknown_child_depth) {
            top->unknown_child_depth--;
        } else {
            if (top->parent) {
                PT_ASSERT(top->parent, "Callstack parent is empty");
                currentContext = top = top->parent;
            } else {
                DEBUG(2) printf("[pintool] Warning: Ignoring return\n");
            }
        }
    }

    void ret_create(uint64_t ip) { ret_consume(ip); }

    bool empty() {
        PT_ASSERT(use_callstack, "Wrong usage of callstack");
        CallContext *top = static_cast<CallContext *>(currentContext);
        return top == NULL || top->used == false;
    }

    CallContext *get_begin() {
        PT_ASSERT(use_callstack, "Wrong usage of callstack");
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
        PT_ASSERT(use_callstack, "Wrong usage of callstack");
        CallContext *top = get_begin();
        PT_ASSERT(top, "Leaks not initialized");
        top->used = false;
        currentContext = top;
    }

    void print_all() {
        PT_ASSERT(use_callstack, "Wrong usage of callstack");
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
    // PT_ASSERT(PIN_MutexInit(&lock), "Mutex init failed");
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
 * @param target UNUSED
 */
VOID RecordMainBegin(THREADID threadid, ADDRINT ins, ADDRINT target,
                     const CONTEXT *ctxt) {
    PIN_LockClient();
    Record = true;
    DEBUG(1)
    printf("Start main() %x to %x\n", (unsigned int)ins, (unsigned int)target);
    RecordFunctionEntry(threadid, 0, 0, false, ins, ctxt, false);
    PIN_UnlockClient();
}

/**
 * Stop recording.
 * @param threadid The thread
 * @param ins The last recorded instruction
 */
VOID RecordMainEnd(THREADID threadid, ADDRINT ins) {
    PIN_LockClient();
    Record = false;
    DEBUG(1) printf("[pintool] End main()\n");
    RecordFunctionExit(threadid, ins, ins, NULL, false);
    PIN_UnlockClient();
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
    PT_ASSERT(threadid == 0, "Multithreading detected but not supported!");
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
    PT_ASSERT(thread_state.size() > threadid, "thread_state corrupted");
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
/** Heap recording                                                     */
/***********************************************************************/

/**
 * calculate sha1-hash and use the 4 bytes of the hash as the memory Index
 */
void calculate_sha1_hash(memobj_t *obj) {
    std::stringstream to_hash(obj->type, ios_base::app | ios_base::out);
    to_hash << obj->size << obj->callsite << obj->callstack;

    SHA1 hash;
    if (hashmap.count(to_hash.str())) {
        hash.update(hashmap[to_hash.str()].back());
    } else {
        hash.update(to_hash.str());
    }
    obj->hash = hash.final();
    hashmap[to_hash.str()].push_back(obj->hash);

    DEBUG(1) {
        PT_DEBUG(1, "HashMap for    " << to_hash.str());
        for (auto &i : hashmap[to_hash.str()]) {
            PT_DEBUG(1, "HashMap Value: " << i);
        }
    }
}

/**
 * gets the call stack and converts every IP Virtual address to it's new
 * representation identified uniquely by its image name and offset to address
 * ASLR All the new IPs are then added to form a unique value per call stack
 * which is used later in the calculate_sha1_hash function
 */

void print_callstack(THREADID threadid) {
    auto mngr = CALLSTACK::CallStackManager::get_instance();
    auto cs = mngr->get_stack(threadid);
    std::vector<string> out;
    CALLSTACK::IPVEC ipvec;
    cs.emit_stack(cs.depth(), out, ipvec);
    for (uint32_t i = 0; i < out.size(); i++) {
        std::cout << out[i];
    }
}

std::string getcallstack(THREADID threadid) {
    auto mngr = CALLSTACK::CallStackManager::get_instance();
    auto cs = mngr->get_stack(threadid);
    std::vector<string> out;
    CALLSTACK::IPVEC ipvec;
    cs.emit_stack(cs.depth(), out, ipvec);
    DEBUG(2) for (uint32_t i = 0; i < out.size(); i++) {
        DEBUG(2) std::cout << out[i];
    }
    std::stringstream unique_cs(ios_base::app | ios_base::out);

    for (auto i : ipvec) {
        string path = i.name;
        size_t imgpos = path.find_last_of("/\\");
        string imgname = path.substr(imgpos + 1);
        size_t pos = imgname.find_last_of(":");
        string name = imgname.substr(0, pos);
        for (auto j : imgvec) {
            if (name == (j.name)) {
                unique_cs << i.ipaddr - j.baseaddr;
                PT_DEBUG(1, name << " " << j.baseaddr << " " << unique_cs.str()
                                 << " " << i.ipaddr);
            }
        }
    }
    return unique_cs.str();
}

ADDRINT get_callsite_offset(ADDRINT callsite) {
    for (auto i : imgvec) {
        if (callsite >= i.baseaddr && callsite <= i.endaddr) {
            return callsite - i.baseaddr;
        }
    }
    PT_WARN("callsite does not belong to image space?");
    PT_WARN("callsite " << std::hex << callsite);
    return 0;
}

/**
 * Handle calls to [m|re|c]alloc by keeping a list of all heap objects
 * This function is not thread-safe. Lock first.
 */
void doalloc(ADDRINT addr, ADDRINT size, uint32_t objid, ADDRINT callsite,
             char const *type, std::string callstack, ADDRINT old_ptr) {
    PT_DEBUG(1,
             "doalloc " << std::hex << addr << " " << size << " type " << type);

    memobj_t obj;
    obj.id = (objid) ? objid : nextheapid++;
    obj.base = addr;
    obj.size = size;
    obj.callsite = callsite;
    obj.type = type;
    obj.callstack = callstack;
    calculate_sha1_hash(&obj);

    if (old_ptr && old_ptr != addr) {
        if (!allocmap.count(old_ptr)) {
            PT_ASSERT(false, "doalloc has a valid old_ptr, but no elements!");
        }
        for (auto item : allocmap[old_ptr]) {
            allocmap[addr].push_back(item);
        }
        allocmap.erase(old_ptr);
    }
    allocmap[addr].push_back(obj.hash.substr(32, 8));

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
        /* Insert in front, if below is of type MMAP and spans over obj */
        (below->type == std::string(MMAP)) && (obj.base >= below->base) &&
        (obj.base + obj.size <= below->base + below->size)) {
        heap.insert(below, obj);
    } else {
        /* Invalid inbetween slot found, thus quit */
        printheap();
        PT_INFO("below.base " << below->base);
        PT_INFO("above.base " << above->base);
        PT_INFO("obj.base   " << obj.base);
        PT_INFO("obj.size   " << obj.size);
        PT_ASSERT(false, "Corrupted heap?!");
    }
    /* Print the current obj into the heapfile */
    heapfile << setw(15) << obj.type << " " << setw(15) << obj.size << " "
             << setw(15) << obj.callsite << " " << setw(15) << obj.callstack
             << " " << setw(15) << obj.hash.substr(32, 8) << ":" << obj.size
             << " " << std::endl;
}

/**
 * Handle calls to free by maintaining a list of all heap objects
 * This function is not thread-safe. Lock first.
 */
uint32_t dofree(ADDRINT addr) {
    PT_DEBUG(1, "dofree 0x" << std::hex << addr);
    if (!addr) {
        return 0;
    }
    for (HEAPVEC::iterator it = heap.begin(); it != heap.end(); ++it) {
        if (it->base != addr) {
            continue;
        }
        heap.erase(it);
        return it->id;
    }
    printheap();
    std::stringstream unique_cs(ios_base::app | ios_base::out);
    PT_ASSERT(false, "Invalid free!");
    return 0;
}

/**
 * Record malloc
 * @param threadid The thread
 * @param size The size parameter passed to malloc
 */
VOID RecordMallocBefore(THREADID threadid, VOID *ip, ADDRINT size) {
    PT_DEBUG(1, "malloc called with 0x" << std::hex << size << " at " << ip);
    if (!Record)
        return;
    // PIN_MutexLock(&lock);
    if (thread_state[threadid].realloc_state.size() == 0) {
        SHA1 hash;
        hash.update(getcallstack(threadid)); /* calculte the hash of the set of
                                                IPs in the Callstack */
        alloc_state_t state = {
            .type = "malloc",
            .size = size,
            .callsite = 0,
            .callstack = hash.final().substr(28, 12), /* 6 byte SHA1 hash */
        };
        thread_state[threadid].malloc_state.push_back(state);
    } else {
        PT_DEBUG(1, "Malloc ignored due to realloc_pending (size= "
                        << std::hex << size << ") at " << ip);
    }
    // PIN_MutexUnlock(&lock);
}

/**
 * Record malloc's result
 * @param threadid The thread
 * @param addr The allocated heap pointer
 */
VOID RecordMallocAfter(THREADID threadid, VOID *ip, ADDRINT addr) {
    PT_DEBUG(1, "Malloc returned " << std::hex << addr);
    if (!Record)
        return;
    // PIN_MutexLock(&lock);
    PT_ASSERT(thread_state[threadid].malloc_state.size() > 0,
              "Malloc returned but not called");
    alloc_state_t state = thread_state[threadid].malloc_state.back();
    thread_state[threadid].malloc_state.pop_back();
    doalloc((ADDRINT)addr, state.size, 0, state.callsite, state.type,
            state.callstack, 0);
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
    PT_DEBUG(1, "Realloc called with " << std::hex << addr << " " << size
                                       << " at " << ip);
    if (!Record)
        return;
    // PIN_MutexLock(&lock);
    SHA1 hash;
    hash.update(getcallstack(
        threadid)); /* calculte the hash of the set of IPs in the Callstack */
    realloc_state_t state = {
        .type = "realloc",
        .old = addr,
        .size = size,
        .callsite = 0,
        .callstack = hash.final().substr(28, 12), /* 6 byte SHA1 hash */
    };
    thread_state[threadid].realloc_state.push_back(state);
    // PIN_MutexUnlock(&lock);
}

/**
 * Record realloc's result
 * @param threadid The thread
 * @param addr The allocated heap pointer
 */
VOID RecordReallocAfter(THREADID threadid, VOID *ip, ADDRINT addr) {
    PT_DEBUG(1, "Realloc returned " << std::hex << addr << " at " << ip);
    if (!Record)
        return;
    // PIN_MutexLock(&lock);
    PT_ASSERT(thread_state[threadid].realloc_state.size() > 0,
              "Realloc returned but not called");
    realloc_state_t state = thread_state[threadid].realloc_state.back();
    thread_state[threadid].realloc_state.pop_back();

    uint32_t objid = 0;
    if (state.old) {
        objid = dofree(state.old);
    }
    doalloc((ADDRINT)addr, state.size, objid, state.callsite, state.type,
            state.callstack, state.old);
    // PIN_MutexUnlock(&lock);
}

/**
 * Record calloc
 * @param threadid The thread
 * @param nelem The number of elements parameter passed to calloc
 * @param size The size parameter passed to calloc
 */
VOID RecordCallocBefore(CHAR *name, THREADID threadid, ADDRINT nelem,
                        ADDRINT size, ADDRINT ret) {
    PT_DEBUG(1, "Calloc called with " << std::hex << nelem << " " << size);
    if (!Record)
        return;
    //  PIN_MutexLock(&lock);
    if (thread_state[threadid].calloc_state.size() == 0) {
        SHA1 hash;
        hash.update(getcallstack(threadid)); /* calculate the hash of the set of
                                                IPs in the Callstack */
        alloc_state_t state = {
            .type = name,
            .size = nelem * size,
            .callsite = get_callsite_offset(ret),
            .callstack = hash.final().substr(28, 12), /* 6 byte SHA1 hash */
        };

        thread_state[threadid].calloc_state.push_back(state);
    }
    //  PIN_MutexUnlock(&lock);
}

/**
 * Record calloc's result
 * @param threadid The thread
 * @param addr The allocated heap pointer
 */
VOID RecordCallocAfter(THREADID threadid, ADDRINT addr, ADDRINT ret) {
    PT_DEBUG(1, "calloc returned " << std::hex << addr);
    if (!Record) {
        PT_DEBUG(1, "ignoring");
        return;
    }
    // PIN_MutexLock(&lock);
    PT_ASSERT(thread_state[threadid].calloc_state.size() != 0,
              "calloc returned but not called");
    alloc_state_t state = thread_state[threadid].calloc_state.back();
    thread_state[threadid].calloc_state.pop_back();
    doalloc(addr, state.size, 0, state.callsite, state.type, state.callstack,
            0);
    //  PIN_MutexUnlock(&lock);
}

/**
 * Record free
 * @param threadid The thread
 * @param addr The heap pointer which is freed
 */
VOID RecordFreeBefore(THREADID threadid, VOID *ip, ADDRINT addr) {
    if (!Record)
        return;
    // PIN_MutexLock(&lock);
    PT_DEBUG(1, "free called with " << std::hex << addr << " at " << ip);
    free_state_t state = {
        .type = "free",
        .addr = addr,
    };
    thread_state[threadid].free_state.push_back(state);
    // PIN_MutexUnlock(&lock);
}

/**
 * Record free
 * @param threadid The thread
 * @param addr The heap pointer which is freed
 */
VOID RecordFreeAfter(THREADID threadid, VOID *ip) {
    if (!Record)
        return;
    // PIN_MutexLock(&lock);
    PT_ASSERT(thread_state[threadid].free_state.size() != 0,
              "free returned but not called");
    free_state_t state = thread_state[threadid].free_state.back();
    thread_state[threadid].free_state.pop_back();
    dofree(state.addr);
    // PIN_MutexUnlock(&lock);
}

/**
 * Record munmap
 * @param threadid The thread
 * @param addr The heap pointer which is munmapped
 */
VOID RecordmunmapBefore(THREADID threadid, ADDRINT addr, ADDRINT len,
                        bool force) {
    PT_DEBUG(1, "munmap called with " << std::hex << addr << "*" << len);
    DEBUG(2) print_callstack(threadid);
    if (!Record && !force)
        return;
    // PIN_MutexLock(&lock);
    dofree(addr);
    //  PIN_MutexUnlock(&lock);
}
/**
 * Record mmap
 * @param threadid      thread
 * @param size          size parameter passed to mmap
 * @param ret           TODO
 * @param force
 */
VOID RecordmmapBefore(CHAR *name, THREADID threadid, ADDRINT size, ADDRINT ret,
                      bool force) {
    PT_DEBUG(1, "mmap called with " << std::hex << size);
    if (!Record && !force)
        return;
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
    hash.update(getcallstack(threadid)); /* calculate the hash of the set of
                                            IPs in the Callstack */
    alloc_state_t state = {
        .type = name,
        .size = size,
        .callsite = get_callsite_offset(ret),
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
VOID RecordmmapAfter(THREADID threadid, ADDRINT addr, ADDRINT ret, bool force) {
    PT_DEBUG(1, "mmap returned " << std::hex << addr);
    if (!Record && !force)
        return;
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

    doalloc(addr, state.size, 0, state.callsite, state.type, state.callstack,
            0);

    //  PIN_MutexUnlock(&lock);
}

/**
 * Record mremap
 * @param threadid The thread
 * @param addr The heap pointer param of mremap
 * @param size The size parameter passed to mremap
 */
VOID RecordmremapBefore(CHAR *name, THREADID threadid, ADDRINT addr,
                        ADDRINT old_size, ADDRINT new_size, ADDRINT ret) {
    PT_DEBUG(1, "mremap called with " << std::hex << addr << " " << new_size);
    if (!Record)
        return;
    // PIN_MutexLock(&lock);

    SHA1 hash;
    hash.update(getcallstack(
        threadid)); /* calculte the hash of the set of IPs in the Callstack */
    realloc_state_t state = {
        .type = name,
        .old = addr,
        .size = new_size,
        .callsite = get_callsite_offset(ret),
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
VOID RecordmremapAfter(THREADID threadid, ADDRINT addr, ADDRINT ret) {
    PT_DEBUG(1, "mremap returned " << std::hex << addr);
    if (!Record)
        return;
    // PIN_MutexLock(&lock);
    PT_ASSERT(thread_state[threadid].mremap_state.size() != 0,
              "mremap returned but not called");

    realloc_state_t state = thread_state[threadid].mremap_state.back();
    thread_state[threadid].mremap_state.pop_back();

    uint32_t objid = 0;
    if (state.old) {
        objid = dofree(state.old);
    }
    doalloc(addr, state.size, objid, state.callsite, state.type,
            state.callstack, 0);
    //  PIN_MutexUnlock(&lock);
}

/**
 * Record brk's call
 *@param threadid The thread
 * @param addr The returned program break end address
 */
VOID RecordBrkBefore(THREADID threadid, ADDRINT addr, bool force) {
    PT_DEBUG(1, "brk called with " << std::hex << addr);
    if (!Record && !force)
        return;
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
VOID RecordBrkAfter(THREADID threadid, ADDRINT addr, ADDRINT ret, bool force) {
    PT_DEBUG(1, "brk returned from " << std::hex << ret << " with " << std::hex
                                     << addr);
    if (!Record && !force)
        return;
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

std::ofstream outFile;

// Holds instruction count for a single procedure
typedef struct RtnCount {
    string _name;
    string _image;
    ADDRINT _address;
    RTN _rtn;
    UINT64 _rtnCount;
    UINT64 _icount;
    struct RtnCount *_next;
} RTN_COUNT;

// Linked list of instruction counts for each routine
RTN_COUNT *RtnList = 0;

// This function is called before every instruction is executed
VOID docount(UINT64 *counter) { (*counter)++; }

const char *StripPath(const char *path) {
    const char *file = strrchr(path, '/');
    if (file)
        return file + 1;
    else
        return path;
}

// Pin calls this function every time a new rtn is executed
VOID Routine(RTN rtn, VOID *v) {

    // Allocate a counter for this routine
    RTN_COUNT *rc = new RTN_COUNT;

    // The RTN goes away when the image is unloaded, so save it now
    // because we need it in the fini
    rc->_name = RTN_Name(rtn);
    rc->_image = StripPath(IMG_Name(SEC_Img(RTN_Sec(rtn))).c_str());
    rc->_address = RTN_Address(rtn);
    rc->_icount = 0;
    rc->_rtnCount = 0;

    // Add to list of routines
    rc->_next = RtnList;
    RtnList = rc;

    RTN_Open(rtn);

    // Insert a call at the entry point of a routine to increment the call count
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR,
                   &(rc->_rtnCount), IARG_END);

    // For each instruction of the routine
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
        // Insert a call to docount to increment the instruction counter for
        // this rtn
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR,
                       &(rc->_icount), IARG_END);
    }

    RTN_Close(rtn);
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
VOID RecordMemRead(THREADID threadid, VOID *ip, VOID *addr, bool fast_recording,
                   const CONTEXT *ctxt) {
    if (!Record)
        return;
    PT_DEBUG(2, "ip in memread is   " << (uint64_t)ip);
    // PIN_MutexLock(&lock);
    entry_t entry;
    entry.type = READ;
    entry.ip = ip;
    entry.data = getLogicalAddress(addr, ip);
    DEBUG(3)
    printf("Read %llx to %llx\n", (long long unsigned int)entry.ip,
           (long long unsigned int)entry.data);
    if (fast_recording) {
        leaks->dleak_consume((uint64_t)entry.ip, (uint64_t)entry.data);
    } else {
        record_entry(entry);
    }
    //  PIN_MutexUnlock(&lock);
}

/**
 * Record memory writes.
 * @param threadid The thread
 * @param ip The instruction issuing write
 * @param addr The data address being written
 * @param fast_recording For fast recording
 */
VOID RecordMemWrite(THREADID threadid, VOID *ip, VOID *addr,
                    bool fast_recording, const CONTEXT *ctxt) {
    if (!Record)
        return;
    // PIN_MutexLock(&lock);
    entry_t entry;
    entry.type = WRITE;
    ADDRINT target =
        ctxt != NULL ? (ADDRINT)PIN_GetContextReg(ctxt, REG_STACK_PTR) : 0;
    PT_DEBUG(4, " TOP from WRITE is " << target);
    PT_DEBUG(2, "ip in memwrite is   " << (uint64_t)ip);
    entry.ip = ip;
    entry.data = getLogicalAddress(addr, ip);
    DEBUG(3)
    printf("Write %llx to %llx\n", (long long unsigned int)entry.ip,
           (long long unsigned int)entry.data);
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
VOID RecordBranch_unlocked(THREADID threadid, ADDRINT ins, ADDRINT target,
                           const CONTEXT *ctxt) {
    if (!Record)
        return;
    entry_t entry;
    entry.type = BRANCH;
    entry.ip = (void *)ins;
    entry.data = (void *)target;
    record_entry(entry);
    PT_DEBUG(4, "Branch entry");
    PT_DEBUG(4, "ip \t" << std::hex << entry.ip);
    PT_DEBUG(4, "data \t" << std::hex << entry.data);
    PT_DEBUG(4, "ins \t" << std::hex << ins);
    PT_DEBUG(4, "target \t" << std::hex << target);
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
    //  PIN_MutexLock(&lock);
    ADDRINT target = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    PT_DEBUG(3, "Branch " << std::hex << bp << " to " << target);
    PT_DEBUG(3, "fast_recording " << fast_recording);
    RecordBranch_unlocked(threadid, bp, target, ctxt);
    if (fast_recording) {
        auto ix = (void *)bp;
        uint64_t *li = static_cast<uint64_t *>(ix);
        uint64_t b = (uint64_t)li;
        auto id = (void *)target;
        uint64_t *ld = static_cast<uint64_t *>(id);
        uint64_t t = (uint64_t)ld;
        leaks->cfleak_consume(b, t);
    }
    //  PIN_MutexUnlock(&lock);
}

#if 0
/**
 * Record conditional branch due to REP-prefix. 
 * @param threadid The thread
 * @param bbl The basic block containing the branch
 * @param bp The branching instruction
 * @param ctxt The CPU context of bp
 * @param fast_recording For fast recording
 */
VOID RecordRep(THREADID threadid, ADDRINT bbl, ADDRINT bp, const CONTEXT * ctxt, bool fast_recording)
{
  //PIN_MutexLock(&lock);
  ADDRINT target = (ADDRINT)PIN_GetContextReg( ctxt, REG_INST_PTR );
  DEBUG(3) std::cout << "[pintool] REP-branch " << std::hex << bp << " to " << target << std::endl;
  RecordBranch_unlocked(threadid, bp, target);
  if (fast_recording) {
    leaks->cfleak_consume(bp, target);
  }
  //PIN_MutexUnlock(&lock);
}
#endif

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
                                  ADDRINT target, const CONTEXT *ctxt) {
    if (!Record)
        return;
    entry_t entry;
    entry.type = FUNC_ENTRY;
    entry.ip = (void *)ins;
    if (entry.ip == nullptr) {
        entry.ip = (void *)ins;
    }
    entry.data = (void *)target;
    PT_DEBUG(3, "Call " << std::hex << ins << " to " << target);
    // leaks->call_consume(ins, target);
    leaks->call_consume((uint64_t)entry.ip, (uint64_t)entry.data);
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
                         BOOL indirect, ADDRINT target, const CONTEXT *ctxt,
                         bool fast_recording) {
    if (WaitForFirstFunction) {
        Record = true;
        WaitForFirstFunction = false;
    }
    if (!Record)
        return;
    //  PIN_MutexLock(&lock);
    if (indirect) {
        PT_DEBUG(2, "Icall to  " << std::hex << target);
    }
    if (KnobFunc.Value()) {
        RecordFunctionEntry_unlocked(threadid, ins, indirect, target, ctxt);
    }
    if (fast_recording) {
        auto ix = (void *)ins;
        uint64_t *li = static_cast<uint64_t *>(ix);
        uint64_t i = (uint64_t)li;
        auto id = (void *)target;
        uint64_t *ld = static_cast<uint64_t *>(id);
        uint64_t t = (uint64_t)ld;
        leaks->cfleak_consume(i, t);
    }
    //  PIN_MutexUnlock(&lock);
}

/**
 * Record ret instructions.
 * This function is not thread-safe! Lock first.
 *
 * @param threadid The thread
 * @param ins The ret instruction
 * @param target The instruction to continue after ret
 */
VOID RecordFunctionExit_unlocked(THREADID threadid, ADDRINT ins, ADDRINT target,
                                 const CONTEXT *ctxt) {
    if (!Record)
        return;
    entry_t entry;
    entry.type = FUNC_EXIT;
    PT_DEBUG(4, " TOP from func EXIT is "
                    << PIN_GetContextReg(ctxt, REG_STACK_PTR));
    entry.ip = (void *)ins;
    entry.data = (void *)target;
    PT_DEBUG(2, "Ret " << std::hex << ins << " to " << target);
    // leaks->ret_consume(ins);
    leaks->ret_consume((uint64_t)entry.ip);
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
    if (!Record)
        return;
    ADDRINT target =
        ctxt != NULL ? (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR) : 0;
    //  PIN_MutexLock(&lock);
    if (KnobFunc.Value()) {
        RecordFunctionExit_unlocked(threadid, ins, target, ctxt);
    }
    if (fast_recording) {
        auto ix = (void *)ins;
        uint64_t *li = static_cast<uint64_t *>(ix);
        uint64_t i = (uint64_t)li;
        auto id = (void *)target;
        uint64_t *ld = static_cast<uint64_t *>(id);
        uint64_t t = (uint64_t)ld;
        leaks->cfleak_consume(i, t);
    }
    //  PIN_MutexUnlock(&lock);
}

/***********************************************************************/
/** Instrumentation Code                                               */
/***********************************************************************/

VOID Image(IMG img, VOID *v) {}

/**
 * Instruments program entry and exit as well as heap functions of libc.
 * @param img The loaded image
 * @param v UNUSED
 */
VOID instrumentMainAndAlloc(IMG img, VOID *v) {
    // TODO
    string name = IMG_Name(img);
    PT_DEBUG(1, "Instrumenting " << name);
    if (imgfile.is_open()) {
        uint64_t high = IMG_HighAddress(img);
        uint64_t low = IMG_LowAddress(img);

        if (vdsofile.is_open() && IMG_IsVDSO(img)) {
            /* For VDSO, the HighAddress does not point to end of ELF file,
             * leading to a truncated ELF file. We over-approximate the ELF size
             * with IMG_SizeMapped instead.
             */
            high = low + IMG_SizeMapped(img);
            PT_DEBUG(1, "vdso low:   0x" << std::hex << low);
            PT_DEBUG(1, "vdso high:  0x" << std::hex << high);
            PT_DEBUG(1, "vdso size mapped:  0x" << std::hex
                                                << IMG_SizeMapped(img));
            vdsofile.write((const char *)low, IMG_SizeMapped(img));
            vdsofile.close();
            name = KnobVDSO.Value();
        }

        PT_DEBUG(1, "image name: " << name);
        PT_DEBUG(1, "image low:  0x " << std::hex << low);
        PT_DEBUG(1, "image high: 0x " << std::hex << high);
        imgfile << "Image:" << std::endl;
        imgfile << name << std::endl;
        imgfile << std::hex << low << ":" << high << std::endl;

        imgobj_t imgdata;
        imgdata.name = name;
        imgdata.baseaddr = low;
        imgdata.endaddr = high;

        SHA1 hash;
        hash.update(imgdata.name);
        imgdata.hash = hash.final().substr(32, 8);

        imgvec.push_back(imgdata);

        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
            string sec_name = SEC_Name(sec);
            low = SEC_Address(sec);
            high = SEC_Address(sec) + SEC_Size(sec);

            PT_DEBUG(1, "sec name: " << sec_name);
            PT_DEBUG(1, "sec low:  0x " << std::hex << low);
            PT_DEBUG(1, "sec high: 0x " << std::hex << high);
            if (!SEC_Mapped(sec)) {
                PT_INFO("unmapped sec dropped: " << sec_name);
                continue;
            }

            imgobj_t imgdata;
            imgdata.name = sec_name;
            imgdata.baseaddr = low;
            imgdata.endaddr = high;

            SHA1 hash;
            hash.update(imgdata.name);
            imgdata.hash = hash.final().substr(32, 8);

            imgvec.push_back(imgdata);
        }
    }

    if (IMG_Valid(img)) {
        if (imgfile.is_open()) {
            for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym);
                 sym = SYM_Next(sym)) {
                imgfile << std::hex << SYM_Address(sym)
                        << ":" + PIN_UndecorateSymbolName(
                                     SYM_Name(sym), UNDECORATION_NAME_ONLY)
                        << std::endl;
            }
        }
        PT_DEBUG(1, "KnobMain: " << KnobMain.Value());
        if (KnobMain.Value().compare("ALL") != 0) {
            RTN mainRtn = RTN_FindByName(img, KnobMain.Value().c_str());
            if (mainRtn.is_valid()) {
                PT_DEBUG(1, "KnobMain is valid");
                RTN_Open(mainRtn);
                RTN_InsertCall(mainRtn, IPOINT_BEFORE, (AFUNPTR)RecordMainBegin,
                               IARG_THREAD_ID, IARG_ADDRINT,
                               RTN_Address(mainRtn), IARG_END, IARG_CONTEXT,
                               IARG_END);
                RTN_InsertCall(mainRtn, IPOINT_AFTER, (AFUNPTR)RecordMainEnd,
                               IARG_THREAD_ID, IARG_ADDRINT,
                               RTN_Address(mainRtn), IARG_END);
                RTN_Close(mainRtn);
            }
        } else {
            PT_DEBUG(1, "Recording all");
            if (!Record) {
                WaitForFirstFunction = true;
            }
        }

        if (name.find("alloc.so") != std::string::npos ||
            name.find("libc.so") != std::string::npos) {
            /* If alloc.so is pre-loaded, it will always be before libc
             * We only instrument once
             */
            if (alloc_instrumented) {
                PT_DEBUG(1, "Allocation already instrumented");
            } else {
                PT_DEBUG(1, "Instrumenting allocation");
                if (KnobTrackHeap.Value()) {
                    RTN mallocRtn = RTN_FindByName(img, MALLOC);
                    if (mallocRtn.is_valid()) {
                        PT_DEBUG(1, "malloc found in " << IMG_Name(img));
                        RTN_Open(mallocRtn);
                        RTN_InsertCall(mallocRtn, IPOINT_BEFORE,
                                       (AFUNPTR)RecordMallocBefore,
                                       IARG_THREAD_ID, IARG_INST_PTR,
                                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                       IARG_END);
                        RTN_InsertCall(mallocRtn, IPOINT_AFTER,
                                       (AFUNPTR)RecordMallocAfter,
                                       IARG_THREAD_ID, IARG_INST_PTR,
                                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
                        RTN_Close(mallocRtn);
                    }

                    RTN reallocRtn = RTN_FindByName(img, REALLOC);
                    if (reallocRtn.is_valid()) {
                        PT_DEBUG(1, "realloc found in " << IMG_Name(img));
                        RTN_Open(reallocRtn);
                        RTN_InsertCall(
                            reallocRtn, IPOINT_BEFORE,
                            (AFUNPTR)RecordReallocBefore, IARG_THREAD_ID,
                            IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
                        RTN_InsertCall(reallocRtn, IPOINT_AFTER,
                                       (AFUNPTR)RecordReallocAfter,
                                       IARG_THREAD_ID, IARG_INST_PTR,
                                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
                        RTN_Close(reallocRtn);
                    }

                    RTN callocRtn = RTN_FindByName(img, CALLOC);
                    if (callocRtn.is_valid()) {
                        PT_DEBUG(1, "Calloc found in " << IMG_Name(img));
                        RTN_Open(callocRtn);
                        RTN_InsertCall(callocRtn, IPOINT_BEFORE,
                                       (AFUNPTR)RecordCallocBefore,
                                       IARG_ADDRINT, CALLOC, IARG_THREAD_ID,
                                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                       IARG_RETURN_IP, IARG_END);
                        RTN_InsertCall(
                            callocRtn, IPOINT_AFTER, (AFUNPTR)RecordCallocAfter,
                            IARG_THREAD_ID, IARG_FUNCRET_EXITPOINT_VALUE,
                            IARG_RETURN_IP, IARG_END);
                        PT_DEBUG(1, "after Calloc insert ");
                        RTN_Close(callocRtn);
                    }

                    RTN freeRtn = RTN_FindByName(img, FREE);
                    if (freeRtn.is_valid()) {
                        PT_DEBUG(1, "free found in " << IMG_Name(img));
                        RTN_Open(freeRtn);
                        RTN_InsertCall(
                            freeRtn, IPOINT_BEFORE, (AFUNPTR)RecordFreeBefore,
                            IARG_THREAD_ID, IARG_INST_PTR,
                            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
                        RTN_InsertCall(freeRtn, IPOINT_AFTER,
                                       (AFUNPTR)RecordFreeAfter, IARG_THREAD_ID,
                                       IARG_INST_PTR, IARG_END);
                        RTN_Close(freeRtn);
                    }

                    RTN mmapRtn = RTN_FindByName(img, MMAP);
                    if (mmapRtn.is_valid()) {
                        PT_DEBUG(1, "mmap found in " << IMG_Name(img));
                        RTN_Open(mmapRtn);
                        RTN_InsertCall(
                            mmapRtn, IPOINT_BEFORE, (AFUNPTR)RecordmmapBefore,
                            IARG_ADDRINT, MMAP, IARG_THREAD_ID,
                            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_RETURN_IP,
                            IARG_BOOL, false, IARG_END);
                        RTN_InsertCall(
                            mmapRtn, IPOINT_AFTER, (AFUNPTR)RecordmmapAfter,
                            IARG_THREAD_ID, IARG_FUNCRET_EXITPOINT_VALUE,
                            IARG_RETURN_IP, IARG_BOOL, false, IARG_END);
                        RTN_Close(mmapRtn);
                    }

                    RTN mremapRtn = RTN_FindByName(img, MREMAP);
                    if (mremapRtn.is_valid()) {
                        PT_DEBUG(1, "mremap found in " << IMG_Name(img));
                        RTN_Open(mremapRtn);
                        RTN_InsertCall(mremapRtn, IPOINT_BEFORE,
                                       (AFUNPTR)RecordmremapBefore,
                                       IARG_ADDRINT, MREMAP, IARG_THREAD_ID,
                                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                       IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                       IARG_RETURN_IP, IARG_END);
                        RTN_InsertCall(
                            mremapRtn, IPOINT_AFTER, (AFUNPTR)RecordmremapAfter,
                            IARG_THREAD_ID, IARG_FUNCRET_EXITPOINT_VALUE,
                            IARG_RETURN_IP, IARG_END);
                        RTN_Close(mremapRtn);
                    }

                    RTN munmapRtn = RTN_FindByName(img, MUNMAP);
                    if (munmapRtn.is_valid()) {
                        RTN_Open(munmapRtn);
                        RTN_InsertCall(munmapRtn, IPOINT_BEFORE,
                                       (AFUNPTR)RecordmunmapBefore,
                                       IARG_THREAD_ID,
                                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                       IARG_BOOL, false, IARG_END);
                        RTN_Close(munmapRtn);
                    }

                    RTN brkRtn = RTN_FindByName(img, BRK);
                    if (brkRtn.is_valid()) {
                        PT_DEBUG(1, "brk found in " << IMG_Name(img));
                        RTN_Open(brkRtn);
                        RTN_InsertCall(brkRtn, IPOINT_BEFORE,
                                       (AFUNPTR)RecordBrkBefore, IARG_THREAD_ID,
                                       IARG_BOOL, false, IARG_END);
                        RTN_InsertCall(
                            brkRtn, IPOINT_AFTER, (AFUNPTR)RecordBrkAfter,
                            IARG_THREAD_ID, IARG_FUNCRET_EXITPOINT_VALUE,
                            IARG_RETURN_IP, IARG_BOOL, false, IARG_END);
                        RTN_Close(brkRtn);
                    }
                }
                alloc_instrumented = 1;
            }
        } /* alloc.so or libc */
    }
}

//////// TEST
// Print syscall number and arguments
VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1,
               ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5) {
#if defined(TARGET_LINUX) && defined(TARGET_IA32)
    // On ia32 Linux, there are only 5 registers for passing system call
    // arguments, but mmap needs 6. For mmap on ia32, the first argument to the
    // system call is a pointer to an array of the 6 arguments
    if (num == SYS_mmap) {
        ADDRINT *mmapArgs = reinterpret_cast<ADDRINT *>(arg0);
        arg0 = mmapArgs[0];
        arg1 = mmapArgs[1];
        arg2 = mmapArgs[2];
        arg3 = mmapArgs[3];
        arg4 = mmapArgs[4];
        arg5 = mmapArgs[5];
    }
#endif

    PT_INFO("syscall " << std::hex << ip << " " << std::hex << num << " "
                       << std::hex << arg0 << " " << std::hex << arg1 << " "
                       << std::hex << arg2 << " " << std::hex << arg3 << " "
                       << std::hex << arg4 << " " << std::hex << arg5);
}

// Print the return value of the system call
VOID SysAfter(ADDRINT ret) { PT_INFO("returns: " << std::hex << ret); }

VOID SyscallEntry(THREADID threadid, CONTEXT *ctxt, SYSCALL_STANDARD std,
                  VOID *v) {
    syscall_number = PIN_GetSyscallNumber(ctxt, std);
    SysBefore(PIN_GetContextReg(ctxt, REG_INST_PTR), syscall_number,
              PIN_GetSyscallArgument(ctxt, std, 0),
              PIN_GetSyscallArgument(ctxt, std, 1),
              PIN_GetSyscallArgument(ctxt, std, 2),
              PIN_GetSyscallArgument(ctxt, std, 3),
              PIN_GetSyscallArgument(ctxt, std, 4),
              PIN_GetSyscallArgument(ctxt, std, 5));

    // https://filippo.io/linux-syscall-table/
    switch (syscall_number) {
    case 9:
        if (PIN_GetSyscallArgument(ctxt, std, 0)) {
            PT_INFO("Dropped syscall.");
            syscall_number = -1;
            break;
        }
        PT_INFO("mmap syscall.");
        RecordmmapBefore((char *)MMAP, threadid,
                         PIN_GetSyscallArgument(ctxt, std, 1),
                         PIN_GetContextReg(ctxt, REG_INST_PTR), true);
        break;
    case 11:
        PT_INFO("munmap syscall.");
        RecordmunmapBefore(threadid, PIN_GetSyscallArgument(ctxt, std, 0),
                           PIN_GetSyscallArgument(ctxt, std, 1), true);
        break;
    case 12:
        PT_INFO("brk syscall.");
        RecordBrkBefore(threadid, PIN_GetSyscallArgument(ctxt, std, 0), true);
        break;
    default:
        syscall_number = -1;
        PT_INFO("Syscall not catched. syscall number: "
                << PIN_GetSyscallNumber(ctxt, std));
        break;
    }
}

VOID SyscallExit(THREADID threadid, CONTEXT *ctxt, SYSCALL_STANDARD std,
                 VOID *v) {
    SysAfter(PIN_GetSyscallReturn(ctxt, std));

    // https://filippo.io/linux-syscall-table/
    switch (syscall_number) {
    case -1:
        // Syscall will be dropped, as its number is set to -1 in SyscallEntry
        break;
    case 9:
        RecordmmapAfter(threadid, PIN_GetSyscallReturn(ctxt, std),
                        PIN_GetContextReg(ctxt, REG_INST_PTR), true);
        break;
    case 11:
        break;
    case 12:
        PT_INFO("brk syscall returned.");
        RecordBrkAfter(threadid, PIN_GetSyscallReturn(ctxt, std),
                       PIN_GetContextReg(ctxt, REG_INST_PTR), true);
        break;
    default:
        PT_ERROR("syscall unknown. syscall number: " << syscall_number);
        PT_ASSERT(false, "syscall");
        break;
    }
    syscall_number = -1;
}
//////// TEST

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
        /* convert this Virtual IP to corresponding Memory Index here */
        DEBUG(2) printf("Adding %lx to instrumentation\n", ip);

        for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
            if (INS_MemoryOperandIsRead(ins, memOp)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                               IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYOP_EA,
                               memOp, IARG_BOOL, fast_recording, IARG_CONTEXT,
                               IARG_END);
                found = true;
            }
            if (INS_MemoryOperandIsWritten(ins, memOp)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                               IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYOP_EA,
                               memOp, IARG_BOOL, fast_recording, IARG_CONTEXT,
                               IARG_END);
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
VOID instrumentCallBranch(INS bbl, INS bp, bool fast_recording) {
    if (INS_IsCall(bp)) {
        if (KnobFunc.Value() || KnobBbl.Value()) {
            INS_InsertCall(bp, IPOINT_BEFORE, AFUNPTR(RecordFunctionEntry),
                           IARG_THREAD_ID, IARG_ADDRINT, INS_Address(bbl),
                           IARG_ADDRINT, INS_Address(bp), IARG_BOOL,
                           INS_IS_INDIRECT(bp), IARG_BRANCH_TARGET_ADDR,
                           IARG_CONTEXT, IARG_BOOL, fast_recording, IARG_END);
        }
    } else if (INS_IsRet(bp)) {
        /* RET would be also detected as branch, therefore we use 'else if' */
        if (KnobFunc.Value() || KnobBbl.Value()) {
            INS_InsertCall(bp, IPOINT_TAKEN_BRANCH, AFUNPTR(RecordFunctionExit),
                           IARG_THREAD_ID, IARG_ADDRINT, INS_Address(bbl),
                           IARG_ADDRINT, INS_Address(bp), IARG_CONTEXT,
                           IARG_BOOL, fast_recording, IARG_END);
        }
    } else if (INS_IsBranch(bp)) {
        if (KnobBbl.Value()) {
            if (INS_Opcode(bp) == XED_ICLASS_XEND) {
                PT_DEBUG(1, "Ignoring XEND");
            } else {
                /* unconditional jumps */
                INS_InsertCall(bp, IPOINT_TAKEN_BRANCH, AFUNPTR(RecordBranch),
                               IARG_THREAD_ID, IARG_ADDRINT, INS_Address(bbl),
                               IARG_ADDRINT, INS_Address(bp), IARG_CONTEXT,
                               IARG_BOOL, fast_recording, IARG_END);
            }

            if (INS_HasFallThrough(bp)) {
                /* conditional/indirect jumps */
                INS_InsertCall(bp, IPOINT_AFTER, AFUNPTR(RecordBranch),
                               IARG_THREAD_ID, IARG_ADDRINT, INS_Address(bbl),
                               IARG_ADDRINT, INS_Address(bp), IARG_CONTEXT,
                               IARG_BOOL, fast_recording, IARG_END);
            }
        }
    }
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

    auto ix = (void *)ip;
    uint64_t *la = static_cast<uint64_t *>(ix);
    // std::cout << la << " la is " << std::endl;
    uint64_t l = (uint64_t)la;
    static int count;
    DEBUG(3)
    printf("leaking instruction  %x with count  %d \n", (unsigned int)ip,
           count);
    count++;

    if (leaks->get_erase_dleak(l) || leaks->was_erased_dleak(l)) {
        /* Instrument dataleaking instruction */
        DEBUG(1) printf("[pintool] Tracing DLEAK %lx\n", (long unsigned int)ip);
        bool found = instrumentMemIns(ins, true);
        PT_ASSERT(found, "Memory instruction to instument not found. "
                         "Have you provided the flag -mem?");
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
            PT_ASSERT(INS_HAS_TAKEN_BRANCH(ins),
                      "Return instruction should support taken "
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

    if (leaks->get_erase_cfleak(l) || leaks->was_erased_cfleak(l)) {
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
            if (INS_HAS_TAKEN_BRANCH(bp)) {
                DEBUG(2)
                printf("[pintool] Found bp %lx\n",
                       (long unsigned int)INS_Address(bp));
                /* We instrument the actual branch point (bp) but report leaks
                 * with respect to the BBL (ins)
                 */
                instrumentCallBranch(ins, bp, true);
                found = true;
                break;
            }
            bp = INS_Next(bp);
        }
        PT_ASSERT(found, "Instruction to instument not found");
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
    PT_ASSERT(f, "Leak file does not exist");
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    DEBUG(1)
    printf("[pintool] Reading leaks from %s, size %ld bytes\n",
           KnobLeakIn.Value().c_str(), len);
    PT_ASSERT(leaks, "Leaks not initialized");
    while (ftell(f) < len) {
        leakfmt_t elem;
        PT_ASSERT(fread(&elem, sizeof(elem), 1, f) == 1,
                  "Failed reading leak file");
        uint64_t callee = 0;
        DEBUG(1)
        printf("[pintool] Loading leak element %x, %" PRIx64 ", %d\n",
               elem.type, elem.ip, elem.nopt);
        switch (elem.type) {
        case FUNC_ENTRY:
            PT_ASSERT(elem.nopt == 1, "Trace format corrupt");
            PT_ASSERT(fread(&callee, sizeof(callee), 1, f) == 1,
                      "Failed reading leak file");
            if (KnobCallstack.Value()) {
                leaks->call_create(elem.ip, callee);
            }
            DEBUG(1) printf("[pintool] Func entry %" PRIx64 "\n", callee);
            break;
        case FUNC_EXIT:
            PT_ASSERT(fseek(f, elem.nopt * sizeof(uint64_t), SEEK_CUR) == 0,
                      "Failed reading leak file");
            if (KnobCallstack.Value()) {
                leaks->ret_create(elem.ip);
            }
            DEBUG(1) printf("[pintool] Func exit\n");
            break;
        case DLEAK:
            PT_ASSERT(elem.nopt == 0, "Trace format corrupt");
            leaks->dleak_create(elem.ip);
            DEBUG(1) printf("[pintool] Adding Dleak: %" PRIx64 "\n", elem.ip);
            break;
        case CFLEAK:
            PT_ASSERT(elem.nopt > 0, "Trace format corrupt");
            PT_ASSERT(fseek(f, elem.nopt * sizeof(uint64_t), SEEK_CUR) == 0,
                      "Failed reading leak file");
            leaks->cfleak_create(elem.ip, NULL, 0);
            DEBUG(1) printf("[pintool] Adding CFleak: %" PRIx64 "\n", elem.ip);
            break;
        default:
            PT_ASSERT(false, "Invalid leak type");
        }
    }
    PT_ASSERT(ftell(f) == len, "Trace format corrupt");
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
                PT_ERROR("Unable to open file " << KnobRawFile.Value());
            } else {
                PT_INFO("Writing raw results to " << KnobRawFile.Value());
                bool res;
                res = fwrite(&trace[0], sizeof(entry_t), trace.size(),
                             ftrace) == trace.size();
                fclose(ftrace);
                PT_ASSERT(res, "Unable to write complete trace file. Out "
                               "of disk memory?");
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
            PT_ASSERT(!KnobLeakIn.Value().empty(), "leakout requires leakin");
            PT_ASSERT(leaks, "Leaks not initialized");
            FILE *fleaks = fopen(KnobLeakOut.Value().c_str(), "w");
            if (!fleaks) {
                PT_ERROR("Unable to open file " << KnobLeakOut.Value());
            } else {
                PT_INFO("Writing leak results to " << KnobLeakOut.Value());
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

    if (heapfile.is_open()) {
        heapfile.close();
    }

    if (logaddrfile.is_open()) {
        logaddrfile.close();
    }

    outFile << setw(23) << "Procedure"
            << " " << setw(15) << "Image"
            << " " << setw(18) << "Address"
            << " " << setw(12) << "Calls"
            << " " << setw(12) << "Instructions" << endl;

    for (RTN_COUNT *rc = RtnList; rc; rc = rc->_next) {
        if (rc->_icount > 0)
            outFile << setw(23) << rc->_name << " " << setw(15) << rc->_image
                    << " " << setw(18) << hex << rc->_address << dec << " "
                    << setw(12) << rc->_rtnCount << " " << setw(12)
                    << rc->_icount << endl;
    }
    for (auto j : allocmap) {
        for (auto i : j.second) {
            allocmapfile << i << " ";
        }
        allocmapfile << std::endl;
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
    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, 0);

    if (!KnobHeapData.Value().empty()) {
        heapfile.open(KnobHeapData.Value().c_str());
        heapfile << hex;
        heapfile.setf(ios::showbase);
        heapfile << setw(15) << "TYPE"
                 << " " << setw(15) << "SIZE"
                 << " " << setw(15) << "Callsite"
                 << " " << setw(15) << "Callstack"
                 << " " << setw(15) << "Memory Index"
                 << "\n"
                 << endl;
    }

    if (!Knoblogaddr.Value().empty()) {
        logaddrfile.open(Knoblogaddr.Value().c_str());
        logaddrfile << hex;
        logaddrfile.setf(ios::showbase);
        logaddrfile << setw(25) << "Segment"
                    << " " << setw(25) << "Instrumented Address"
                    << " " << setw(35) << "Logical Address"
                    << "\n"
                    << endl;
    }

    if (!Knoballocmap.Value().empty()) {
        allocmapfile.open(Knoballocmap.Value().c_str());
        allocmapfile << hex;
        allocmapfile.setf(ios::showbase);
        allocmapfile << setw(25) << "Return address"
                     << " " << setw(35) << "alloc map"
                     << "\n"
                     << endl;
    }

    if (!KnobLeaks.Value()) {
        /* Traditional tracing */
        if (KnobBbl.Value() || KnobMem.Value() || KnobFunc.Value()) {
            INS_AddInstrumentFunction(instrumentAnyInstructions, 0);
            PIN_AddSyscallEntryFunction(SyscallEntry, 0);
            PIN_AddSyscallExitFunction(SyscallExit, 0);
        }
    } else {
        /* Tracing only leaks specified by leak file */
        PT_DEBUG(1, "[pintool] Tracing leaks");
        /* calling loadLeaks via PIN_AddApplicationStartFunction.
         * This ensures the program under instrumentation is already completely
         * loaded before loadLeaks is called, thus preserving the order (and
         * thus the memory layout) in which shared libraries are loaded.
         */
        PIN_AddApplicationStartFunction(loadLeaks, 0);
        INS_AddInstrumentFunction(instrumentLeakingInstructions, 0);
    }

    /* Getting the stack, heap and vvar address range for this process */
    stack.baseaddr = execute_commands("stack", 1, " ");
    stack.endaddr = execute_commands("stack", 2, " ");
    PT_DEBUG(1, "stackBaseAddr is " << std::hex << stack.baseaddr);
    PT_DEBUG(1, "stackEndAddr  is " << std::hex << stack.endaddr);

    imgobj_t imgdata;
    imgdata.name = "vvar";
    SHA1 hash;
    hash.update(imgdata.name);
    imgdata.hash = hash.final().substr(32, 8);

    imgdata.baseaddr = execute_commands("vvar", 1, " ");
    imgdata.endaddr = execute_commands("vvar", 2, " ");
    PT_DEBUG(1, "vvarBaseAddr is " << std::hex << imgdata.baseaddr);
    PT_DEBUG(1, "vvarEndAddr  is " << std::hex << imgdata.endaddr);

    imgvec.push_back(imgdata);

    imgobj_t imgdataUnknown;
    imgdataUnknown.name = "unknown1";
    SHA1 hashUnknown;
    hashUnknown.update(imgdataUnknown.name);
    imgdataUnknown.hash = hashUnknown.final().substr(32, 8);

    imgdataUnknown.baseaddr = execute_commands("-B 1 stack", 1, "| head -n 1");
    PT_DEBUG(1, "Unknown1 is " << std::hex << imgdataUnknown.baseaddr);

    imgdataUnknown.endaddr = execute_commands("-B 1 stack", 2, "| head -n 1");
    PT_DEBUG(1, "Unknown1 is " << std::hex << imgdataUnknown.endaddr);

    imgvec.push_back(imgdataUnknown);

    auto mngr = CALLSTACK::CallStackManager::get_instance();
    mngr->activate();

    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    PIN_AddFiniFunction(Fini, 0);

    init();
    PIN_StartProgram();

    return 0;
}
