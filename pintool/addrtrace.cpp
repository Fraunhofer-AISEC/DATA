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
#define DEBUG(x) if (KnobDebug.Value() >= x)

int alloc_instrumented = 0;

/* When using '-main ALL', ensures recording starts at function call */
bool WaitForFirstFunction = false;
bool Record = false;
bool use_callstack = false;

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
/* Heap tracking */

typedef struct {
    uint32_t id;
    char const *type;
    size_t size;
    uint64_t base;
    ADDRINT callsite;
    std::string callstack;
    std::string hash;
    bool used;
} memobj_t;

uint32_t nextheapid = 1;
memobj_t *heapcache;
typedef std::vector<memobj_t> HEAPVEC;
HEAPVEC heap;

std::unordered_map<std::string, std::vector<string>> hashmap;
std::unordered_map<uint64_t, std::vector<string>> allocmap;

ADDRINT heapBaseAddr;
ADDRINT heapEndAddr;
string heapBaseAddr_hash;

int writecount = 0;

/***********************************************************************/
/* Image tracking*/
typedef struct {
    string name;
    uint64_t baseaddr;
    uint64_t endaddr;
    uint32_t startaddr;
    string imghash;
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
/* Stack tracking*/
ADDRINT stackBaseAddr; // Base address of the stack is calculated at Threadstart
ADDRINT stackEndAddr;  // Base address of the stack is calculated at Threadstart
string stackBaseAddr_hash; // hash of the stackBaseAddr

int pid = PIN_GetPid();
/***********************************************************************/
/* Map for Book keeping between Virtual Address <----------> Logical Address*/
std::unordered_map<uint64_t, uint64_t>
    addressMap; // Virtual Address is  the Key , Logical Address is the Value
std::unordered_map<uint64_t, uint64_t>
    conversionMap; // Logical Address is  the Key , Virtual Address is the Value

/***********************************************************************/
/* Multithreading */

/* Global lock to protect trace buffer */
// PIN_MUTEX lock;

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

uint64_t getIndex(string hash) {
    uint64_t to_shift;
    sscanf(hash.c_str(), "%llx", (long long unsigned int *)&to_shift);
    /*std::cout << "shifted hash is " << (to_shift<<32) << std::endl;*/
    return (to_shift << 32);
}

ADDRINT execute_commands(const std::string command, short pos,
                         const std::string opt_command) {
    std::stringstream command_string;
    command_string << "cat /proc/" << pid << "/maps | grep " << command
                   << " | awk '{print $1}' | cut -f" << pos << " -d-"
                   << opt_command;
    std::cout << command_string.str() << " command is " << std::endl;
    const std::string to_pass(command_string.str());
    std::cout << to_pass.c_str() << std::endl;

    FILE *fp;
    char buffer[64];
    const char *arg = to_pass.c_str();
    fp = popen(arg, "r");
    if (!fp) {
        std::cout << " ERROR executing command " << std::endl;
        return 0;
    }
    if (fp != NULL) {
        while (fgets(buffer, 64, fp) != NULL) {
            pclose(fp);
        }
    }
    std::cout << " buf is " << buffer << std::endl;
    std::string tmp = "0x" + (std::string)buffer;
    std::cout << " tmp is " << tmp << std::endl;
    std::cout << " func is " << std::hex << strtol(tmp.c_str(), NULL, 0)
              << std::endl;

    return ((ADDRINT)strtol(tmp.c_str(), NULL, 0));
}

void *getLogicalAddress(void *ip) {
    // std::cout << "Converting Virtual IP:     " << (uint64_t)ip  <<std::endl;
    uint64_t *la = static_cast<uint64_t *>(ip);
    if (ip == nullptr) {
        std::cout << " ERROR: dereferenced a nullptr " << std::endl;
        // assert
        return nullptr;
    }

    // is the Virtual Address in the IMG/Code address space?
    for (auto i : imgvec) {
        if ((uint64_t)ip >= i.baseaddr && (uint64_t)ip <= i.endaddr) {
            logaddrfile << setw(25) << "IMG/Code"
                        << " " << setw(25) << (uint64_t)ip << " ";
            la =
                (uint64_t *)(getIndex(i.imghash) | ((uint64_t)ip - i.baseaddr));
            // std::cout<<"returned la is " << la <<std::endl;
            logaddrfile << setw(25) << la << " " << std::endl;
            /*	if (addressMap.count((uint64_t)ip)) {
                                          //assert? Same instruction
               instrumented angain? } else { addressMap.insert({(uint64_t) ip,
               (uint64_t) la}); conversionMap.insert({(uint64_t) la, (uint64_t)
               ip});
                          }*/
            /*		for (auto i : funcvec) {
                                    if ((uint64_t)ip >= i.baseaddr &&
               (uint64_t)ip <= i.endaddr) { std::cout<< " IP missed is " <<
               (uint64_t)ip << " Image name is " << i.name << " Function is " <<
               i.funcname<<std::endl; logaddrfile << setw(25) << "IMG/Code" << "
               " << setw(25) << (uint64_t)ip << " "; la = (uint64_t *)
               (getIndex(i.imghash) | ((uint64_t)ip - i.baseaddr)); logaddrfile
               << setw(25) << la << " " << std::endl;
                                    }
                            }*/
            return la;
        }
    }

    // is the Virtual Address in the Heap object address space?
    for (auto i : heap) {
        if (((uint64_t)ip >= i.base && (uint64_t)ip <= (i.base + i.size)) ||
            ((uint64_t)ip <= i.base && (uint64_t)ip >= (i.base - i.size))) {
            logaddrfile << setw(25) << "HEAP"
                        << " " << setw(25) << (uint64_t)ip << " ";
            // la  = (uint64_t *) (getIndex(i.hash) | ((uint64_t)ip - i.base));
            la = (uint64_t *)(getIndex(i.hash.substr(32, 8)) |
                              std::labs(i.base - (uint64_t)ip));
            std::cout << " heap hash " << (uint64_t)la << std::endl;
            logaddrfile << setw(25) << la << " " << std::endl;
            if (addressMap.count((uint64_t)ip)) {
                // assert? Same instruction instrumented angain?
            } else {
                addressMap.insert({(uint64_t)ip, (uint64_t)la});
                conversionMap.insert({(uint64_t)la, (uint64_t)ip});
            }

            return la;
        }
    }

    // is the Virtual Address in the Stack address space?
    if ((uint64_t)ip <= stackBaseAddr && (uint64_t)ip >= stackEndAddr) {
        logaddrfile << setw(25) << "Stack"
                    << " " << setw(25) << (uint64_t)ip << " ";
        la = (uint64_t *)(getIndex(stackBaseAddr_hash) |
                          (stackBaseAddr - (uint64_t)ip));
        // std::cout << " converted log addr for stack is  " << (uint64_t)la <<
        // std::endl;
        logaddrfile << setw(25) << la << " " << std::endl;
        if (addressMap.count((uint64_t)ip)) {
            // assert? Same instruction instrumented angain?
        } else {
            addressMap.insert({(uint64_t)ip, (uint64_t)la});
            conversionMap.insert({(uint64_t)la, (uint64_t)ip});
        }
        return la;
    }

    // is the Virtual Address in the Heap address space
    // but does not belong to any heap object already tracked?
    if ((uint64_t)ip >= heapBaseAddr && (uint64_t)ip <= heapEndAddr) {
        la = (uint64_t *)(getIndex(heapBaseAddr_hash) |
                          ((uint64_t)ip - heapBaseAddr));
        return la;
    }

    std::cout << "classification error with inst " << (uint64_t)ip << std::endl;
    /*	for (auto i : funcvec) {
                    if ((uint64_t)ip >= i.baseaddr && (uint64_t)ip <= i.endaddr)
       { std::cout<< "Missed IP is " << (uint64_t)ip << "Image name is " <<
       i.name << "Function is " << i.funcname<<std::endl;
                    }
            }*/
    return ip;
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
    ASSERT(threadid == 0,
           "[pintool] Error: Multithreading detected but not supported!");
    DEBUG(1) printf("[pintool] Thread begin %d\n", threadid);
    // PIN_MutexLock(&lock);

    std::string to_hash_stack = "STACKSSPACE";
    SHA1 hash_stack;
    hash_stack.update(to_hash_stack);
    stackBaseAddr_hash = hash_stack.final().substr(32, 8);

    std::string to_hash_heap = "HEAPSPACE";
    SHA1 hash_heap;
    hash_heap.update(to_hash_heap);
    stackBaseAddr_hash = hash_heap.final().substr(32, 8);

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
/** Heap recording                                                     */
/***********************************************************************/

void printheap() {
    std::cout << "[pintool] Heap:" << std::endl;
    for (HEAPVEC::iterator it = heap.begin(); it != heap.end(); ++it) {
        std::cout << std::hex << it->id << ":" << it->base << "-" << it->size
                  << " used:" << it->used << std::endl;
    }
}

memobj_t *lookup_heap(VOID *addr) {
    uintptr_t paddr = (uintptr_t)addr;
    if (heapcache) {
        ASSERT(heapcache->used, "[pintool] Error: Heapcache corrupt");
        if (paddr >= heapcache->base &&
            paddr < heapcache->base + heapcache->size) {
            return heapcache;
        }
    }

    for (HEAPVEC::reverse_iterator it = heap.rbegin(); it != heap.rend();
         ++it) {
        if (!it->used) {
            continue;
        }
        if (paddr >= it->base) {
            if (paddr < it->base + it->size) {
                return heapcache = &(*it);
            } else {
                break;
            }
        }
    }
    return NULL;
}

VOID test_mem_heap(entry_t *pentry) {
    memobj_t *obj = lookup_heap(pentry->data);
    if (obj) {
        uint64_t pdata = (uint64_t)pentry->data;
        pdata -= obj->base;
        ASSERT((pdata & 0xFFFFFFFF00000000ULL) == 0,
               "[pintool] Error: Heap object too big");
        pdata |= (uint64_t)obj->id << 32ULL;
        pentry->data = (void *)pdata;
        pentry->type |= MASK_HEAP;
    }
}

/**
 * calculate sha1-hash and use the 4 bytes of the hash as the memory Index
 */
void calculate_sha1_hash(memobj_t *obj) {
    std::stringstream to_hash(obj->type, ios_base::app | ios_base::out);
    to_hash << obj->size << obj->callsite << obj->callstack;
    std::cout << to_hash.str() << std::endl;
    SHA1 hash;
    hash.update(to_hash.str());
    obj->hash = hash.final();
    std::cout << "hash of heap is " << obj->hash << std::endl;
    if (hashmap.count(to_hash.str())) {
        hash.update(hashmap[to_hash.str()].back());
        hashmap[to_hash.str()].push_back(hash.final());
        obj->hash = hashmap[to_hash.str()].back();
        for (auto &i : hashmap[to_hash.str()]) {
            std::cout << "Val for the colliding key is " << i << std::endl;
        }
    } else {
        hashmap[to_hash.str()].push_back(obj->hash);
    }
}

/**
 * gets the call stack and converts every IP Virtual address to it's new
 * representation identified uniquely by its image name and offset to address
 * ASLR All the new IPs are then added to form a unique value per call stack
 * which is used later in the calculate_sha1_hash function
 */

std::string getcallstack(THREADID threadid) {
    auto mngr = CALLSTACK::CallStackManager::get_instance();
    auto cs = mngr->get_stack(threadid);
    std::vector<string> out;
    CALLSTACK::IPVEC ipvec;
    cs.emit_stack(cs.depth(), out, ipvec);
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
                std::cout << name << " " << j.baseaddr << " " << unique_cs.str()
                          << " " << i.ipaddr << std::endl;
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
    std::cout << "Error: callsite does not belong to image space?" << std::endl;
    return 0;
}

/**
 * Handle calls to [m|re|c]alloc by keeping a list of all heap objects
 * This function is not thread-safe. Lock first.
 */
void doalloc(ADDRINT addr, ADDRINT size, uint32_t objid, ADDRINT callsite,
             char const *type, std::string callstack, ADDRINT old_ptr) {
    heapcache = NULL;
    bool insert = true;
    memobj_t obj;
    if (objid) {
        obj.id = objid;
    } else {
        obj.id = nextheapid++;
    }

    obj.base = addr;
    obj.size = size;
    obj.used = true;
    obj.callsite = callsite;
    obj.type = type;
    obj.callstack = callstack;
    calculate_sha1_hash(&obj);
    /*if (allocmap.count(addr)) {
      hash.update(allocmap[to_hash.str()].back());
      allocmap[to_hash.str()].push_back(hash.final());
      obj->hash = allocmap[to_hash.str()].back();
      for (auto &i : allocmap[to_hash.str()]) {
        std::cout <<"Val for the colliding key is " << std::endl;
     // }
    } else {*/
    if (!old_ptr) {
        allocmap[addr].push_back(obj.hash.substr(32, 8));
    }
    if (old_ptr) {
        if (allocmap.count(old_ptr)) {
            auto val = allocmap[old_ptr];
            allocmap.erase(old_ptr);
            for (auto i : val) {
                allocmap[addr].push_back(i);
            }
            allocmap[addr].push_back(obj.hash.substr(32, 8));
        } else {
            allocmap[addr].push_back(obj.hash.substr(32, 8));
        }
    }

    /*		allocmapfile << setw(25) << addr << " " << setw(25);
                    auto var = allocmap[addr];
                    for (auto i : var) {
                                            allocmapfile << i << " ";
                    }
                    allocmapfile << std::endl;
      //}*/
    /*for ( auto it : allocmap) {
            allocmapfile << setw(25) << it.first << " " << setw(25);
            for (auto i : it.second) {
                                    allocmapfile << i << " ";
            }
            allocmapfile << std::endl;
    }*/

    DEBUG(0)
    std::cout << "doalloc " << std::hex << addr << " " << size << std::endl;
    /* Keep heap vector sorted */
    HEAPVEC::iterator prev = heap.begin();
    HEAPVEC::iterator found = heap.end();
    for (HEAPVEC::iterator it = heap.begin(); it != heap.end(); ++it) {
        if (it->used) {

            if (abs(int(obj.base - it->base)) == 16) {
                /* duplicate found, don't insert current object*/
                std::cout << "duplicate found " << std::endl;
                DEBUG(0) printheap();
                *it = obj;
                DEBUG(0) printheap();

                insert = false;
                break;
            }
            if (it->base >= obj.base) {
                /* insert before*/
                DEBUG(0) std::cout << "obj.type " << obj.type << std::endl;
                if (obj.base + obj.size > it->base) {
                    DEBUG(0) printheap();
                    ASSERT(false, "[Error] Corrupted heap?!");
                }
                found = it;
                break;
            }
        }
        prev = it;
    }
    if (insert) {
        if (found == heap.end()) {
            /* no match found, append to the end */
            heap.push_back(obj);
        } else {
            if (prev == heap.begin() || prev->used) {
                /* We cannot reuse prev, insert at 'prev' */
                if (prev != found && prev->used &&
                    prev->base + prev->size > obj.base) {
                    /* malloc/calloc/realloc has internally called mmap/mremap,
                     * don't assert mark the previous object if it was of type
                     * mmap/mremap and if the base address difference is 16 */
                    if (prev != found && prev->used &&
                        (abs(int(obj.base - prev->base) == 16)) &&
                        ((strcmp(prev->type, "mmap") == 0) ||
                         (strcmp(prev->type, "mremap") == 0))) {
                        /* erase the entry to avoid duplication? but freeing is
                         * a problem*/
                        std::cout << "type is" << prev->type << std::endl;
                        /*heap.erase(prev);
                          --found;*/
                    } else {
                        DEBUG(2) printheap();
                        ASSERT(false, "[Error] Corrupted heap?!");
                    }
                }
                heap.insert(found, obj);
            } else {
                /* prev is unused, reuse it */
                *prev = obj;
            }
        }
    }
    /* print the current obj into the heapfile */
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
    heapcache = NULL;
    DEBUG(0) std::cout << "Dofree " << std::hex << addr << std::endl;
    if (!addr) {
        return 0;
    }
    for (HEAPVEC::iterator it = heap.begin(); it != heap.end(); ++it) {
        if (abs(int(it->base - addr)) == 16) {
            /* A duplicate was found earlier and freed already
             * Don't do anything */
            std::cout << " duplicate in free" << std::endl;
            return 1;
        }
        if (!it->used) {
            continue;
        }
        if (it->base == addr) {
            it->used = false;
            return it->id;
        }
    }
    std::cout << "[Error] Invalid free!" << std::endl;
    DEBUG(0) printheap();
    return 0;
}

#if 0
/**
 * Record malloc
 * @param threadid The thread
 * @param size The size parameter passed to malloc
 */
VOID RecordMallocBefore(THREADID threadid, VOID* ip, ADDRINT size) {
  if (!Record) return;
  //PIN_MutexLock(&lock);
  if (thread_state[threadid].realloc_state.size() == 0) {
    DEBUG(1) std::cout << "[pintool] Malloc called with " << std::hex << size << " at " << ip << std::endl;
    alloc_state_t state = { .size = size };
    thread_state[threadid].malloc_state.push_back(state);
  } else {
    DEBUG(1) std::cout << "[pintool] Malloc ignored due to realloc_pending (size= " << std::hex << size << ") at " << ip << std::endl;
  }
  //PIN_MutexUnlock(&lock);
}
#endif

#if 0
/**
 * Record malloc's result
 * @param threadid The thread
 * @param addr The allocated heap pointer
 */
VOID RecordMallocAfter(THREADID threadid, VOID* ip, ADDRINT addr) {
  if (!Record) return;
  //PIN_MutexLock(&lock);
  DEBUG(1) std::cout << "[pintool] Malloc returned " << std::hex << addr << std::endl;
  ASSERT(thread_state[threadid].malloc_state.size() > 0, "[pintool] Error: Malloc returned but not called");
  alloc_state_t state = thread_state[threadid].malloc_state.back();
  thread_state[threadid].malloc_state.pop_back();
  domalloc(addr, state.size, 0);
  //PIN_MutexUnlock(&lock);
}
#endif

void *MallocWrapper(CONTEXT *ctxt, AFUNPTR pf_malloc, size_t size) {
    void *addr;
    PIN_CallApplicationFunction(ctxt, PIN_ThreadId(), CALLINGSTD_DEFAULT,
                                pf_malloc, NULL, PIN_PARG(void *), &addr,
                                PIN_PARG(size_t), size, PIN_PARG_END());
    DEBUG(0) std::cout << "Malloc returned " << std::hex << addr << std::endl;
#if 1
    THREADID threadid = PIN_ThreadId();
    DEBUG(0)
        std::cout << "Malloc called with " << std::hex << size << std::endl;
    SHA1 hash;
    hash.update(getcallstack(
        threadid)); /* calculte the hash of the set of IPs in the Callstack */
    alloc_state_t state = {
        .type = "malloc",
        .size = size,
        .callsite = 0,
        .callstack = hash.final().substr(28, 12), /* 6 byte SHA1 hash */
    };

    // ASSERT(thread_state[threadid].malloc_state.size(), "[Error] Malloc
    // returned but not called");
    doalloc((ADDRINT)addr, state.size, 0, state.callsite, state.type,
            state.callstack, 0);
    // thread_state[threadid].malloc_pending = false;
#endif
    return addr;
}

#if 0
/**
 * Record realloc
 * @param threadid The thread
 * @param addr The heap pointer param of realloc
 * @param size The size parameter passed to realloc
 */
VOID RecordReallocBefore(THREADID threadid, VOID* ip, ADDRINT addr, ADDRINT size) {
  if (!Record) return;
  //PIN_MutexLock(&lock);
  DEBUG(1) std::cout << "[pintool] Realloc called with " << std::hex << addr << " " << size << " at " << ip << std::endl;
  realloc_state_t state;
  state.size = size;
  state.old = addr;
  thread_state[threadid].realloc_state.push_back(state);
  //PIN_MutexUnlock(&lock);
}
#endif

#if 0
/**
 * Record realloc's result
 * @param threadid The thread
 * @param addr The allocated heap pointer
 */
VOID RecordReallocAfter(THREADID threadid, VOID* ip, ADDRINT addr) {
  if (!Record) return;
  //PIN_MutexLock(&lock);
  DEBUG(1) std::cout << "[pintool] Realloc returned " << std::hex << addr << " at " << ip << std::endl;
  ASSERT(thread_state[threadid].realloc_state.size() > 0, "[pintool] Error: Realloc returned but not called");
  realloc_state_t state = thread_state[threadid].realloc_state.back();
  thread_state[threadid].realloc_state.pop_back();

  uint32_t objid = 0;
  if (state.old) {
    objid = dofree(state.old);
  }
  domalloc(addr, state.size, objid);
  //PIN_MutexUnlock(&lock);
}
#endif

void *ReallocWrapper(CONTEXT *ctxt, AFUNPTR pf_realloc, void *ptr,
                     size_t size) {
    void *addr;
    PIN_CallApplicationFunction(ctxt, PIN_ThreadId(), CALLINGSTD_DEFAULT,
                                pf_realloc, NULL, PIN_PARG(void *), &addr,
                                PIN_PARG(void *), ptr, PIN_PARG(size_t), size,
                                PIN_PARG_END());
    DEBUG(0)
    std::cout << "Realloc called with " << std::hex << ptr << " " << size
              << std::endl;
    DEBUG(0) std::cout << "Realloc returned " << std::hex << addr << std::endl;
    THREADID threadid = PIN_ThreadId();
    SHA1 hash;
    hash.update(getcallstack(
        threadid)); /* calculte the hash of the set of IPs in the Callstack */
    realloc_state_t state = {
        .type = "realloc",
        .old = (ADDRINT)ptr,
        .size = size,
        .callsite = 0,
        .callstack = hash.final().substr(28, 12), /* 6 byte SHA1 hash */
    };

    // thread_state[threadid].realloc_pending = true;
#if 1
    // ASSERT(thread_state[threadid].realloc_pending == true, "[Error] Realloc
    // returned but not called");
    uint32_t objid = 0;
    if (state.old) {
        objid = dofree(state.old);
    }
    doalloc((ADDRINT)addr, state.size, objid, state.callsite, state.type,
            state.callstack, state.old);
    // thread_state[threadid].realloc_pending = false;
#endif
    return addr;
}

/**
 * Record calloc
 * @param threadid The thread
 * @param nelem The number of elements parameter passed to calloc
 * @param size The size parameter passed to calloc
 */
VOID RecordCallocBefore(CHAR *name, THREADID threadid, ADDRINT nelem,
                        ADDRINT size, ADDRINT ret) {
    if (!Record)
        return;
    //  PIN_MutexLock(&lock);
    if (thread_state[threadid].calloc_state.size() == 0) {
        DEBUG(1)
        std::cout << "Calloc called with " << std::hex << nelem << " " << size
                  << std::endl;
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
    //  PIN_MutexLock(&lock);
    DEBUG(1) std::cout << "Calloc returned " << std::hex << addr << std::endl;
    if (!Record) {
        DEBUG(1) std::cout << "ignoring" << std::endl;
        return;
    }
    ASSERT(thread_state[threadid].calloc_state.size() != 0,
           "[Error] Calloc returned but not called");
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
VOID RecordFreeBefore(THREADID threadid, ADDRINT addr) {
    if (!Record)
        return;
    //  PIN_MutexLock(&lock);
    DEBUG(0) std::cout << "Free called with " << std::hex << addr << std::endl;
    dofree(addr);
    //  PIN_MutexUnlock(&lock);
}

/**
 * Record munmap
 * @param threadid The thread
 * @param addr The heap pointer which is munmapped
 */
VOID RecordmunmapBefore(THREADID threadid, ADDRINT addr, ADDRINT len) {
    if (!Record)
        return;
    //  PIN_MutexLock(&lock);
    DEBUG(1)
    std::cout << "munmap called with " << std::hex << addr << "*" << len
              << std::endl;
    dofree(addr);
    //  PIN_MutexUnlock(&lock);
}
/**
 * Record mmap
 * @param threadid The thread
 * @param size The size parameter passed to mmap
 */
VOID RecordmmapBefore(CHAR *name, THREADID threadid, ADDRINT size,
                      ADDRINT ret) {
    if (!Record)
        return;
    //  PIN_MutexLock(&lock);
    if (thread_state[threadid].mremap_state.size() == 0) {
        DEBUG(1)
            std::cout << "mmap called with " << std::hex << size << std::endl;
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
    }
    //  PIN_MutexUnlock(&lock);
}

/**
 * Record mmap's result
 *@param threadid The thread
 * @param addr The allocated heap pointer
 */
VOID RecordmmapAfter(THREADID threadid, ADDRINT addr, ADDRINT ret) {
    //  PIN_MutexLock(&lock);

    DEBUG(1) std::cout << "mmap returned " << std::hex << addr << std::endl;
    ASSERT(thread_state[threadid].mmap_state.size() != 0,
           "[Error] mmap returned but not called");

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
    if (!Record)
        return;
    //  PIN_MutexLock(&lock);
    DEBUG(1)
    std::cout << "mremap called with " << std::hex << addr << " " << new_size
              << std::endl;

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
    if (!Record)
        return;
    //  PIN_MutexLock(&lock);
    DEBUG(1) std::cout << "mremap returned " << std::hex << addr << std::endl;
    ASSERT(thread_state[threadid].mremap_state.size() != 0,
           "[Error] mremap returned but not called");

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
    std::cout << "ip in memread is   " << (uint64_t)ip << " " << std::endl;
    //  PIN_MutexLock(&lock);
    entry_t entry;
    entry.type = READ;
    entry.ip = getLogicalAddress(ip);
    entry.data = getLogicalAddress(addr);
    test_mem_heap(&entry);
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
    std::cout << " TOP from WRITE is " << target << std::endl;
    entry.ip = getLogicalAddress(ip);
    entry.data = getLogicalAddress(addr);
    test_mem_heap(&entry);
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
    entry.ip = getLogicalAddress((void *)ins);
    entry.data = getLogicalAddress((void *)target);
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
    //  PIN_MutexLock(&lock);
    ADDRINT target = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    DEBUG(3)
    std::cout << "Branch " << std::hex << bp << " to " << target << std::endl;
    RecordBranch_unlocked(threadid, bp, target, ctxt);
    if (fast_recording) {
        auto ix = (getLogicalAddress((void *)bp));
        uint64_t *li = static_cast<uint64_t *>(ix);
        uint64_t b = (uint64_t)li;
        auto id = (getLogicalAddress((void *)target));
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
    // entry.ip = getLogicalAddress((void*) ((uintptr_t)ins), ctxt);
    entry.ip = getLogicalAddress((void *)(ins));
    if (entry.ip == nullptr) {
        entry.ip = (void *)ins;
    }
    // entry.data = getLogicalAddress((void*) ((uintptr_t)target), ctxt);
    entry.data = getLogicalAddress((void *)(target));
    DEBUG(3)
    std::cout << "Call " << std::hex << ins << " to " << target << std::endl;
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
        DEBUG(2) std::cout << "Icall to  " << std::hex << target << std::endl;
    }
    if (KnobFunc.Value()) {
        RecordFunctionEntry_unlocked(threadid, ins, indirect, target, ctxt);
    }
    if (fast_recording) {
        auto ix = (getLogicalAddress((void *)ins));
        uint64_t *li = static_cast<uint64_t *>(ix);
        uint64_t i = (uint64_t)li;
        auto id = (getLogicalAddress((void *)target));
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
    std::cout << " TOP from func EXIT is "
              << PIN_GetContextReg(ctxt, REG_STACK_PTR) << std::endl;
    entry.ip = getLogicalAddress((void *)((uintptr_t)ins));
    entry.data = getLogicalAddress((void *)((uintptr_t)target));
    DEBUG(2)
    std::cout << "Ret " << std::hex << ins << " to " << target << std::endl;
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
        auto ix = (getLogicalAddress((void *)ins));
        uint64_t *li = static_cast<uint64_t *>(ix);
        uint64_t i = (uint64_t)li;
        auto id = (getLogicalAddress((void *)target));
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
    DEBUG(1) std::cout << "[pintool] Instrumenting " << name << std::endl;
    if (imgfile.is_open()) {
        uint64_t high = IMG_HighAddress(img);
        uint64_t low = IMG_LowAddress(img);

        if (vdsofile.is_open() && IMG_IsVDSO(img)) {
            /* For VDSO, the HighAddress does not point to end of ELF file,
             * leading to a truncated ELF file. We over-approximate the ELF size
             * with IMG_SizeMapped instead.
             */
            high = low + IMG_SizeMapped(img);
            DEBUG(1)
            std::cout << "[pintool] VDSO low:   0x" << std::hex << low
                      << std::endl;
            DEBUG(1)
            std::cout << "[pintool] VDSO high:  0x" << std::hex << high
                      << std::endl;
            DEBUG(1)
            std::cout << "[pintool] VDSO size mapped:  0x" << std::hex
                      << IMG_SizeMapped(img) << std::endl;
            vdsofile.write((const char *)low, IMG_SizeMapped(img));
            vdsofile.close();
            name = KnobVDSO.Value();
        }

        imgfile << "Image:" << std::endl;
        imgfile << name << std::endl;
        imgfile << std::hex << low << ":" << high << std::endl;
    }

    if (IMG_Valid(img)) {
        if (imgfile.is_open()) {
            for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym);
                 sym = SYM_Next(sym)) {
                imgfile << std::hex << SYM_Address(sym) << ":" + SYM_Name(sym)
                        << std::endl;
            }
        }
        DEBUG(1)
        std::cout << "[pintool] KnobMain: " << KnobMain.Value() << std::endl;
        if (KnobMain.Value().compare("ALL") != 0) {
            RTN mainRtn = RTN_FindByName(img, KnobMain.Value().c_str());
            if (mainRtn.is_valid()) {
                RTN_Open(mainRtn);
                RTN_InsertCall(mainRtn, IPOINT_BEFORE, (AFUNPTR)RecordMainBegin,
                               IARG_THREAD_ID, IARG_ADDRINT,
                               RTN_Address(mainRtn), IARG_END);
                RTN_InsertCall(mainRtn, IPOINT_AFTER, (AFUNPTR)RecordMainEnd,
                               IARG_THREAD_ID, IARG_ADDRINT,
                               RTN_Address(mainRtn), IARG_END);
                RTN_Close(mainRtn);
            }
        } else {
            DEBUG(1) std::cout << "[pintool] Recording all" << std::endl;
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
                DEBUG(1)
                std::cout << "[pintool] Allocation already instrumented"
                          << std::endl;
            } else {
                DEBUG(1)
                    std::cout << "[pintool] Instrumenting allocation"
                              << std::endl;
                if (KnobTrackHeap.Value()) {
#if 0
          RTN mallocRtn = RTN_FindByName(img, MALLOC);
          if (mallocRtn.is_valid()) {
            DEBUG(1) std::cout << "[pintool] Malloc found in " << IMG_Name(img) << std::endl;
            RTN_Open(mallocRtn);
            RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)RecordMallocBefore,
              IARG_THREAD_ID,
              IARG_INST_PTR,
              IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
              IARG_END);
            RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)RecordMallocAfter,
              IARG_THREAD_ID,
              IARG_INST_PTR,
              IARG_FUNCRET_EXITPOINT_VALUE,
              IARG_END);
            RTN_Close(mallocRtn);
          }
#endif
                    RTN MallocRtn = RTN_FindByName(
                        img, "malloc"); //  Find the malloc() function.
                    if (RTN_Valid(MallocRtn)) {
                        PROTO protoMalloc = PROTO_Allocate(
                            PIN_PARG(void *), CALLINGSTD_DEFAULT, "malloc",
                            PIN_PARG(size_t), PIN_PARG_END());

                        RTN_ReplaceSignature(
                            MallocRtn, AFUNPTR(MallocWrapper), IARG_PROTOTYPE,
                            protoMalloc, IARG_CONST_CONTEXT, IARG_ORIG_FUNCPTR,
                            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
                    }

#if 0
          RTN reallocRtn = RTN_FindByName(img, REALLOC);
          if (reallocRtn.is_valid()) {
            DEBUG(1) std::cout << "[pintool] Realloc found in " << IMG_Name(img) << std::endl;
            RTN_Open(reallocRtn);
            RTN_InsertCall(reallocRtn, IPOINT_BEFORE, (AFUNPTR)RecordReallocBefore,
              IARG_THREAD_ID,
              IARG_INST_PTR,
              IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
              IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
              IARG_END);
            RTN_InsertCall(reallocRtn, IPOINT_AFTER, (AFUNPTR)RecordReallocAfter,
              IARG_THREAD_ID,
              IARG_INST_PTR,
              IARG_FUNCRET_EXITPOINT_VALUE,
              IARG_END);
            RTN_Close(reallocRtn);
          }
#endif

                    RTN ReallocRtn = RTN_FindByName(
                        img, "realloc"); //  Find the malloc() function.
                    if (RTN_Valid(ReallocRtn)) {
                        PROTO protoRealloc = PROTO_Allocate(
                            PIN_PARG(void *), CALLINGSTD_DEFAULT, "realloc",
                            PIN_PARG(size_t), PIN_PARG_END());
                        RTN_ReplaceSignature(
                            ReallocRtn, AFUNPTR(ReallocWrapper), IARG_PROTOTYPE,
                            protoRealloc, IARG_CONST_CONTEXT, IARG_ORIG_FUNCPTR,
                            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
                    }

                    RTN callocRtn = RTN_FindByName(img, CALLOC);
                    if (callocRtn.is_valid()) {
                        DEBUG(1)
                        std::cout << "[pintool] Calloc found in "
                                  << IMG_Name(img) << std::endl;
                        RTN_Open(callocRtn);
                        RTN_InsertCall(
                            callocRtn, IPOINT_BEFORE,
                            (AFUNPTR)RecordCallocBefore, IARG_THREAD_ID,
                            IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
                        RTN_InsertCall(callocRtn, IPOINT_AFTER,
                                       (AFUNPTR)RecordCallocAfter,
                                       IARG_THREAD_ID, IARG_INST_PTR,
                                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
                        RTN_Close(callocRtn);
                    }

                    RTN freeRtn = RTN_FindByName(img, FREE);
                    if (freeRtn.is_valid()) {
                        DEBUG(1)
                        std::cout << "[pintool] Free found in " << IMG_Name(img)
                                  << std::endl;
                        RTN_Open(freeRtn);
                        RTN_InsertCall(
                            freeRtn, IPOINT_BEFORE, (AFUNPTR)RecordFreeBefore,
                            IARG_THREAD_ID, IARG_INST_PTR,
                            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
                        RTN_Close(freeRtn);
                    }
                }
                alloc_instrumented = 1;
            }
        } /* alloc.so or libc */
    }
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
                std::cout << "Ignoring XEND" << std::endl;
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

    // ip = getLogicalAddress();
    auto ix = (getLogicalAddress((void *)ip));
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
        ASSERT(found,
               "[pintool] Error: Memory instruction to instument not found. "
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
                ASSERT(
                    res,
                    "[pintool] Error: Unable to write complete trace file. Out "
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

    /* Getting the stack, heap and vvar address range for this process */
    stackBaseAddr = execute_commands("stack", 2, " ");
    DEBUG(1)
    std::cout << "stackBaseAddr is " << std::hex << stackBaseAddr << std::endl;
    stackEndAddr = execute_commands("stack", 1, " ");
    DEBUG(1)
    std::cout << "stackEndAddr is " << std::hex << stackEndAddr << std::endl;

    imgobj_t imgdata;
    imgdata.name = "vvar";
    SHA1 hash;
    hash.update(imgdata.name);
    imgdata.imghash = hash.final().substr(32, 8);

    imgdata.baseaddr = execute_commands("vvar", 1, " ");
    DEBUG(1)
    std::cout << "vvarBaseAddr is " << std::hex << imgdata.baseaddr
              << std::endl;

    imgdata.endaddr = execute_commands("vvar", 2, " ");
    DEBUG(1)
    std::cout << "vvarEndAddr is " << std::hex << imgdata.endaddr << std::endl;

    imgvec.push_back(imgdata);

    imgobj_t imgdataUnknown;
    imgdataUnknown.name = "unknown1";
    SHA1 hashUnknown;
    hashUnknown.update(imgdataUnknown.name);
    imgdataUnknown.imghash = hashUnknown.final().substr(32, 8);

    imgdataUnknown.baseaddr = execute_commands("-B 1 stack", 1, "| head -n 1");
    DEBUG(1)
    std::cout << "Unknown1 is " << std::hex << imgdataUnknown.baseaddr
              << std::endl;

    imgdataUnknown.endaddr = execute_commands("-B 1 stack", 2, "| head -n 1");
    DEBUG(1)
    std::cout << "Unknown1 is " << std::hex << imgdataUnknown.endaddr
              << std::endl;

    imgvec.push_back(imgdataUnknown);

    auto mngr = CALLSTACK::CallStackManager::get_instance();
    mngr->activate();

    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    PIN_AddFiniFunction(Fini, 0);

    init();
    PIN_StartProgram();

    heapBaseAddr = execute_commands("heap", 1, " ");
    DEBUG(1)
    std::cout << "heapBaseAddr is " << std::hex << heapBaseAddr << std::endl;
    heapEndAddr = execute_commands("heap", 2, " ");
    DEBUG(1)
    std::cout << "heapEndAddr is " << std::hex << heapEndAddr << std::endl;

    return 0;
}
