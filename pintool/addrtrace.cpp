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

#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <getopt.h>
#include "pin.H"

/**
 * Pin 3.11 Documentation:
 * https://software.intel.com/sites/landingpage/pintool/docs/97998/Pin/html
 */

// Pin above 3.7.97720 deprecates some functions
#if (PIN_PRODUCT_VERSION_MAJOR > 3) || \
    (PIN_PRODUCT_VERSION_MAJOR == 3 && PIN_PRODUCT_VERSION_MINOR > 7) || \
    (PIN_PRODUCT_VERSION_MAJOR == 3 && PIN_PRODUCT_VERSION_MINOR == 7 && PIN_BUILD_NUMBER > 97720)
  #define INS_IS_INDIRECT INS_IsIndirectControlFlow
  #define INS_HAS_TAKEN_BRANCH INS_IsValidForIpointTakenBranch
  #define INS_HAS_IPOINT_AFTER INS_IsValidForIpointAfter
#else
  #define INS_IS_INDIRECT INS_IsIndirectBranchOrCall
  #define INS_HAS_TAKEN_BRANCH INS_IsBranchOrCall
  #define INS_HAS_IPOINT_AFTER INS_HasFallThrough
#endif

using namespace std;

/***********************************************************************/

VOID RecordFunctionEntry(THREADID threadid, ADDRINT bbl, ADDRINT bp, BOOL indirect, ADDRINT target, bool report_as_cfleak);
VOID RecordFunctionExit(THREADID threadid, ADDRINT bbl, ADDRINT bp, const CONTEXT* ctxt, bool report_as_cfleak);

/***********************************************************************/

KNOB<string> KnobRawFile(KNOB_MODE_WRITEONCE, "pintool",
        "raw", "", "Raw output file.");

KNOB<bool> KnobFunc(KNOB_MODE_WRITEONCE, "pintool",
        "func", "0", "Trace function calls and returns.");

KNOB<bool> KnobBbl(KNOB_MODE_WRITEONCE, "pintool",
        "bbl", "0", "Trace basic blocks.");

KNOB<bool> KnobMem(KNOB_MODE_WRITEONCE, "pintool",
        "mem", "0", "Trace data memory accesses.");

KNOB<bool> KnobTrackHeap(KNOB_MODE_WRITEONCE, "pintool",
        "heap", "0", "Track heap usage (malloc, free).");

KNOB<string> KnobSyms(KNOB_MODE_WRITEONCE, "pintool",
        "syms", "", "Output file for image information.");

KNOB<string> KnobVDSO(KNOB_MODE_WRITEONCE, "pintool",
        "vdso", "vdso.so", "Output file for the vdso shared library.");

KNOB<bool> KnobLeaks(KNOB_MODE_WRITEONCE, "pintool",
        "leaks", "0", "Enable fast recording of leaks, provided via leakin.");

KNOB<string> KnobLeakIn(KNOB_MODE_WRITEONCE, "pintool",
        "leakin", "", "Binary input file containing all leaks to trace."
                      "If empty, all selected instructions are traced. "
                      "In any case specify -func, -bbl, -mem -heap accordingly!"
                      "This means that instructions in the -bin file are only traced,"
                      "if also the corresponding flag (e.g. -mem, -bbl) is set");

KNOB<string> KnobLeakOut(KNOB_MODE_WRITEONCE, "pintool",
        "leakout", "", "Hierarchical output file of all leaks. Only useful with -bin option.");

KNOB<bool> KnobCallstack(KNOB_MODE_WRITEONCE, "pintool",
        "cs", "0", "Take callstack into account and trace leaks only in the correct calling context. Only useful with -bin option.");

KNOB<string> KnobMain(KNOB_MODE_WRITEONCE, "pintool",
        "main", "main", "Main method to start tracing. Defaults to 'main'. Provide ALL to trace from the beginning.");

KNOB<int> KnobDebug(KNOB_MODE_WRITEONCE, "pintool",
        "debug", "0", "Enable debugging output.");

/***********************************************************************/
/** Recording                                                          */
/***********************************************************************/

// TODO: instrument strdup

#define MALLOC "malloc"
#define REALLOC "realloc"
#define CALLOC "calloc"
#define FREE "free"
#define DEBUG(x) if(KnobDebug.Value() >= x)

int alloc_instrumented = 0;

/* When using '-main ALL', ensures recording starts at function call */
bool WaitForFirstFunction = false;
bool Record = false;
bool use_callstack = false;

/**
 * Traces are stored in a binary format, containing a sequence of
 * entry_t entries.
 */
typedef struct __attribute__((packed))
{
  uint8_t type; /* holds values of entry_type_t */
  uint64_t ip;     /* instruction pointer */
  uint64_t data;   /* additional data, depending on type */
}
entry_t;

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
  READ  = MASK_NONE | A,
  WRITE = MASK_NONE | B,

  MASK_BRANCH = 4,
  /* Branching instructions */
  BRANCH     = MASK_BRANCH | A,
  FUNC_ENTRY = MASK_BRANCH | B,
  FUNC_EXIT  = MASK_BRANCH | C,
  FUNC_BBL   = MASK_BRANCH | D,

  MASK_HEAP = 8,
  /* Instructions doing memory reads/writes on heap objects */
  HREAD  = MASK_HEAP | READ,
  HWRITE = MASK_HEAP | WRITE,
  /* Heap alloc/free calls */
  HALLOC = MASK_HEAP | C,
  HFREE  = MASK_HEAP | D,

  MASK_LEAK = 16,
  /* Dataleaks and Controlflow leaks, used for fast recording */
  DLEAK  = MASK_LEAK | A,
  CFLEAK = MASK_LEAK | B,
};

std::vector<entry_t> trace; /* Contains all traced instructions */
ofstream imgfile;           /* Holds memory layout with function symbols */
ofstream vdsofile;          /* Holds vdso shared library */

/***********************************************************************/
/* Heap tracking */

typedef struct {
  uint32_t id;
  size_t size;
  uint64_t base;
  bool used;
} memobj_t;

uint32_t nextheapid = 1;
memobj_t* heapcache;
typedef std::vector<memobj_t> HEAPVEC;
HEAPVEC heap;

/***********************************************************************/
/* Multithreading */

/* Global lock to protect trace buffer */
//PIN_MUTEX lock;

typedef struct {
  ADDRINT size;
} alloc_state_t;

typedef struct {
  ADDRINT old;
  ADDRINT size;
} realloc_state_t;

typedef struct {
  /* allocation routines sometimes call themselves in a nested way during initialization */
  std::vector<alloc_state_t> malloc_state;
  std::vector<alloc_state_t> calloc_state;
  std::vector<realloc_state_t> realloc_state;
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
    uint64_t ip; /* The leaking instruction */

  public:
    DataLeak(uint64_t ip = 0) : ip(ip) {
    }

    /**
     * Add evidence
     * @param d The evidence to add
     */
    void append(uint64_t d) {
      ASSERT(ip, "[pintool] Error: IP not set");
      DEBUG(1) printf("[pintool] DLEAK@%" PRIx64 ": %" PRIx64 " appended\n", ip, d);
      data.push_back(d);
    }

    void print() {
      for (std::vector<uint64_t>::iterator it = data.begin(); it != data.end(); it++) {
        printf("         %" PRIx64 " ", *it);
      }
      printf("\n");
    }

    /**
     * Export evidence to binary format
     * @param f The file to export to
     */
    void doexport(FILE* f) {
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
    std::vector<uint64_t> targets; /* Holds evidences */
    std::vector<uint64_t> mergepoints; /* unused */
    uint64_t bp; /* The leaking instruction */

  public:
    CFLeak(uint64_t bp = 0) : bp(bp) {
    }

    /**
     * Add evidence
     * @param ip The evidence to add
     */
    void append(uint64_t ip) {
      ASSERT(bp, "[pintool] Error: BP not set");
      DEBUG(1) printf("[pintool] CFLEAK@%" PRIx64 ": %" PRIx64 " appended\n", bp, ip);
      targets.push_back(ip);
    }

    void print() {
      for (std::vector<uint64_t>::iterator it = targets.begin(); it != targets.end(); it++) {
        printf("         %" PRIx64 " ", *it);
      }
      printf("\n");
    }

    /**
     * Export evidence to binary format
     * @param f The file to export to
     */
    void doexport(FILE* f) {
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
    Context() {
    }

    /**
     * Add a new dataleak to trace during execution
     * @param ip The instruction to trace
     */
    virtual void dleak_create(uint64_t ip) {
      if (dleaks.find(ip) == dleaks.end()) {
        dleaks.insert(std::pair<uint64_t, DataLeak>(ip, DataLeak(ip)));
      } else {
        DEBUG(1) printf("[pintool] Warning: DLEAK: %" PRIx64 " not created\n", ip);
      }
    }

    /**
     * Add a new cfleak to trace during execution
     * @param ip The instruction to trace (branch point)
     * @param mp The merge point (unused)
     * @param len The length of the branch (branch point-> merge point) (unused)
     */
    virtual void cfleak_create(uint64_t ip, uint64_t* mp, uint8_t len) {
      if (cfleaks.find(ip) == cfleaks.end()) {
        cfleaks.insert(std::pair<uint64_t, CFLeak>(ip, CFLeak(ip)));
      } else {
        DEBUG(1) printf("[pintool] Warning: CFLEAK: %" PRIx64 " not created\n", ip);
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
        DEBUG(1) printf("[pintool] Warning: DLEAK: %" PRIx64 " not appended\n", ip);
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
        DEBUG(1) printf("[pintool] Warning: CFLEAK: %" PRIx64 " not appended\n", bbl);
      } else {
        cfleaks[bbl].append(target);
      }
    }

    virtual void print() {
      for (dleaks_t::iterator it = dleaks.begin(); it != dleaks.end(); it++) {
        printf("[pintool]  DLEAK %" PRIx64 ": ", it->first);
        it->second.print();
      }
      for (cfleaks_t::iterator it = cfleaks.begin(); it != cfleaks.end(); it++) {
        printf("[pintool]  CFLEAK %" PRIx64 ": ", it->first);
        it->second.print();
      }
    }

    /**
     * Export evidence to binary format
     * @param f The file to export to
     */
    virtual void doexport(FILE* f) {
      for (dleaks_t::iterator it = dleaks.begin(); it != dleaks.end(); it++) {
        it->second.doexport(f);
      }
      for (cfleaks_t::iterator it = cfleaks.begin(); it != cfleaks.end(); it++) {
        it->second.doexport(f);
      }
    }
};

class CallContext;
class CallStack;
typedef std::map<uint64_t, CallContext*> children_t;

/**
 * Wraps class Context for use in class CallStack
 */
class CallContext : public Context {
  friend class CallStack;
  private:
    uint64_t caller;
    uint64_t callee;
    CallContext* parent;
    children_t children;
    int unknown_child_depth;
    bool used;

  public:
    CallContext(uint64_t caller = 0, uint64_t callee = 0)
      : Context(), caller(caller), callee(callee), parent(NULL), unknown_child_depth(0), used(false) {
    }

    virtual void dleak_append(uint64_t ip, uint64_t data) {
      if (used == false || unknown_child_depth) {
        DEBUG(1) printf("[pintool] Warning: DLEAK %" PRIx64 ": skipping due to %d %d\n", ip, used, unknown_child_depth);
      } else {
        Context::dleak_append(ip, data);
      }
    }

    virtual void cfleak_append(uint64_t bbl, uint64_t target) {
      if (used == false || unknown_child_depth) {
        DEBUG(1) printf("[pintool] Warning: CFLEAK %" PRIx64 ": skipping due to %d %d\n", bbl, used, unknown_child_depth);
      } else {
        Context::cfleak_append(bbl, target);
      }
    }

    virtual void print(Context* currentContext = NULL) {
      if (this == currentContext) {
          printf("*");
        }
      printf("%" PRIx64 "-->%" PRIx64 " (%d)(%d)\n", this->caller, this->callee, this->unknown_child_depth, this->used);
      Context::print();
      for (children_t::iterator it = children.begin(); it != children.end(); it++) {
        it->second->print(currentContext);
      }
      printf("<\n");
    }

    /**
     * Export evidence to binary format
     * @param f The file to export to
     */
    virtual void doexport(FILE* f) {
      uint8_t type = FUNC_ENTRY;
      uint8_t res = 0;
      res += fwrite(&type, sizeof(type), 1, f) != 1;
      res += fwrite(&caller, sizeof(caller), 1, f) != 1;
      res += fwrite(&callee, sizeof(callee), 1, f) != 1;
      ASSERT(!res, "[pintool] Error: Unable to write file");
      Context::doexport(f);
      for (children_t::iterator it = children.begin(); it != children.end(); it++) {
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
    std::set<uint64_t> traced_dataleaks; /* List of data leaks which shall be instrumented */
    std::set<uint64_t> traced_cfleaks;   /* List of control-flow leaks which shall be instrumented */
    std::set<uint64_t> erased_dataleaks; /* List of data leaks which are already instrumented */
    std::set<uint64_t> erased_cfleaks;   /* List of control-flow leaks which are already instrumented */
    Context* currentContext;

  public:
    size_t get_uninstrumented_dleak_size() {
      return traced_dataleaks.size();
    }

    size_t get_uninstrumented_cfleak_size() {
      return traced_cfleaks.size();
    }

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
    bool was_erased_dleak(uint64_t ip) {
      return erased_dataleaks.count(ip);
    }

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
    bool was_erased_cfleak(uint64_t ip) {
      return erased_cfleaks.count(ip);
    }

    void print_uninstrumented_leaks() {
      if (traced_dataleaks.size() > 0) {
        printf("[pintool] Uninstrumented DLEAKS:\n");
        for (std::set<uint64_t>::iterator it = traced_dataleaks.begin(); it != traced_dataleaks.end(); it++) {
          printf(" %" PRIx64 "\n", *it);
        }
      }
      if (traced_cfleaks.size() > 0) {
        printf("[pintool] Uninstrumented CFLEAKS:\n");
        for (std::set<uint64_t>::iterator it = traced_cfleaks.begin(); it != traced_cfleaks.end(); it++) {
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
    virtual void cfleak_create(uint64_t bp, uint64_t* mp, uint8_t len) {
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
    virtual void doexport(FILE* f) {
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
    Flat() {
      currentContext = new Context();
    }

    virtual void call_create(uint64_t caller, uint64_t callee) {
    }

    virtual void ret_create(uint64_t ip) {
    }

    virtual void call_consume(uint64_t caller, uint64_t callee) {
    }

    virtual void ret_consume(uint64_t ip) {
    }

    virtual void print_all() {
      currentContext->print();
    }
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
    /* Generate a hash of caller and callee by swapping callee's DWORDS and XORING both. */
    uint64_t get_call_id(uint64_t caller, uint64_t callee) {
      uint64_t id = caller;
      uint32_t lower = callee & 0x00000000FFFFFFFFULL;
      uint32_t upper = callee >> 32ULL;
      id ^= upper | ((uint64_t)lower << 32ULL);
      return id;
    }
  public:
    CallStack() {
    }

    void call_create(uint64_t caller, uint64_t callee) {
      ASSERT(use_callstack, "[pintool] Error: Wrong usage of callstack");
      DEBUG(2) printf("[pintool] Building callstack %" PRIx64 " --> %" PRIx64 "\n", caller, callee);
      uint64_t id = get_call_id(caller, callee);
      if (currentContext == NULL) {
        currentContext = new CallContext(caller, callee);
      } else {
        CallContext* top = static_cast<CallContext*>(currentContext);
        if (top->children.find(id) == top->children.end()) {
          CallContext* newcs = new CallContext(caller, callee);
          newcs->used = true;
          newcs->parent = top;
          top->children[id] = newcs;
        }
        CallContext* move = top->children[id];
        currentContext = top = move;
      }
    }

    void call_consume(uint64_t caller, uint64_t callee) {
      ASSERT(use_callstack, "[pintool] Error: Wrong usage of callstack");
      ASSERT(currentContext, "[pintool] Error: Callstack is not initialized");
      DEBUG(3) print_all();
      DEBUG(2) printf("[pintool] Calling %" PRIx64 " --> %" PRIx64 "\n", caller, callee);
      uint64_t id = get_call_id(caller, callee);
      CallContext* top = static_cast<CallContext*>(currentContext);
      if (!top->used) {
        if (top->caller == caller && top->callee == callee) {
          DEBUG(2) printf("[pintool] Entered first leaking callstack\n");
          top->used = true;
        }
      } else {
        if (top->unknown_child_depth || top->children.find(id) == top->children.end()) {
          top->unknown_child_depth++;
        } else {
          CallContext* move = top->children[id];
          currentContext = top = move;
        }
      }
      DEBUG(3) print_all();
    }

    void ret_consume(uint64_t ip) {
      ASSERT(use_callstack, "[pintool] Error: Wrong usage of callstack");
      ASSERT(currentContext, "[pintool] Error: Callstack is not initialized");
      DEBUG(2) printf("[pintool] Returning %" PRIx64 "\n", ip);
      CallContext* top = static_cast<CallContext*>(currentContext);
      if (top->unknown_child_depth) {
        top->unknown_child_depth--;
      } else {
        if (top->parent) {
          ASSERT(top->parent, "[pintool] Error: Callstack parent is empty");
          currentContext = top = top->parent;
        } else {
          DEBUG(2) printf("[pintool] Warning: Ignoring return\n");
        }
      }
    }

    void ret_create(uint64_t ip) {
      ret_consume(ip);
    }

    bool empty() {
      ASSERT(use_callstack, "[pintool] Error: Wrong usage of callstack");
      CallContext* top = static_cast<CallContext*>(currentContext);
      return top == NULL || top->used == false;
    }

    CallContext* get_begin() {
      ASSERT(use_callstack, "[pintool] Error: Wrong usage of callstack");
      CallContext* c = static_cast<CallContext*>(currentContext);
      while(c && c->parent) {
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
      CallContext* top = get_begin();
      ASSERT(top, "[pintool] Error: Leaks not initialized");
      top->used = false;
      currentContext = top;
    }

    void print_all() {
      ASSERT(use_callstack, "[pintool] Error: Wrong usage of callstack");
      CallContext* top = get_begin();
      if (top) {
        printf("[pintool] Callstack:\n");
        top->print(currentContext);
      }
    }
};

AbstractLeakContainer* leaks = NULL;

/***********************************************************************/
/** Thread/Main recording and initialization                           */
/***********************************************************************/

void init() {
  //ASSERT(PIN_MutexInit(&lock), "[pintool] Error: Mutex init failed");
}

/**
 * Add an entry to the trace
 * This function is not thread-safe. Lock first.
 */
VOID record_entry(entry_t entry)
{
  trace.push_back(entry);
}

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
VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    ASSERT(threadid == 0, "[pintool] Error: Multithreading detected but not supported!");
    DEBUG(1) printf("[pintool] Thread begin %d\n",threadid);
    //PIN_MutexLock(&lock);
    if (thread_state.size() <= threadid) {
      thread_state_t newstate;
      newstate.RetIP = 0;
      newstate.newbbl = 0;
      thread_state.push_back(newstate);
    } else {
      thread_state[threadid].RetIP = 0;
      thread_state[threadid].newbbl = 0;
    }
    ASSERT(thread_state.size() > threadid, "[pintool] Error: thread_state corrupted");
    //PIN_MutexUnlock(&lock);
}

/**
 * Track thread destruction.
 * @param threadid The thread
 * @param ctxt Unused
 * @param code Unused
 * @param v Unused
 */
VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    //PIN_MutexLock(&lock);
    DEBUG(1) printf("[pintool] Thread end %d code %d\n",threadid, code);
    //PIN_MutexUnlock(&lock);
}

/***********************************************************************/
/** Heap recording                                                     */
/***********************************************************************/

void printheap() {
  std::cout << "[pintool] Heap:" << std::endl;
  for(HEAPVEC::iterator it = heap.begin(); it != heap.end(); ++it) {
    std::cout << std::hex << it->id << ":" << it->base << "-" << it->size << " used:" << it->used << std::endl;
  }
}

memobj_t* lookup_heap(uint64_t addr) {
  uint64_t paddr = addr;
  if (heapcache) {
    ASSERT(heapcache->used, "[pintool] Error: Heapcache corrupt");
    if (paddr >= heapcache->base && paddr < heapcache->base + heapcache->size) {
      return heapcache;
    }
  }

  for(HEAPVEC::reverse_iterator it = heap.rbegin(); it != heap.rend(); ++it) {
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

VOID test_mem_heap(entry_t* pentry) {
  memobj_t* obj = lookup_heap(pentry->data);
  if (obj) {
    uint64_t data_addr = (uint64_t)(&pentry->data);
    uint64_t* paddr = (uint64_t*)((void*)data_addr);
    *paddr -= obj->base;
    ASSERT((*paddr & 0xFFFFFFFF00000000ULL) == 0, "[pintool] Error: Heap object too big");
    *paddr |= (uint64_t)obj->id << 32ULL;
    pentry->type |= MASK_HEAP;
  }
}

/**
 * Add alloc/free to the trace
 * This function is not thread-safe. Lock first.
 */
void record_heap_op(memobj_t *obj, ADDRINT addr) {
  entry_t entry;
  entry.type = obj->used ? HALLOC : HFREE;
  entry.ip = (((uint64_t)obj->id << 32ULL) | obj->size);
  entry.data = addr;
  record_entry(entry);
}

/**
 * Handle calls to [m|re|c]alloc by keeping a list of all heap objects
 * This function is not thread-safe. Lock first.
 */
void domalloc(ADDRINT addr, ADDRINT size, uint32_t objid) {
  heapcache = NULL;
  memobj_t obj;
  if (objid) {
    obj.id = objid;
  } else {
    obj.id = nextheapid++;
  }

  obj.base = addr;
  obj.size = size;
  obj.used = true;
  record_heap_op(&obj, addr);

  DEBUG(2) std::cout << "[pintool] Domalloc " << std::hex << addr << " " << size << std::endl;
  /* Keep heap vector sorted */
  HEAPVEC::iterator prev = heap.end();
  HEAPVEC::iterator found = heap.end();
  for(HEAPVEC::iterator it = heap.begin(); it != heap.end(); ++it) {
    if (it->used) {
      if (it->base >= obj.base) {
        /* insert before*/
        if (obj.base + obj.size > it->base) {
          DEBUG(2) printheap();
          DEBUG(2) std::cout << "[pintool] Inserting new object" << std::hex << obj.base << "-" << obj.size << std::endl;
          ASSERT(false, "[pintool] Error: Corrupted heap A?!");
        }
        found = it;
        break;
      }
    }
    prev = it;
  }

  if (found == heap.end()) {
    /* no match found, append to the end */
    heap.push_back(obj);
  } else {
    if (prev == heap.end()) {
      heap.insert(found, obj);
    } else if (prev->used) {
        /* We cannot reuse prev, insert at 'found' */
        if(prev->used && prev->base + prev->size > obj.base) {
          DEBUG(2) printheap();
          DEBUG(2) std::cout << "[pintool] Inserting new object" << std::hex << obj.base << "-" << obj.size << std::endl;
          ASSERT(false, "[pintool] Error: Corrupted heap B?!");
        }
        heap.insert(found, obj);
    } else {
        /* prev is unused, reuse it */
        *prev = obj;
    }
  }
}

/**
 * Handle calls to free by maintaining a list of all heap objects
 * This function is not thread-safe. Lock first.
 */
uint32_t dofree(ADDRINT addr) {
  heapcache = NULL;
  DEBUG(2) std::cout << "[pintool] Dofree " << std::hex << addr << std::endl;
  if (!addr) {
    return 0;
  }
  for(HEAPVEC::iterator it = heap.begin(); it != heap.end(); ++it) {
    if (!it->used) {
      continue;
    }
    if (it->base == addr) {
      it->used = false;
      record_heap_op(it, addr);
      return it->id;
    }
  }
  std::cout << "[pintool] Warning: Invalid free!" << std::endl;
  DEBUG(2) printheap();
  return 0;
}

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

/**
 * Record calloc
 * @param threadid The thread
 * @param nelem The number of elements parameter passed to calloc
 * @param size The size parameter passed to calloc
 */
VOID RecordCallocBefore(THREADID threadid, VOID* ip, ADDRINT nelem, ADDRINT size) {
  if (!Record) return;
  //PIN_MutexLock(&lock);
  DEBUG(1) std::cout << "[pintool] Calloc called with " << std::hex << nelem << " " << size << " at " << ip << std::endl;
  alloc_state_t state = { .size = size };
  thread_state[threadid].calloc_state.push_back(state);
  //PIN_MutexUnlock(&lock);
}

/**
 * Record calloc's result
 * @param threadid The thread
 * @param addr The allocated heap pointer
 */
VOID RecordCallocAfter(THREADID threadid, VOID* ip, ADDRINT addr) {
  if (!Record) return;
  //PIN_MutexLock(&lock);
  DEBUG(1) std::cout << "[pintool] Calloc returned " << std::hex << addr << " at " << ip << std::endl;
  ASSERT(thread_state[threadid].calloc_state.size() > 0, "[pintool] Error: Calloc returned but not called");
  alloc_state_t state = thread_state[threadid].calloc_state.back();
  thread_state[threadid].calloc_state.pop_back();
  domalloc(addr, state.size, 0);
  //PIN_MutexUnlock(&lock);
}

/**
 * Record free
 * @param threadid The thread
 * @param addr The heap pointer which is freed
 */
VOID RecordFreeBefore(THREADID threadid, VOID* ip, ADDRINT addr) {
  if (!Record) return;
  //PIN_MutexLock(&lock);
  DEBUG(1) std::cout << "[pintool] Free called with " << std::hex << addr << " at " << ip << std::endl;
  dofree(addr);
  //PIN_MutexUnlock(&lock);
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
VOID RecordMemRead(THREADID threadid, VOID * ip, VOID * addr, bool fast_recording)
{
  if (!Record) return;
  //PIN_MutexLock(&lock);
  entry_t entry;
  entry.type = READ;
  entry.ip = (uint64_t)((uintptr_t)ip);
  entry.data = (uint64_t)((uintptr_t)addr);
  test_mem_heap(&entry);
  DEBUG(3) printf("[pintool] Read %" PRIx64 " to %" PRIx64 "\n", (uint64_t)entry.ip, (uint64_t)entry.data);
  if (fast_recording) {
    leaks->dleak_consume((uint64_t)entry.ip, (uint64_t)entry.data);
  } else {
    record_entry(entry);
  }
  //PIN_MutexUnlock(&lock);
}

/**
 * Record memory writes.
 * @param threadid The thread
 * @param ip The instruction issuing write
 * @param addr The data address being written
 * @param fast_recording For fast recording
 */
VOID RecordMemWrite(THREADID threadid, VOID * ip, VOID * addr, bool fast_recording)
{
  if (!Record) return;
  //PIN_MutexLock(&lock);
  entry_t entry;
  entry.type = WRITE;
  entry.ip = (uint64_t)((uintptr_t)ip);
  entry.data = (uint64_t)((uintptr_t)addr);
  test_mem_heap(&entry);
  DEBUG(3) printf("[pintool] Write %" PRIx64 " to %" PRIx64 "\n", (uint64_t)entry.ip, (uint64_t)entry.data);
  if (fast_recording) {
    leaks->dleak_consume((uint64_t)entry.ip, (uint64_t)entry.data);
  } else {
    record_entry(entry);
  }
  //PIN_MutexUnlock(&lock);
}

/**
 * Record conditional and unconditional branches.
 * This function is not thread-safe! Lock first.
 *
 * @param threadid The thread
 * @param ins The branching instruction
 * @param target The next instruction (e.g. branch target)
 */
VOID RecordBranch_unlocked(THREADID threadid, ADDRINT ins, ADDRINT target)
{
  if (!Record) return;
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
VOID RecordBranch(THREADID threadid, ADDRINT bbl, ADDRINT bp, const CONTEXT * ctxt, bool fast_recording)
{
  //PIN_MutexLock(&lock);
  ADDRINT target = (ADDRINT)PIN_GetContextReg( ctxt, REG_INST_PTR );
  DEBUG(3) std::cout << "[pintool] Branch " << std::hex << bp << " to " << target << std::endl;
  RecordBranch_unlocked(threadid, bp, target);
  if (fast_recording) {
    leaks->cfleak_consume(bp, target);
  }
  //PIN_MutexUnlock(&lock);
}

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

/**
 * Record call instructions.
 * This function is not thread-safe! Lock first.
 *
 * @param threadid The thread
 * @param ins The call instruction
 * @param indirect For indirect calls
 * @param target The called function's entry
 */
VOID RecordFunctionEntry_unlocked(THREADID threadid, ADDRINT ins, BOOL indirect, ADDRINT target)
{
  if (!Record) return;
  entry_t entry;
  entry.type = FUNC_ENTRY;
  entry.ip = ins;
  entry.data = target;
  DEBUG(3) std::cout << "[pintool] Call " << std::hex << ins << " to " << target << std::endl;
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
VOID RecordFunctionEntry(THREADID threadid, ADDRINT bbl, ADDRINT ins, BOOL indirect, ADDRINT target, bool fast_recording)
{
  if (WaitForFirstFunction) {
    Record = true;
    WaitForFirstFunction = false;
  }
  if (!Record) return;
  //PIN_MutexLock(&lock);
  if (indirect) {
    DEBUG(2) std::cout << "[pintool] Icall to  " << std::hex << target << std::endl;
  }
  if (KnobFunc.Value()) {
    RecordFunctionEntry_unlocked(threadid, ins, indirect, target);
  }
  if (fast_recording) {
    leaks->cfleak_consume(ins, target);
  }
  //PIN_MutexUnlock(&lock);
}

/**
 * Record ret instructions.
 * This function is not thread-safe! Lock first.
 *
 * @param threadid The thread
 * @param ins The ret instruction
 * @param target The instruction to continue after ret
 */
VOID RecordFunctionExit_unlocked(THREADID threadid, ADDRINT ins, ADDRINT target)
{
  if (!Record) return;
  entry_t entry;
  entry.type = FUNC_EXIT;
  entry.ip = ins;
  entry.data = target;
  DEBUG(2) std::cout << "[pintool] Ret " << std::hex << ins << " to " << target << std::endl;
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
VOID RecordFunctionExit(THREADID threadid, ADDRINT bbl, ADDRINT ins, const CONTEXT * ctxt, bool fast_recording)
{
  if (!Record) return;
  ADDRINT target = ctxt != NULL ? (ADDRINT)PIN_GetContextReg( ctxt, REG_INST_PTR ) : 0;
  //PIN_MutexLock(&lock);
  if (KnobFunc.Value()) {
    RecordFunctionExit_unlocked(threadid, ins, target);
  }
  if (fast_recording) {
    leaks->cfleak_consume(ins, target);
  }
  //PIN_MutexUnlock(&lock);
}

/***********************************************************************/
/** Instrumentation Code                                               */
/***********************************************************************/


/**
 * Instruments program entry and exit as well as heap functions of libc.
 * @param img The loaded image
 * @param v UNUSED
 */
VOID instrumentMainAndAlloc(IMG img, VOID *v)
{
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
      DEBUG(1) std::cout << "[pintool] VDSO low:   0x" << std::hex << low << std::endl;
      DEBUG(1) std::cout << "[pintool] VDSO high:  0x" << std::hex << high << std::endl;
      DEBUG(1) std::cout << "[pintool] VDSO size mapped:  0x" << std::hex << IMG_SizeMapped(img) << std::endl;
      vdsofile.write((const char*)low, IMG_SizeMapped(img));
      vdsofile.close();
      name = KnobVDSO.Value();
    }

    imgfile << "Image:" << std::endl;
    imgfile << name << std::endl;
    imgfile << std::hex << low << ":" << high << std::endl;
  }

  if (IMG_Valid(img)) {
    if (imgfile.is_open()) {
      for( SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym) ) {
        imgfile << std::hex << SYM_Address(sym) << ":" + SYM_Name(sym) << std::endl;
      }
    }
    DEBUG(1) std::cout << "[pintool] KnobMain: " << KnobMain.Value() << std::endl;
    if (KnobMain.Value().compare("ALL") != 0) {
      RTN mainRtn = RTN_FindByName(img, KnobMain.Value().c_str());
      if (mainRtn.is_valid()) {
        RTN_Open(mainRtn);
        RTN_InsertCall(mainRtn, IPOINT_BEFORE, (AFUNPTR)RecordMainBegin,
          IARG_THREAD_ID,
          IARG_ADDRINT, RTN_Address(mainRtn), IARG_END);
        RTN_InsertCall(mainRtn, IPOINT_AFTER, (AFUNPTR)RecordMainEnd,
          IARG_THREAD_ID,
          IARG_ADDRINT, RTN_Address(mainRtn), IARG_END);
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
        DEBUG(1) std::cout << "[pintool] Allocation already instrumented" << std::endl;
      } else {
        DEBUG(1) std::cout << "[pintool] Instrumenting allocation" << std::endl;
        if (KnobTrackHeap.Value()) {
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

          RTN callocRtn = RTN_FindByName(img, CALLOC);
          if (callocRtn.is_valid()) {
            DEBUG(1) std::cout << "[pintool] Calloc found in " << IMG_Name(img) << std::endl;
            RTN_Open(callocRtn);
            RTN_InsertCall(callocRtn, IPOINT_BEFORE, (AFUNPTR)RecordCallocBefore,
              IARG_THREAD_ID,
              IARG_INST_PTR,
              IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
              IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
              IARG_END);
            RTN_InsertCall(callocRtn, IPOINT_AFTER, (AFUNPTR)RecordCallocAfter,
              IARG_THREAD_ID,
              IARG_INST_PTR,
              IARG_FUNCRET_EXITPOINT_VALUE,
              IARG_END);
            RTN_Close(callocRtn);
          }

          RTN freeRtn = RTN_FindByName(img, FREE);
          if (freeRtn.is_valid()) {
            DEBUG(1) std::cout << "[pintool] Free found in " << IMG_Name(img) << std::endl;
            RTN_Open(freeRtn);
            RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)RecordFreeBefore,
              IARG_THREAD_ID,
              IARG_INST_PTR,
              IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
              IARG_END);
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
BOOL instrumentMemIns(INS ins, bool fast_recording)
{
  if (KnobMem.Value()) {
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    bool found = false;
    ADDRINT ip = INS_Address(ins);
    DEBUG(1) printf("[pintool] Adding %lx to instrumentation\n", (long unsigned int)ip);

    for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
      if (INS_MemoryOperandIsRead(ins, memOp)) {
        INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR) RecordMemRead,
                IARG_THREAD_ID,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_BOOL, fast_recording,
                IARG_END);
        found = true;
      }
      if (INS_MemoryOperandIsWritten(ins, memOp)) {
        INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR) RecordMemWrite,
                IARG_THREAD_ID,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_BOOL, fast_recording,
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
bool instrumentCallBranch(INS bbl, INS bp, bool fast_recording)
{
  bool instrumented = false;
  if (INS_IsCall(bp)) {
    if (KnobFunc.Value() || KnobBbl.Value()) {
      INS_InsertCall(bp, IPOINT_BEFORE, AFUNPTR(RecordFunctionEntry),
                          IARG_THREAD_ID,
                          IARG_ADDRINT, INS_Address(bbl),
                          IARG_ADDRINT, INS_Address(bp),
                          IARG_BOOL, INS_IS_INDIRECT(bp),
                          IARG_BRANCH_TARGET_ADDR,
                          IARG_BOOL, fast_recording,
                          IARG_END);
      DEBUG(1) printf("[pintool] Instrumented call@%lx\n", (long unsigned int)INS_Address(bp));
      instrumented = true;
    }
  } else if (INS_IsRet(bp)) {
    /* RET would be also detected as branch, therefore we use 'else if' */
    if (KnobFunc.Value() || KnobBbl.Value()) {
      ASSERT(INS_HAS_TAKEN_BRANCH(bp), "[pintool] Error: Return instruction should support taken branch.");
      INS_InsertCall(bp, IPOINT_TAKEN_BRANCH, AFUNPTR(RecordFunctionExit),
                          IARG_THREAD_ID,
                          IARG_ADDRINT, INS_Address(bbl),
                          IARG_ADDRINT, INS_Address(bp),
                          IARG_CONTEXT,
                          IARG_BOOL, fast_recording,
                          IARG_END);
      DEBUG(1) printf("[pintool] Instrumented ret@%lx\n", (long unsigned int)INS_Address(bp));
      instrumented = true;
    }
  } else if (INS_IsBranch(bp)) {
    if (KnobBbl.Value()) {
      if (!INS_HAS_TAKEN_BRANCH(bp)) {
        std::cout << "[pintool] Warning: Branch instruction " << INS_Mnemonic(bp) << "@ 0x" << std::hex << INS_Address(bp) << " does not support taken branch. Ignoring." << std::endl;
        // TODO: test for leaks in XBEGIN/XEND/XABORT
      } else {
        /* unconditional jumps */
        INS_InsertCall(bp, IPOINT_TAKEN_BRANCH, AFUNPTR(RecordBranch),
                            IARG_THREAD_ID,
                            IARG_ADDRINT, INS_Address(bbl),
                            IARG_ADDRINT, INS_Address(bp),
                            IARG_CONTEXT,
                            IARG_BOOL, fast_recording,
                            IARG_END);
        DEBUG(1) printf("[pintool] Instrumented jump@%lx\n", (long unsigned int)INS_Address(bp));
        instrumented = true;
      }
      
      if (INS_HAS_IPOINT_AFTER(bp)) {
        /* conditional/indirect jumps */
        INS_InsertCall(bp, IPOINT_AFTER, AFUNPTR(RecordBranch),
                            IARG_THREAD_ID,
                            IARG_ADDRINT, INS_Address(bbl),
                            IARG_ADDRINT, INS_Address(bp),
                            IARG_CONTEXT,
                            IARG_BOOL, fast_recording,
                            IARG_END);
        DEBUG(1) printf("[pintool] Instrumented indirect jump@%lx\n", (long unsigned int)INS_Address(bp));
        instrumented = true;
      }
    }
  } else if (INS_RepPrefix(bp)) {
    ADDRINT ip = INS_Address(bp);
    DEBUG(2) printf("[pintool] REP@%lx: REP-predicated instruction\n", (long unsigned int)ip);

    /* Rep-prefix does not necessarily show architectural effect
     * E.g. repz retq (see http://pages.cs.wisc.edu/~lena/repzret.php)
     */

    if (INS_HAS_IPOINT_AFTER(bp)) {
      DEBUG(2) printf("[pintool] REP@%lx has fall-through\n", (long unsigned int)ip);
      /* REP-prefixed instruction where REP is in effect (e.g. rep stos) */
      INS_InsertCall(bp, IPOINT_AFTER, AFUNPTR(RecordRep),
                          IARG_THREAD_ID,
                          IARG_ADDRINT, INS_Address(bbl),
                          IARG_ADDRINT, INS_Address(bp),
                          IARG_CONTEXT,
                          IARG_BOOL, fast_recording,
                          IARG_END);
      instrumented = true;
      DEBUG(1) printf("[pintool] Instrumented rep@%lx\n", (long unsigned int)INS_Address(bp));
    }
  }
  return instrumented;
}

/**
 * Instrument any instructions according to the knobs
 * @param ins The instruction to trace
 * @param v UNUSED
 */
VOID instrumentAnyInstructions(INS ins, VOID *v)
{
  instrumentMemIns(ins, false);
  instrumentCallBranch(ins, ins, false);
}

/**
 * Instrument only those instructions which were reported as leaking,
 * i.e. for which an entry in leaks exists.
 * @param ins The instruction to trace
 * @param v UNUSED
 */
VOID instrumentLeakingInstructions(INS ins, VOID *v)
{
  ADDRINT ip = INS_Address(ins);

  if (leaks->get_erase_dleak(ip) || leaks->was_erased_dleak(ip)) {
    /* Instrument dataleaking instruction */
    DEBUG(1) printf("[pintool] Tracing DLEAK %lx\n", (long unsigned int)ip);
    bool found = instrumentMemIns(ins, true);
    ASSERT(found, "[pintool] Error: Memory instruction to instument not found. Have you provided the flag -mem?");
  }

  if (KnobFunc.Value()) {
    /* Instrument call/ret for generating call stack */
    if (INS_IsCall(ins)) {
      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(RecordFunctionEntry),
                          IARG_THREAD_ID,
                          IARG_ADDRINT, INS_Address(ins),
                          IARG_ADDRINT, INS_Address(ins),
                          IARG_BOOL, INS_IS_INDIRECT(ins),
                          IARG_BRANCH_TARGET_ADDR,
                          IARG_BOOL, false,
                          IARG_END);
      DEBUG(1) printf("[pintool] Instrumented call stack call@%lx\n", (long unsigned int)INS_Address(ins));
    } else if (INS_IsRet(ins)) {
      ASSERT(INS_HAS_TAKEN_BRANCH(ins), "[pintool] Error: Return instruction should support taken branch.");
      INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(RecordFunctionExit),
                          IARG_THREAD_ID,
                          IARG_ADDRINT, INS_Address(ins),
                          IARG_ADDRINT, INS_Address(ins),
                          IARG_CONTEXT,
                          IARG_BOOL, false,
                          IARG_END);
      DEBUG(1) printf("[pintool] Instrumented call stack ret@%lx\n", (long unsigned int)INS_Address(ins));
    }
  }

  if (leaks->get_erase_cfleak(ip) || leaks->was_erased_cfleak(ip)) {
    /* Instrument cfleaking instruction */
    DEBUG(1) printf("[pintool] Tracing CFLEAK %lx\n", (long unsigned int)ip);

    /* Need to find actual branch inside BBL, since ins is start address of the whole BBL
     * Therefore, we assume that the *first* branch/call inside the BBL is our conditional branch/call of interest.
     * Unconditional branches must therefore have started a new BBL.
     */
    INS bp = ins;
    bool found = false;
    while (bp != INS_Invalid()) {
      DEBUG(2) printf("[pintool] Testing ins %lx\n", (long unsigned int)INS_Address(bp));
      if (instrumentCallBranch(ins, bp, true)) {
        DEBUG(2) printf("[pintool] Found bp %lx\n", (long unsigned int)INS_Address(bp));
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
VOID loadLeaks(VOID* v) {
  FILE *f = NULL;
  f = fopen(KnobLeakIn.Value().c_str(), "r");
  ASSERT(f, "[pintool] Error: Leak file does not exist");
  fseek(f, 0, SEEK_END);
  long len = ftell(f);
  rewind(f);

  DEBUG(1) printf("[pintool] Reading leaks from %s, size %ld bytes\n", KnobLeakIn.Value().c_str(), len);
  ASSERT(leaks, "[pintool] Error: Leaks not initialized");
  while(ftell(f) < len) {
    leakfmt_t elem;
    ASSERT(fread(&elem, sizeof(elem), 1, f) == 1, "[pintool] Error: Failed reading leak file");
    uint64_t callee = 0;
    DEBUG(1) printf("[pintool] Loading leak element %x, %" PRIx64 ", %d\n", elem.type, elem.ip, elem.nopt);
    switch(elem.type) {
      case FUNC_ENTRY:
        ASSERT(elem.nopt == 1, "[pintool] Error: Trace format corrupt");
        ASSERT(fread(&callee, sizeof(callee), 1, f) == 1, "[pintool] Error: Failed reading leak file");
        if (KnobCallstack.Value()) {
          leaks->call_create(elem.ip, callee);
        }
        DEBUG(1) printf("[pintool] Func entry %" PRIx64 "\n", callee);
        break;
      case FUNC_EXIT:
        ASSERT(fseek(f, elem.nopt * sizeof(uint64_t), SEEK_CUR) == 0, "[pintool] Error: Failed reading leak file");
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
        ASSERT(fseek(f, elem.nopt * sizeof(uint64_t), SEEK_CUR) == 0, "[pintool] Error: Failed reading leak file");
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
    static_cast<CallStack*>(leaks)->rewind();
  }
}

/**
 * Write traces to files
 */
VOID Fini(INT32 code, VOID *v)
{
  if (!KnobLeaks.Value()) {
    if (!KnobRawFile.Value().empty()) {
      FILE* ftrace = fopen(KnobRawFile.Value().c_str(), "w");
      if (!ftrace) {
        std::cout << "[pintool] Error: Unable to open file " << KnobRawFile.Value() << std::endl;
      } else {
        std::cout << "[pintool] Writing raw results to " << KnobRawFile.Value() << std::endl;
        bool res;
        res = fwrite(&trace[0], sizeof(entry_t), trace.size(), ftrace) == trace.size();
        fclose(ftrace);
        ASSERT(res, "[pintool] Error: Unable to write complete trace file. Out of disk memory?");
      }
    }
  /* KnobLeaks is set */
  } else {
    DEBUG(1) leaks->print_all();
    DEBUG(1) printf("[pintool] Number of uninstrumented data leaks: %zu\n", leaks->get_uninstrumented_dleak_size());
    DEBUG(1) printf("[pintool] Number of uninstrumented cflow leaks: %zu\n", leaks->get_uninstrumented_cfleak_size());
    DEBUG(1) leaks->print_uninstrumented_leaks();

    if (!KnobLeakOut.Value().empty()) {
      ASSERT(!KnobLeakIn.Value().empty(), "[pintool] Error: leakout requires leakin");
      ASSERT(leaks, "[pintool] Error: Leaks not initialized");
      FILE* fleaks = fopen(KnobLeakOut.Value().c_str(), "w");
      if (!fleaks) {
        std::cout << "[pintool] Unable to open file " << KnobLeakOut.Value() << std::endl;
      } else {
        std::cout << "[pintool] Writing leak results to " << KnobLeakOut.Value() << std::endl;
        if (use_callstack) {
          static_cast<CallStack*>(leaks)->rewind();
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

INT32 Usage()
{
  PIN_ERROR("Address Leak Detector\n"
          + KNOB_BASE::StringKnobSummary() + "\n");
  return -1;
}

int main(int argc, char *argv[])
{
  if (PIN_Init(argc, argv)) return Usage();

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

  if (!KnobLeaks.Value()) {
    /* Traditional tracing */
    if (KnobBbl.Value() || KnobMem.Value() || KnobFunc.Value()) {
      INS_AddInstrumentFunction(instrumentAnyInstructions, 0);
    }
  } else {
    /* Tracing only leaks specified by leak file */
    DEBUG(1) std::cout << "[pintool] Tracing leaks" << std::endl;
    /* calling loadLeaks via PIN_AddApplicationStartFunction.
     * This ensures the program under instrumentation is already completely loaded
     * before loadLeaks is called, thus preserving the order (and thus
     * the memory layout) in which shared libraries are loaded.
     */
    PIN_AddApplicationStartFunction(loadLeaks, 0);
    INS_AddInstrumentFunction(instrumentLeakingInstructions, 0);
  }

  PIN_AddThreadStartFunction(ThreadStart, 0);
  PIN_AddThreadFiniFunction(ThreadFini, 0);
  PIN_AddFiniFunction(Fini, 0);

  init();
  PIN_StartProgram();

  return 0;
}
