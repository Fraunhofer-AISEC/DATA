#if !defined(UTILS_H_)
#define UTILS_H_

#include "pin.H"
#include "proc-map.H"

extern int DEBUG_LEVEL;

#define DEBUG(x) if (DEBUG_LEVEL >= x)
#define MESSAGE(x, y) std::cout << x << y << std::endl
#define PT_DEBUG(x, msg) DEBUG(x) MESSAGE("[pt-dbg" << x << "] ", msg)
#define PT_INFO(msg) MESSAGE("[pt-info] ", msg)
#define PT_WARN(msg) MESSAGE("[pt-warn] ", msg)
#define PT_ASSERT(x, msg)                                                      \
    {                                                                          \
        if (!(x)) {                                                            \
            printProcMap();                                                    \
            MESSAGE("[pt-error] ", msg);                                       \
            ASSERT(false, "pintool failed.");                                  \
        }                                                                      \
    }
#define PT_ERROR(msg) PT_ASSERT(false, msg)

// TODO PT_ASSERT
//            printheap();
//            print_allocmap();

#endif
