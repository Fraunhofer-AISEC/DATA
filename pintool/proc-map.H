#if !defined(PROC_MAP_H_)
#define PROC_MAP_H_

#include "pin.H"

void printProcMap(void);
ADDRINT getAddrFromProcMap(const std::string command, short pos);

#endif
