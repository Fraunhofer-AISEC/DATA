#if !defined(PIN_MACROS_H_)
#define PIN_MACROS_H_

/**
 * We support Pin 3.11-97998 Documentation:
 * https://software.intel.com/sites/landingpage/pintool/docs/97998/Pin/html
 */
#define INS_DIRECT INS_DirectControlFlowTargetAddress
#define INS_IS_DIRECT INS_IsDirectControlFlow
#define INS_IS_INDIRECT INS_IsIndirectControlFlow
#define INS_HAS_TAKEN_BRANCH INS_IsValidForIpointTakenBranch
#define INS_HAS_IPOINT_AFTER INS_IsValidForIpointAfter

#endif
