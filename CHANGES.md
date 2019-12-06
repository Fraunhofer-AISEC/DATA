# Changelog

This files contains all notable changes for each version of DATA.

## Versions

- [v0.3](#v0.3)
- [v0.2](#v0.2)
- [v0.1](#v0.1)

## v0.3

Version of DATA as used in the Usenix Security'20 paper **Big Numbers --
Big Troubles**

### Updated
- Made cryptolib directory independent of DATA. To run:
  1. `source data.sh` globally
  2. `source ${DATA_COMMON}/DATA_init.sh` within the framework script
  3. Run analysis via framework script instead of Makefile
- In the framework script, renamed
  - COMMON -> DATA_COMMON
  - ANALYSISDIR/leakage_models -> DATA_LEAKAGE_MODELS
  - DATA_LEAKAGE_MODELS
  - cb_run_single -> cb_prepare_algo
  - NTRACE_DIFF -> PHASE1_TRACES
  - NREPS_GEN   -> PHASE2_FIXEDKEYS
  - NTRACE_GEN  -> PHASE2_TRACES
  - NTRACE_SPE  -> PHASE3_TRACES

- Runtime of phase3 increased by parallel programming and optimized
  RDC precomputation
- Updated Intel Pin from 3.7 to 3.11

### Added
- BoringSSL, LibreSSL
- Support for nonce leakage:
  - PHASE3_SKIP_PHASE2: phase3 analyzes *all* phase1 differences rather
                        than phase2 leaks only
  - PERSIST_ARTIFACTS:  keep run artifacts for phase3 analysis (e.g. for
                        recovering nonces)
  - Nonce recovery in ${DATA_COMMON}/dsa_nonce
- Generic OpenSSL compilation in ${DATA_COMMON}/openssl

### Removed
- `common.sh -n` Result directory must be specified explicitly.
                 This allows to run multiple instances of the same
                 script in parallel

### Known issues
- Intel RTM (TSX): Tracing of XABORT following an indirect jump fails
                   in Pintool. Workaround: Disable RTM/TSX in the CPU 
                   MSR, or try to switch back to Intel Pin 3.7 (in 
                   DATA/pin/Makefile).

## v0.2

### Added

- Support for the graphical user interface (GUI) available 
  [here](https://github.com/IAIK/data-gui). Note that DATA v0.2 is 
  compatible with DATA GUI v1.1, but not necessarily other versions.
- Command to start GUI with example analysis (`make gui`).
- Template directory to simplify adding new cryptolibs.
- README.md that explains how to preload shared libraries.
- README.md for PyCrypto.
- Changelog to track versions and changes.

### Changed

- DATA framework now requires Python v3.5.
- Authors are now listed in separate AUTHORS.md file.
- Improved support for preloading shared libraries.

### Fixed

- Created leak objects with invalid RDC result under certain
  circumstances.

## v0.1

Initial version of DATA as used in the corresponding
[publication](https://www.usenix.org/conference/usenixsecurity18/presentation/weiser).

