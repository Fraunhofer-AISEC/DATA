# Changelog

This files contains all notable changes for each version of DATA.

## Versions

- [v0.2](#v0.2)
- [v0.1](#v0.1)

## v0.2

### Added

- Support for the graphical user interface (GUI) available
  [here](https://github.com/IAIK/data-gui). Note that DATA
  v0.2 is compatible with DATA GUI v1.1, but not necessarily
  other versions.
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

