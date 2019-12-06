#!/bin/bash
#------------------------------------------------------------------------
# Configuration
#------------------------------------------------------------------------

if [[ -z "${SETARCH}" ]]; then
  SETARCH=$(arch)
fi
CONFIG="${SETARCH}"

if [[ "${FLAGS}" != "" ]]; then
  CONFIG+="-${FLAGS// /-}" # replace spaces with ','
fi

BUILDDIR=${PWD}/build/${CONFIG}
export CONFIG
export BUILDDIR
