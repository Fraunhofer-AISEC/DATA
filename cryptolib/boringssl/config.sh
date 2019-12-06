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

export BORINGSSLDIR=${PWD}/boringssl
export BUILDDIR=${BORINGSSLDIR}/build/${CONFIG}
