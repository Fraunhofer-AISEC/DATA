#------------------------------------------------------------------------
# Configuration
#------------------------------------------------------------------------
if [[ -z "${SETARCH}" ]]; then
  SETARCH=$(arch)
fi
CONFIG="${SETARCH}"

if [[ "${FLAGS}" != "" ]]; then
  CONFIG+="${FLAGS// /}" # strip spaces in flags
fi

export LIBRESSLDIR=${PWD}/portable
export BUILDDIR=${LIBRESSLDIR}/build/${CONFIG}
