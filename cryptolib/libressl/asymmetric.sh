#!/bin/bash

#########################################################################
# Copyright (C) 2017-2018 IAIK TU Graz and Fraunhofer AISEC
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#########################################################################
# @file asymmetric.sh
# @brief Test script for LibreSSL asymmetric ciphers.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3
#########################################################################

#########################################################################
# DO NOT CHANGE: Preparing DATA
#------------------------------------------------------------------------
source "${DATA_COMMON}/DATA_init.sh" || { echo "source data.sh first!" && exit 1; }
#########################################################################

#------------------------------------------------------------------------
# Specify your framework settings used by DATA
#------------------------------------------------------------------------

# The name of the framework. Do not use spaces or special characters.
export FRAMEWORK=libressl

# The file containing all supported algorithms
export TARGETFILE=asymmetric.txt

# The number of measurements for difference detection (phase1)
export PHASE1_TRACES=16

# The number of constant keys for generic tests (phase2)
# Make sure that PHASE2_FIXEDKEYS <= PHASE1_TRACES
export PHASE2_FIXEDKEYS=3

# The number of measurements per constant key for generic tests (phase2)
export PHASE2_TRACES=60

# The number of measurements for specific tests (phase3)
export PHASE3_TRACES=200

# If PHASE3_SKIP_PHASE2 is 1, then all phase1 differences are analyzed
export PHASE3_SKIP_PHASE2="0"

# (Optional) Additional flags for the pintool. Supported flags are:
#  -main <main>    Start recording at function <main>. Note that the <main>
#                  symbol must exist, otherwise this will yield empty traces!
#  -heap           Trace heap allocations and replace heap addresses with
#                  relative offset
export PINTOOL_ARGS=""

# If greater 0, the DSA modulus q is fixed to this number of one-MSB bits
export FIXED_MODULUS_MSBS=2

#------------------------------------------------------------------------
# Implement your framework-specific callbacks
#------------------------------------------------------------------------
#
# Globally available environment variables:
#   $FRAMEWORK           The framework name
#   $BASEDIR             The absolute directory path of this script
#   $DATA_COMMON         The absolute directory for common DATA scripts
#   $DATA_LEAKAGE_MODELS The absolute directory for DATA leakage models
#
# Available for cb_genkey, cb_pre_run, cb_run_command, cb_post_run
#   $ALGO       The currently tested algo
#
# Available for cb_pre_run, cb_run_command, cb_post_run
#   $ENVFILE

export NONCE_EXTRACTOR_DIR="${DATA_COMMON}/dsa_nonce"

# DATA callback for setting up the framework to analyze. This callback
# is invoked once inside the current directory before analysis starts.
# Implement framework-specific tasks here like framework compilation.
function cb_prepare_framework {
  source config.sh # Sets BUILDDIR environment variable
  make -s
  RES=$((RES + $?))
  make -s -C "${NONCE_EXTRACTOR_DIR}"
  RES=$((RES + $?))

  export LD_LIBRARY_PATH=${BUILDDIR}/crypto:${BUILDDIR}/ssl:${BUILDDIR}/apps/openssl
  export OPENSSL=${BUILDDIR}/apps/openssl/openssl
}

# $1 ... DSA parameter file
function get_modulus {
  # 1. Delete newlines such that sed can operate on a single line
  # 2. Extract everything between Q: and G:
  # 3. Delete spaces and :
  ${OPENSSL} pkeyparam -text -in $1 | tr -d '\n' | sed -e "s/.*Q:\(.*\)G:.*/\1/g" | tr -d " " | tr -d ":"
}

# DATA callback for generating keys. This callback is invoked every
# time a new key is needed. Implement key generation according to
# your algorithm and store the generated key inside a file named $2.
#
# $1 ... key file name
# $ALGO ... rsa/dsa/dsa_nonce/ec/ec_nonce
# $PARAM ... additional parameters
function cb_genkey {
  TMPLOGFILE=$(mktemp)
  if [[ "${ALGO}" == "rsa" ]]; then
    ${OPENSSL} genpkey -algorithm "rsa" -out "$1" &>> ${TMPLOGFILE}
    RES=$((RES + $?))
  elif [[ "${ALGO}" == "ec" || "${ALGO}" == "ec_nonce" ]]; then
    echo "ECDSA with curve ${PARAM}" >> ${TMPLOGFILE}
    ${OPENSSL} genpkey -genparam -algorithm "ec" -pkeyopt "ec_paramgen_curve:${PARAM}" -out "ec.param" &>> ${TMPLOGFILE}
    RES=$((RES + $?))
    ${OPENSSL} genpkey -paramfile "ec.param" -out "$1" &>> ${TMPLOGFILE}
    RES=$((RES + $?))
  elif [[ "${ALGO}" == "dsa" || "${ALGO}" == "dsa_nonce" ]]; then
    OPTIONS="-pkeyopt dsa_paramgen_q_bits:${PARAM}"
    echo "DSA with parameter ${OPTIONS}" &>> ${TMPLOGFILE}
    if [[ "${FIXED_MODULUS_MSBS}" -gt "0" ]]; then
      ITER=0
      MAXITER=1000
      while ! [[ -f "${ALGO}.param" ]]; do
        ITER=$((ITER+1))
        if [[ "${ITER}" -ge "${MAXITER}" ]]; then
          log_error "Failed to create modulus with MSB=${FIXED_MODULUS_MSBS} within ${MAXITER} iterations"
          exit 1
        fi
        # Generate one fixed DSA parameter set where the topmost bits of q are set, according to FIXED_MODULUS_MSBS
        ${OPENSSL} genpkey -genparam -algorithm "dsa" ${OPTIONS} -out "${ALGO}-tmp.param" &>> ${TMPLOGFILE}
        RES=$((RES + $?))
        if [[ "${RES}" -gt "0" ]]; then
          break
        fi
        q=$(get_modulus "${ALGO}-tmp.param")
        msbs=$(${DATA_COMMON}getmsbs.py "0x$q")
        echo "q=0x$q ($msbs MSBs)"
        if [[ "$msbs" -ne "${FIXED_MODULUS_MSBS}" ]]; then
          rm "${ALGO}-tmp.param"
        else
          mv "${ALGO}-tmp.param" "${ALGO}.param"
        fi
      done
    else
      # Always generate new DSA parameters
      ${OPENSSL} genpkey -genparam -algorithm "dsa" ${OPTIONS} -out "${ALGO}.param" &>> ${TMPLOGFILE}
      RES=$((RES + $?))
    fi
    ${OPENSSL} genpkey -paramfile "${ALGO}.param" -out "${1}" &>> ${TMPLOGFILE}
    RES=$((RES + $?))
  else
    pass
  fi
  if [[ "${RES}" -ne "0" ]]; then
    print_error "Failed generating key/param!"
    cat ${TMPLOGFILE} >> ${LOGFILE}
  fi
  rm ${TMPLOGFILE}
}

# DATA callback for custom commands that are executed immediately before
# the algorithm is profiled. It is executed in a temporary directory
# which contains the keyfile $1 and ${ENVFILE}.
#
# If 'cb_run_command' needs any other files, copy them to ${PWD}.
#
# $1 ... key file name
function cb_pre_run {
  # Create input file
  # RSA input must match exactly size of modulus N.
  # Hence, we use sha1 instead, which is 20 bytes.
  echo -n "00000000000000000000" > input.bin

  # Update environment to use our own LibreSSL compilation
  echo "LD_LIBRARY_PATH=${LD_LIBRARY_PATH}" >> "${ENVFILE}"
  log_verbose "running with key $1"
}

# DATA callback for the main invocation of the tested algorithm.
# It shall return the bash command to execute as string. It is
# executed inside a temporary directory with a clean environment.
# If you need special files or environment variables set, specify
# them in cb_pre_run.
#
# $1 ... key file name
function cb_run_command {
  echo "${OPENSSL} pkeyutl -sign -in input.bin -out output.bin -inkey ${1} -pkeyopt digest:sha1"
}

# DATA callback for custom commands that are executed immediately after
# the algorithm is profiled. It is executed in a temporary directory.
# You can cleanup any custom files generated by your algorithm.
#
# $1 ... key file name
function cb_post_run {
  if [[ "${PERSIST_ARTIFACTS}" == "1" ]]; then
    :
  else
    rm -f "$1.A" "$1.B" input.bin output.bin
  fi
}

# Function returns filename (relative path) or empty string on error
function cb_pre_leakage_model {
  KEYFILE="${1}"

  if [[ "${ALGO}" == "ec_nonce" ]]; then
    NONCE_EXTRACTOR_BIN="${NONCE_EXTRACTOR_DIR}/ecdsa_nonce"
  elif [[ "${ALGO}" == "dsa_nonce" ]]; then
    NONCE_EXTRACTOR_BIN="${NONCE_EXTRACTOR_DIR}/dsa_nonce"
  else
    return
  fi

  OUTPUT=$( "${NONCE_EXTRACTOR_BIN}" "${KEYFILE}" output.bin input.bin 2>&1 )
  RES=$?
  if [[ "${RES}" -ne "0" ]]; then
    # redirect to stderr because we can only print the return value to stdout
    (>&2 log_error "cb_pre_leakage_model: Error while running: ${NONCE_EXTRACTOR_BIN} '${KEYFILE}' '${PWD}/output.bin' '${PWD}/input.bin'")
    (>&2 log_error "cb_pre_leakage_model: ${OUTPUT}")
    echo ""
  else
    echo "${OUTPUT}" > output.nonces
    echo "output.nonces"
  fi
}

function cb_targets {
  echo "####################"
  echo "Supported ec curves:"
  echo "####################"
  ${OPENSSL} ecparam -list_curves
}

# Sets callback for specific leakage test
function update_leakage_model {
  if [[ "${ALGO}" == "rsa" ]]; then
    export SPECIFIC_LEAKAGE_CALLBACK=${DATA_LEAKAGE_MODELS}/rsa_privkey_hw.py
  elif [[ "${ALGO}" == "dsa_nonce" ]]; then
    export SPECIFIC_LEAKAGE_CALLBACK=${DATA_LEAKAGE_MODELS}/dsa_nonce.py
  elif [[ "${ALGO}" == "dsa" ]]; then
    export SPECIFIC_LEAKAGE_CALLBACK=${DATA_LEAKAGE_MODELS}/dsa_privkey_hw.py
  elif [[ "${ALGO}" == "ec_nonce" ]]; then
    export SPECIFIC_LEAKAGE_CALLBACK=${DATA_LEAKAGE_MODELS}/dsa_nonce.py
  elif [[ "${ALGO}" == "ec" ]]; then
    export SPECIFIC_LEAKAGE_CALLBACK=${DATA_LEAKAGE_MODELS}/ecdsa_privkey_hw.py
  fi
}

# DATA callback for preparing an individual algorithm. It shall:
# 1. Parse the next algorithm from the commandline string of all algorithms
#    and set up anything necessary for analyzing this algorithm.
#    If the algorithm needs additional parameters (like key sizes), 
#    increase $SHIFT accordingly.
# 2. Configure $WORKDIR, which will create a subdirectory holding all
#    intermediate files generated by the algorithm and the results.
#    Do not use an absolute path!
#
# $* ... algorithm string from the commandline
function cb_prepare_algo {
  PERSIST_ARTIFACTS=""
  ALGO=$1
  PARAM=$2
  SHIFT=$((SHIFT+1))
  if [[ "${ALGO}" == "dsa_nonce" || "${ALGO}" == "ec_nonce" ]]; then
    # For nonce analysis, we need the artifacts (the signatures)
    # to compute the nonce
    PERSIST_ARTIFACTS="1"
    # Phase 2 needs to be skipped in order for SPEcific tests to use
    # the unfiltered phase 1 results
    export PHASE3_SKIP_PHASE2="1"
  fi
  update_leakage_model

  WORKDIR="$FRAMEWORK/$CONFIG/$ALGO/$PARAM"
}

#########################################################################
# DO NOT CHANGE: Running DATA's commandline parser
#------------------------------------------------------------------------
DATA_parse "$@"
#------------------------------------------------------------------------
# DO NOT ADD CODE AFTER THIS LINE
#########################################################################
