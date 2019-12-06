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
# @file symmetric.sh
# @brief Test script for OpenSSL symmetric ciphers.
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
export FRAMEWORK=openssl

# The file containing all supported algorithms
export TARGETFILE=symmetric.txt

# The number of measurements for difference detection (phase1)
export PHASE1_TRACES=3

# The number of constant keys for generic tests (phase2)
# Make sure that PHASE2_FIXEDKEYS <= PHASE1_TRACES
export PHASE2_FIXEDKEYS=3

# The number of measurements per constant key for generic tests (phase2)
export PHASE2_TRACES=60

# The number of measurements for specific tests (phase3)
export PHASE3_TRACES=200

# (Optional) Additional flags for the pintool. Supported flags are:
#  -main <main>    Start recording at function <main>. Note that the <main>
#                  symbol must exist, otherwise this will yield empty traces!
#  -heap           Trace heap allocations and replace heap addresses with 
#                  relative offset
export PINTOOL_ARGS=""

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

# The leakage model of phase 3.
# See ${DATA_LEAKAGE_MODELS} for all options.
export SPECIFIC_LEAKAGE_CALLBACK=${DATA_LEAKAGE_MODELS}/sym_byte_value.py

# DATA callback for setting up the framework to analyze. This callback
# is invoked once inside the current directory before analysis starts.
# Implement framework-specific tasks here like framework compilation.
function cb_prepare_framework {
  source config.sh # Sets BUILDDIR environment variable
  make -s
  RES=$((RES + $?))

  export LD_LIBRARY_PATH=${BUILDDIR}/openssl
  export OPENSSL=${BUILDDIR}/openssl/apps/openssl
}

# DATA callback for generating keys. This callback is invoked every
# time a new key is needed. Implement key generation according to
# your algorithm and store the generated key inside a file named $2.
#
# $1 ... key file name
function cb_genkey {
  "${DATA_COMMON}"/genkey.py "${KEYBYTES}" > "$1"
  RES=$((RES + $?))
}

# DATA callback for custom commands that are executed immediately before
# the algorithm is profiled. It is executed in a temporary directory
# which contains the keyfile $1 and ${ENVFILE}.
#
# If 'cb_run_command' needs any other files, copy them to ${PWD}.
#
# $1 ... key file name
function cb_pre_run {
  rm -f "${ALG_OUTFILE}"
  echo "hello" > input.bin

  # Update environment to use our own OpenSSL compilation
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
  HEXKEY=$(cat "$1")
  echo "${OPENSSL} ${ALGO} -e -in input.bin -out output.bin -nosalt -K ${HEXKEY} -iv 0"
}

# DATA callback for custom commands that are executed immediately after
# the algorithm is profiled. It is executed in a temporary directory.
# You can cleanup any custom files generated by your algorithm.
#
# $1 ... key file name
function cb_post_run {
  rm -f input.bin output.bin
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
  ALGO=$1
  # key bits
  PARAM=$2
  SHIFT=$((SHIFT+1))
  KEYBYTES=$(( PARAM / 8 ))

  WORKDIR="$FRAMEWORK/$CONFIG/$ALGO/$PARAM"
}

#########################################################################
# DO NOT CHANGE: Running DATA's commandline parser
#------------------------------------------------------------------------
DATA_parse "$@"
#------------------------------------------------------------------------
# DO NOT ADD CODE AFTER THIS LINE
#########################################################################
