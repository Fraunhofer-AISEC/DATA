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
# @brief Test script for pycrypto symmetric ciphers.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.2
#########################################################################

#------------------------------------------------------------------------
# Specify your framework settings used by DATA
#------------------------------------------------------------------------

# The name of the framework. Do not use spaces or special characters.
export FRAMEWORK=python

# The file containing all supported algorithms, line separated
export TARGETFILE=symmetric.txt

# The number of measurements for difference detection (phase1)
export NTRACE_DIFF=3

# The number of constant keys for generic tests (phase2)
# Make sure that NREPS_GEN <= NTRACE_DIFF
export NREPS_GEN=3

# The number of measurements per constant key for generic tests (phase2)
export NTRACE_GEN=60

# The number of measurements for specific tests (phase3)
export NTRACE_SPE=200

# (Optional) Additional flags for the pintool. Supported flags are:
#  -main <main>    Start recording at function <main>. Note that the <main>
#                  symbol must exist, otherwise this will yield empty traces!
#  -heap           Trace heap allocations and replace heap addresses with 
#                  relative offset
export PINTOOL_ARGS=" -main Py_Main"

#########################################################################
# DO NOT CHANGE: Preparing DATA
#------------------------------------------------------------------------
export COMMON="${PWD}/../common/"
source "${COMMON}common.sh"
#########################################################################

#------------------------------------------------------------------------
# Implement your framework-specific callbacks
#------------------------------------------------------------------------
#
# Globally available environment variables:
#   $FRAMEWORK    The framework name
#   $BASEDIR      The absolute directory path of this script
#   $COMMON       The absolute directory for common DATA scripts
#   $ANALYSISDIR  The absolute directory for DATA Python analysis scripts
#
# Available for cb_genkey, cb_pre_run, cb_run_command, cb_post_run
#   $ALGO       The currently tested algo
#
# Available for cb_pre_run, cb_run_command, cb_post_run
#   $ENVFILE

# The leakage model of phase 3.
# See ${ANALYSISDIR}/leakage_models for all options.
export SPECIFIC_LEAKAGE_CALLBACK=${ANALYSISDIR}/leakage_models/sym_byte_value_from_bin.py
export INTERPRETER=$PWD/.pyenv27/bin/python

# DATA callback for setting up the framework to analyze. This callback
# is invoked once inside the current directory before analysis starts.
# Implement framework-specific tasks here like framework compilation.
function cb_prepare_framework {
  make -s
}

# DATA callback for generating keys. This callback is invoked every
# time a new key is needed. Implement key generation according to
# your algorithm and store the generated key inside a file named $2.
#
# $1 ... key file name
function cb_genkey {
  ${INTERPRETER} "${BASEDIR}/symmetric.py" genkey "$ALGO" "$1"
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
  # Update environment to use our own OpenSSL compilation
  echo "LC_ALL=C.UTF-8" >> "${ENVFILE}"
  echo "LANG=C.UTF-8" >> "${ENVFILE}"
}

# DATA callback for the main invocation of the tested algorithm.
# It shall return the bash command to execute as string. It is
# executed inside a temporary directory with a clean environment.
# If you need special files or environment variables set, specify
# them in cb_pre_run.
#
# $1 ... key file name
function cb_run_command {
  echo "${INTERPRETER} ${BASEDIR}/symmetric.py run $ALGO $1"
}

# DATA callback for custom commands that are executed immediately after 
# the algorithm is profiled. It is executed in a temporary directory.
# You can cleanup any custom files generated by your algorithm.
#
# $1 ... key file name
function cb_post_run {
  :
}

# DATA callback for testing an individual algorithm. It shall parse
# the next algorithm from the commandline string, update $ALGO and
# invoke 'run' accordingly. If the algorithm needs additional
# parameters (like key sizes), increase $SHIFT accordingly.
#
# $* ... algorithm string from the commandline
function cb_run_single {
  ALGO=$1
  DATA_run
}

#########################################################################
# DO NOT CHANGE: Running DATA's commandline parser
#------------------------------------------------------------------------
DATA_parse "$@"
#------------------------------------------------------------------------
# DO NOT ADD CODE AFTER THIS LINE
#########################################################################
