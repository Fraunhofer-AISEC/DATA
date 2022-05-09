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
# @file common.sh
# @brief Main framework script.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3
#########################################################################

#------------------------------------------------------------------------
# Settings
#------------------------------------------------------------------------

if [[ "${DATA_ROOT}" == "" ]]; then
  echo "DATA not loaded! 'source data.sh' first"
  return 1
fi

# DEBUG can be any non-negative digit
if ! [[ "${DEBUG}" =~ "^[0-9]+$" ]] && [[ "${DEBUG}" -gt "0" ]]; then
  export DEBUG=${DEBUG}
else
  export DEBUG=0
fi

# PinTool architecture
if [[ -z "${SETARCH}" ]]; then
  SETARCH=$(arch)
fi

export PIN=${PIN_ROOT}/pin
export PINTOOL=${DATA_ROOT}/pintool/${SETARCH}/addrtrace.so

# PinTool arguments
#
# By restricting memory, we ensure that multiple invocations of Pin have the same memory layout
# If Pin segfaults, try to find a better memory layout
if [[ "${SETARCH}" == "i386" ]]; then
export PINFLAGS="-ifeellucky -restrict_memory 0x10000000:0x50000000 -pin_memory_range 0x100000000:0xF00000000"
else
export PINFLAGS="-ifeellucky -restrict_memory 0x50000000:0x70000000 -pin_memory_range 0x100000000:0xF00000000"
fi

export STDARGS="-debug ${DEBUG} -bbl -func -mem -cs"
export OUTFMT="-raw"
export LEAKIN="-leakin"
export LEAKOUT="-leakout"

# Directories
export PRELOAD=${DATA_ROOT}/cryptolib/common/preload/
export CLEANENV=${DATA_ROOT}/cryptolib/common/cleanenv
export CLEANENVVAR=""
export ANALYZE="python ${DATA_ROOT}/analysis/analyze.py"
export LOGFILE="test.log"
export ENVFILE="env.txt"
export NODIFFFILE="nodiff"

# Number formatting
export LC_NUMERIC="en_US.UTF-8"

#------------------------------------------------------------------------
# Internal Members and Settings (Do Not Change)
#------------------------------------------------------------------------

# Commands
ABORT_ON_ERROR=1
DO_GENKEYS=0
DO_PHASE1_MEASURE=0
DO_PHASE1_ANALYZE=0
DO_PHASE2_MEASURE=0
DO_PHASE2_ANALYZE=0
DO_PHASE3_MEASURE=0
DO_PHASE3_ANALYZE=0
DO_CLEANUP=0
DO_PARALLEL=0
DO_TRACE_REUSE=0
DO_FINAL=0
DO_EXPORT=0
DO_DRY=0
DO_GUI=0

# Extension for trace files
TRACEEXT=trace

# Intermediate files / directories
PHASE2_FIXDIR="gen_trc_fix"
PHASE2_RNDDIR="gen_trc_rnd"
PHASE2_KEYDIR="gen_key_rnd"
PHASE2_RNDPIC="gen_rnd.pickle"
PHASE2_FIXPICS="gen_fix_[0-9]*.pickle result_gen_[0-9]*.pickle"
PHASE3_RNDDIR="spe_trc_rnd"
PHASE3_KEYDIR="spe_key_rnd"
PHASE3_RNDPIC="spe_rnd.pickle"

# Analysis variables
SYMFILE=pinsyms.txt
EXTSYMFILE=allsyms.txt
RESPICFILE_PHASE1=result_phase1.pickle
RESPICFILE_PHASE2=result_phase2.pickle
RESPICFILE_PHASE3=result_phase3
RESPICFILE_FINAL=result_final.pickle
RESXMLFILE_PHASE1=result_phase1.xml
RESXMLFILE_PHASE2=result_phase2.xml
RESXMLFILE_PHASE3=result_phase3
RESXMLFILE_FINAL=result_final.xml
LEAKFILE=leaks.bin
EXPORTFILE=framework.zip

# Measurement phases
PHASE1="1"
PHASE2="2"
PHASE3="3"

# Output colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log levels
LL_INFO="Info"
LL_WARN="Warn"
LL_ERR="Error"

# Performance measurements
START_TIME_REAL=0
START_TIME_CPU=0
PEAK_MEMORY=0
CLK_TCK_SEC=$(getconf CLK_TCK)

# Parallel execution
NUMPROC=$(nproc)
declare -a WAITPIDS
RES=0

#------------------------------------------------------------------------
# Helper Functions
#------------------------------------------------------------------------

# Starts the GUI with the latest result
# Requires "datagui" to be in the PATH variable
function start_gui {
  enter_workdir
  local LATEST=${RESPICFILE_FINAL}
  local FRAMEWORK_FILE=$(readlink -f ${EXPORTFILE})
 
  if [[ ! -f "${LATEST}" ]]; then
    LATEST=${RESPICFILE_PHASE2}
  fi

  if [[ ! -f "${LATEST}" ]]; then
    LATEST=${RESPICFILE_PHASE1}
  fi

  LATEST=$(readlink -f ${LATEST})

  leave_workdir

  datagui "${LATEST}" "${FRAMEWORK_FILE}"
}

# Log
function print_color {
  if [[ "${4}" == "" ]]; then
    if [ -t 1 ]; then
      printf "${2}[%s]${NC}" "${3}"
    else
      printf "[${1}][%s]" "${3}"
    fi
  else
    if [ -t 1 ]; then
      printf "${2}[%s%s]${NC}" "${3}" "${4}"
    else
      printf "[${1}][%s%s]" "${3}" "${4}"
    fi
  fi
}

function GET_ID {
  if ! [[ -z "${WORKDIR}" ]]; then
    ID="${WORKDIR}"
  elif ! [[ -z "${FRAMEWORK}" ]]; then
    ID="${FRAMEWORK}"
  else
    ID="DATA"
  fi
  echo "${ID}"
}

function print_error {
  print_color "${LL_ERR}" "${RED}" "$(GET_ID)"
  echo "$*"
}

function log_error {
  echo "$*" >> ${LOGFILE}
  print_error "$*"
}

function print_warning {
  print_color "${LL_WARN}" "${YELLOW}" "$(GET_ID)"
  echo "$*"
}

function log_warning {
  echo "$*" >> ${LOGFILE}
  print_color "${LL_WARN}" "${YELLOW}" "$(GET_ID)"
  echo "$*"
}

function print_info {
  print_color "${LL_INFO}" "${GREEN}" "$(GET_ID)"
  echo "$*"
}

function log_info {
  echo "$*" >> ${LOGFILE}
  print_info "$*"
}

function log_verbose {
  echo "$*" >> ${LOGFILE}
}

# Directories
function enter_workdir {
  local L_WORKDIR=${RESULTDIR}/${WORKDIR}
  mkdir -p "${L_WORKDIR}"
  pushd "${L_WORKDIR}" &> /dev/null
}

function leave_workdir {
  popd &> /dev/null
}

function leave_frameworkdir {
  leave_workdir
}

function cleanup {
  enter_workdir
  log_info "Cleaning up working directory."
  # Remove phase1 trace files
  rm -f ./*.${TRACEEXT}
  # Remove phase1 intermediate pickle files
  rm -f phase1*[0-9]*-[0-9]*.pickle
  # Remove phase2 traces
  rm -f ./${PHASE2_FIXDIR}/*.${TRACEEXT}
  rm -f ./${PHASE2_RNDDIR}/*.${TRACEEXT}
  # Remove phase 2 intermediate pickle files
  rm -f ${PHASE2_RNDPIC} ${PHASE2_FIXPICS}
  # Remove phase 3 traces
  rm -f ./${PHASE3_RNDDIR}/*.${TRACEEXT}
  # Keep phase 3 intermediate pickle file, as it might be used with different leakage models
  # ${PHASE3_RNDPIC}
  log_info "Cleaning up completed."
  leave_workdir
}

# performance
function subfloat {
  echo "$1 $2" | awk "{printf \"%.4f\", \$1-\$2}"
}
function divfloat {
  echo "$1 $2" | awk "{printf \"%.4f\", \$1/\$2}"
}
function setstarttime {
  getelapsedtime
  START_TIME_REAL=$CUR_TIME_REAL
  START_TIME_CPU=$CUR_TIME_CPU
}
function getelapsedtime {
  CUR_TIME_REAL=$(date +"%s.%N")
  T1=$(awk "{print \$14}" < "/proc/$$/stat")
  T2=$(awk "{print \$15}" < "/proc/$$/stat")
  T3=$(awk "{print \$16}" < "/proc/$$/stat")
  T4=$(awk "{print \$17}" < "/proc/$$/stat")
  CUR_TIME_CPU=$(( T1 + T2 + T3 + T4 ))
  CUR_TIME_CPU=$(divfloat "${CUR_TIME_CPU}" "${CLK_TCK_SEC}")
  DIFF_TIME_REAL=$(subfloat "${CUR_TIME_REAL}" "${START_TIME_REAL}")
  DIFF_TIME_CPU=$(subfloat "${CUR_TIME_CPU}" "${START_TIME_CPU}")
}
function getpeakmemory {
  enter_workdir
  PEAK_MEMORY=0
  if [[ -f "${LOGFILE}" ]]; then
    PEAK_MEMORY=$(awk -F "=" '/memory=/ {printf "%1.2f\n", $2 / 1024}' "${LOGFILE}" | sort -g | tail -n 1)
  fi
  leave_workdir
}

# Interprets the supplied arguments as a command and runs it.
# If DO_PARALLEL set to 1 the command runs in the background, WAITPIDS will 
# be filled, and wait_subprocesses has to be called to wait for the 
# background processes.
function execpar {
  if [[ "${DO_PARALLEL}" -eq "1" ]]; then
    while [ "$(jobs | wc -l)" -ge "${NUMPROC}" ]; do
      sleep 1
    done
    # run command in background:
    "$@" &
    # add background task to wait list
    WAITPIDS+=($!)
  else
    # run command
    "$@"
  fi
}

# Wait for all subprocesses that are listed in WAITPIDS.
# Sets RES to the cumulated result of the processes
function wait_subprocesses {
  RES=0
  # wait for all WAITPIDS
  for pid in ${WAITPIDS[*]}; do
      wait $pid
      RES=$(($RES + $?))
  done
  WAITPIDS=()
}

# Is called before actual work is done
# FRAMEWORK is already specified
function init_for_run {
  if [[ -z ${RESULTDIR} ]]; then
    print_warning "RESULTDIR not specified! Using current directory"
    export RESULTDIR="$PWD/results"
  fi
  pushd "${PRELOAD}" &> /dev/null
  CLEANENVVAR=$(./preload.sh) || RES=$?
  popd &> /dev/null
  abortonerror

  RES=0
  cb_prepare_framework
  abortonerror
}

# $1 ... keyfile
function genkey_wrapper {
  RES=0
  cb_genkey "$1"
  abortonerror
  if [[ ! -f "$1" ]]; then
    log_error "Generation of key $1 failed"
    abort
  fi
}

# $1 ... filename
# $2 ... key size in bytes
function gen_random_binkey_file {
  dd if=/dev/urandom of="$1" bs="$2" count=1 2> /dev/null
}

# $PHASE1_TRACES ... number keys to generate for phase 1
function gen_keys {
  enter_workdir
  NK=$PHASE1_TRACES
  if [[ "$PHASE2_FIXEDKEYS" -gt "$NK" ]]; then
    log_warning "PHASE2_FIXEDKEYS > PHASE1_TRACES (${PHASE2_FIXEDKEYS} > ${PHASE1_TRACES}). Using ${PHASE2_FIXEDKEYS} keys."
    NK=$PHASE2_FIXEDKEYS
  fi
  log_info "Generating $NK keys"
  for i in $(seq 1 "$NK"); do
    KEYFILE=key$i.key
    if ! [[ -f ${KEYFILE} ]]; then
      genkey_wrapper "$KEYFILE"
    fi
  done
  leave_workdir
}

function list_targets {
  echo "List of supported target algorithms:"
  echo "====================================="

  if [[ -f ${TARGETFILE} ]]; then
    while read LINE; do
      if [[ "${LINE}" == "" ]] || [[ ${LINE} == "#*" ]]; then
        # Skip comments and empty lines
        continue
      fi
      echo "${LINE}"
    done < "${TARGETFILE}"
  else
    echo "No TARGETFILE specified"
  fi

  # If cb_targets is specified, call it
  type cb_targets &>/dev/null
  if [[ "$?" -eq "0" ]]; then
    cb_targets
  fi
}

#------------------------------------------------------------------------
# Execution and Instrumentation
#------------------------------------------------------------------------

function execute {
  log_verbose "[$BASHPID] RUNNING $*"
  /usr/bin/time -f "system=%S\nuser=%U\ntotal=%e\nmemory=%M" -a -o "${LOGFILE}" bash -c "$* &>> ${LOGFILE}"
  RES=$?
  log_verbose "[$BASHPID] run_status=$RES"
  abortonerror
}

function execute_noerror {
  log_verbose "[$BASHPID] RUNNING $*"
  /usr/bin/time -f "system=%S\nuser=%U\ntotal=%e\nmemory=%M" -a -o "${LOGFILE}" bash -c "$* &>> ${LOGFILE}"
  RES=$?
  log_verbose "[$BASHPID] run_status=$RES"
}

function execute_clean {
  log_verbose "[$BASHPID] RUNNING ${CLEANENV} ${ENVFILE} $*"
  touch "${ENVFILE}"
  /usr/bin/time -f "system=%S\nuser=%U\ntotal=%e\nmemory=%M" -a -o "${LOGFILE}" "${CLEANENV}" ${ENVFILE} $* &>> ${LOGFILE}
  RES=$?
  log_verbose "[$BASHPID] run_status=$RES"
}

# Run program with PIN instrumentation.
# This function is thread-safe.
#
# $1 ... phase, either "1", "2", or "3".
# $2 ... output file name. if "debug" is specified, run without pin.
# $3 ... keyfile.
function run_pin {
  PHASE=$1
  OUTFILE=$2
  KEY=$3
  if [[ ! -f "${KEY}" ]]; then
    log_warning "Key file ${KEYFILE} missing"
  fi
  # binary input file name. contains previous leaks of phase 1.
  INFILE=${LEAKFILE}
  TMPKEY=tmpkey.key
  TMPTRACE=trace.trace
  TARGETDIR=${PWD}
  # Work in a separate subdir to allow parallel runs
  SUBDIR=$(printf "%08d" ${BASHPID})
  rm -rf "${SUBDIR}"
  mkdir -p "${SUBDIR}"
  pushd "${SUBDIR}" &> /dev/null
  # Copy key file
  cp "${TARGETDIR}"/"${KEY}" ${TMPKEY}
  if [[ -f ${TARGETDIR}/${INFILE} ]]; then
    ln -s "${TARGETDIR}"/${INFILE} ${INFILE}
  fi

  echo "${CLEANENVVAR}" > ${ENVFILE}
  # Custom pre_run has to copy other necessary files from ${WORKDIR} to ${PWD} (which is ${SUBDIR})
  if [[ "${DO_DRY}" -ne "0" ]]; then
    log_info "Dry-run: Executing inside ${PWD}"
  fi
  RES=0
  cb_pre_run "${TMPKEY}"
  abortonerror
  CURCMD=$(cb_run_command ${TMPKEY})
  if [[ "$PHASE" -eq "1" ]]; then
    FASTRECORDING=0
  else
    FASTRECORDING=1
  fi
  execute_clean "${PIN} ${PINFLAGS} -t ${PINTOOL} ${PINTOOL_ARGS} -leaks ${FASTRECORDING} ${STDARGS} ${OUTFMT} ${TMPTRACE} ${LEAKOUT} ${TMPTRACE} ${LEAKIN} ${INFILE} -syms ${SYMFILE} -- ${CURCMD}"
  cat "${LOGFILE}" >> "../"${LOGFILE} # merge logfile from subdir
  abortonerror

  RES=0
  cb_post_run "${TMPKEY}"
  abortonerror

  popd &> /dev/null

  if [[ "${DO_DRY}" -eq "0" ]]; then
    rm -f "${SUBDIR}"/"${LOGFILE}" "${SUBDIR}"/"${TMPKEY}" "${SUBDIR}"/"${INFILE}"
    if [[ -f ${SUBDIR}/${TMPTRACE} ]]; then
      mv "${SUBDIR}"/"${TMPTRACE}" "${OUTFILE}"
    fi
    mv "${SUBDIR}"/"${SYMFILE}" . &>/dev/null
    mv "${SUBDIR}"/"${EXTSYMFILE}" . &>/dev/null
    mv "${SUBDIR}/vdso.so" . &>/dev/null
    if [[ "${PERSIST_ARTIFACTS}" -eq "1" ]]; then
        mv "${SUBDIR}" "${OUTFILE}.artifacts"
    else
        rm -rf "${SUBDIR}"
    fi
  fi
}

function abortonerror {
  if [[ "${ABORT_ON_ERROR}" -ne "0" ]] && [[ "${RES}" -ne "0" ]]; then
    abort
  fi
}

function abort {
  log_error "FATAL ERROR! See logfile for details:"
  log_error "${PWD}/${LOGFILE}"
  leave_workdir
  exit 1
}

# $1 ... key index
# $2 ... trace index
function tracefile {
  echo "trace$1_$2.${TRACEEXT}"
}

# Debug function to test new framework scripts
function dryrun_phase1 {
  enter_workdir
  KEYFILE=drykey.key
  TRACE=drytrace.trace
  rm -rf $KEYFILE
  log_info "Dry-run: Generating key ${KEYFILE}"
  genkey_wrapper "${KEYFILE}"
  log_info "Dry-run: Running without trace recording"
  log_info "Dry-run: Executing inside ${PWD}"
  log_info "Dry-run: Aborting on any error"

  echo "${CLEANENVVAR}" > ${ENVFILE}

  log_info "Dry-run: Executing cb_pre_run"
  RES=0
  cb_pre_run "${KEYFILE}"
  abortonerror

  log_info "Dry-run: Environment env.txt:"
  cat ${ENVFILE}

  log_info "Dry-run: Executing cb_run_command"
  CURCMD=$(cb_run_command ${KEYFILE})
  log_info "Dry-run: cb_run_command returned '${CURCMD}'"
  log_info "Dry-run: Executing '${CURCMD}'"

  execute_clean "${CURCMD}"
  abortonerror

  log_info "Dry-run: Executing cb_post_run"
  RES=0
  cb_post_run "${KEYFILE}"
  abortonerror

  log_info "Dry-run: Running all again with Pin trace recording to ${TRACE}"
  run_pin ${PHASE1} "${TRACE}" "${KEYFILE}"

  leave_workdir
}

#------------------------------------------------------------------------
# Phase 1: Difference Detection
#------------------------------------------------------------------------

# Requires function cb_run_command
# PHASE1_TRACES ... number of traces to record
function measure_phase1 {
  enter_workdir
  log_info "Phase1: Recording traces."

  if [[ -f ${RESPICFILE_PHASE1} ]]; then
    log_info "Phase1: Already analyzed. Skipping."
    return
  fi

  getelapsedtime
  TSR=$CUR_TIME_REAL
  TSC=$CUR_TIME_CPU
  for i in $(seq 1 "$PHASE1_TRACES"); do
    TRACE=$(tracefile "$i" 1)
    KEYFILE=key$i.key
    if ! [[ -f ${TRACE} ]]; then
      execpar run_pin ${PHASE1} "${TRACE}" "${KEYFILE}"
    fi
  done
  wait_subprocesses
  abortonerror
  getelapsedtime
  TDR=$(printf "%.2f" "$(subfloat "${CUR_TIME_REAL}" "${TSR}")")
  TDC=$(printf "%.2f" "$(subfloat "${CUR_TIME_CPU}" "${TSC}")")
  log_info "Phase1: Recording completed in ${TDR} seconds (or ${TDC} CPU seconds)."
  leave_workdir
}

# $1 ... trace1
# $2 ... trace2
# $3 ... pickle output file
# $5 ... xmlfile, optional
function diff_full {
  PICKLE=$3
  XML=$4
  EXEC="${ANALYZE} diff $1 $2 --syms ${EXTSYMFILE} --pickle ${PICKLE} --debug ${DEBUG}"
  if [[ "${XML}" != "" ]]; then
    EXEC+=" --xml ${XML}"
  fi
  execute "${EXEC}"
}

# $1 ... file1
# $2 ... file2
# $RES ... 0 if files are equal
function diff_quick {
  execute_noerror "diff -q $1 $2"
}

# Analyze traces pairwise
function analyze_phase1 {
  enter_workdir
  log_info "Phase1: Starting analysis of traces."

  getelapsedtime
  TSR=$CUR_TIME_REAL
  TSC=$CUR_TIME_CPU
  N=${PHASE1_TRACES}
  ALLDIFF=0
  NODIFF=0
  # ELF symbols
  if ! [[ -f "${SYMFILE}" ]]; then
    log_error "Symbol file missing!"
    abort
  fi
  if ! [[ -f "${EXTSYMFILE}" ]]; then
    log_info "Phase1: Extending ELF symbols."
    execute_noerror "${ANALYZE} addsyms ${SYMFILE} ${EXTSYMFILE} --debug ${DEBUG}"
    if [[ "${RES}" -ne "0" ]]; then
      log_warning "Error adding ELF symbol information. Falling back to symbols exported by Pin. Address-to-symbol mapping might be imprecise!"
      cp "${SYMFILE}" "${EXTSYMFILE}"
    fi
    log_info "Phase1: Extending completed."
  fi

  if [[ -f ${RESXMLFILE_PHASE1} ]]; then
    log_info "Phase1: Already merged. Skipping."
    return
  fi

  # Traces
  log_info "Phase1: Scanning traces."
  for i in $(seq 2 "$N"); do
    for j in $(seq 1 "$i"); do
        if ! [[ "$i" -eq "$j" ]]; then
          TRACE1=$(tracefile "$i" 1)
          TRACE2=$(tracefile "$j" 1)
          PICKLE=phase1_$j-$i.pickle
          ALLDIFF=$((ALLDIFF+1))
          if [[ -f ${TRACE1} ]] && [[ -f ${TRACE2} ]]; then
            diff_quick "${TRACE1}" "${TRACE2}"
            # Do expensive analysis only if quick-diff finds differences
            if [[ "${RES}" -eq "1" ]]; then
              RES=0
              if [[ -f ${PICKLE} ]]; then
                continue
              fi
              execpar diff_full "${TRACE1}" "${TRACE2}" "${PICKLE}"
            else
              NODIFF=$((NODIFF+1))
            fi
          else
            log_warning "analyze_phase1: files missing: ${TRACE1}, ${TRACE2}"
          fi
        fi
    done
  done
  wait_subprocesses
  abortonerror
  log_info "Phase1: Scanning completed."
  log_info "Phase1: Merging results."
  if [[ "$ALLDIFF" -eq "$NODIFF" ]]; then
    log_info "Phase1: No difference found"
    touch ${NODIFFFILE}
  else
    PICKLEFILES="phase1_[0-9]*-[0-9]*.pickle"
    execute "${ANALYZE}" merge ${PICKLEFILES} --syms ${EXTSYMFILE} --pickle ${RESPICFILE_PHASE1} --debug ${DEBUG}
    execute "${ANALYZE}" show ${RESPICFILE_PHASE1} --xml ${RESXMLFILE_PHASE1} --syms ${EXTSYMFILE} -${LEAKOUT} ${LEAKFILE} --debug ${DEBUG}
  fi
  log_info "Phase1: Merging completed."
  getelapsedtime
  TDR=$(printf "%.2f" "$(subfloat "${CUR_TIME_REAL}" "${TSR}")")
  TDC=$(printf "%.2f" "$(subfloat "${CUR_TIME_CPU}" "${TSC}")")
  log_info "Phase1: Analysis completed in ${TDR} seconds (or ${TDC} CPU seconds)."
  if [[ -f ${RESXMLFILE_PHASE1} ]]; then
    log_info "Phase1: Results generated: $(readlink -f $RESXMLFILE_PHASE1)"
  fi
  leave_workdir
}

#------------------------------------------------------------------------
# Phase 2: Leakage Detection
#------------------------------------------------------------------------

# Requires function cb_run_command
# Requires function cb_genkey
# PHASE2_FIXEDKEYS ... number of fixed inputs to consider
# PHASE2_TRACES ... number of generic measurements to take (fixed, random)
# LEAKFILE ... previous leaks stored in binary file format
function measure_phase2 {
  enter_workdir

  log_info "Phase2: Recording traces for generic leakage test."

  if [[ -f ${RESPICFILE_PHASE2} ]]; then
    log_info "Phase2: Already analyzed. Skipping."
    return
  fi

  getelapsedtime
  TSR=$CUR_TIME_REAL
  TSC=$CUR_TIME_CPU
  if ! [[ -f ${LEAKFILE} ]]; then
    log_error "No leakfile ${LEAKFILE} found! Run phase1 analysis first!"
    exit 1
  fi
  if [[ "${PHASE2_FIXEDKEYS}" == "" ]] || [[ "${PHASE2_TRACES}" == "" ]]; then
    log_error "Please specify PHASE2_FIXEDKEYS and PHASE2_TRACES!"
    exit 1
  fi
  log_info "Phase2: Recording traces for random secret input."
  mkdir -p ${PHASE2_FIXDIR}
  mkdir -p ${PHASE2_RNDDIR}
  mkdir -p ${PHASE2_KEYDIR}
  for j in $(seq 1 "$PHASE2_TRACES"); do
    RND_FILE=${PHASE2_RNDDIR}/trace_rnd_$j.${TRACEEXT}
    RND_KEY=${PHASE2_KEYDIR}/key_rnd_$j.key
    if ! [[ -f ${RND_KEY} ]]; then
      genkey_wrapper "${RND_KEY}"
    fi
    if ! [[ -f ${RND_FILE} ]]; then
      execpar run_pin ${PHASE2} "${RND_FILE}" "${RND_KEY}" # random
    fi
  done
  wait_subprocesses
  abortonerror
  log_info "Phase2: Recording completed."
  log_info "Phase2: Recording traces for fixed secret input."
  for i in $(seq 1 "$PHASE2_FIXEDKEYS"); do
    FIX_KEY=key$i.key
    for j in $(seq 1 "$PHASE2_TRACES"); do
      FIX_FILE=${PHASE2_FIXDIR}/trace_fix_${i}_${j}.${TRACEEXT}
      if ! [[ -f ${FIX_FILE} ]]; then
        execpar run_pin ${PHASE2} "${FIX_FILE}" "${FIX_KEY}" # fixed
      fi
    done
  done
  wait_subprocesses
  abortonerror
  log_info "Phase2: Recording completed."
  getelapsedtime
  TDR=$(printf "%.2f" "$(subfloat "${CUR_TIME_REAL}" "${TSR}")")
  TDC=$(printf "%.2f" "$(subfloat "${CUR_TIME_CPU}" "${TSC}")")
  log_info "Phase2: Recording completed in ${TDR} seconds (or ${TDC} CPU seconds)."
  leave_workdir
}

# Analyze fix vs. random
#
# PHASE2_FIXEDKEYS ... number of fixed inputs to consider
# PHASE2_TRACES ... number of generic measurements to analyze (fixed, random)
function analyze_phase2 {
  enter_workdir

  log_info "Phase2: Starting generic leakage analysis."

  if [[ -f ${RESPICFILE_PHASE2} ]]; then
    log_info "Phase2: Already analyzed. Skipping."
    return
  fi

  getelapsedtime
  TSR=$CUR_TIME_REAL
  TSC=$CUR_TIME_CPU
  if [[ "${PHASE2_FIXEDKEYS}" == "" ]] || [[ "${PHASE2_TRACES}" == "" ]]; then
    log_error "Please specify PHASE2_FIXEDKEYS and PHASE2_TRACES!"
    exit 1
  fi
  if ! [[ -f ${RESPICFILE_PHASE1} ]]; then
    log_error "Previous ${RESPICFILE_PHASE1} file not found!"
    exit 1
  fi
  if ! [[ -f ${PHASE2_RNDPIC} ]]; then
    log_info "Phase2: Preparing random-key traces."
    cp ${RESPICFILE_PHASE1} ${PHASE2_RNDPIC}
    execpar execute "${ANALYZE}" loadleaks "${PHASE2_RNDPIC}" --filepattern="${PHASE2_RNDDIR}/trace_rnd_%.${TRACEEXT}" --keypattern="${PHASE2_KEYDIR}/key_rnd_%.key" --start=1 --end="$PHASE2_TRACES" --source 0 --debug ${DEBUG}
  fi
  # load traces into pickle file
  for i in $(seq 1 "$PHASE2_FIXEDKEYS"); do
    FIXPIC=gen_fix_${i}.pickle
    FIX_KEY=key$i.key
    if ! [[ -f ${FIXPIC} ]]; then
      log_info "Phase2: Preparing fixed-key traces."
      cp ${RESPICFILE_PHASE1} "${FIXPIC}"
      execpar execute "${ANALYZE}" loadleaks "${FIXPIC}" --filepattern="${PHASE2_FIXDIR}/trace_fix_${i}_%.${TRACEEXT}" --keypattern="${FIX_KEY}" --start=1 --end="$PHASE2_TRACES" --source 0 --debug ${DEBUG}
    fi
  done
  wait_subprocesses
  abortonerror
  log_info "Phase2: Preparation of traces completed."
  log_info "Phase2: Running statistical tests."
  # analyze above generated pickle files
  for i in $(seq 1 "$PHASE2_FIXEDKEYS"); do
    FIXPIC=gen_fix_${i}.pickle
    RESPIC=result_gen_${i}.pickle
    FIX_KEY=key$i.key
    if ! [[ -f ${RESPIC} ]]; then
      execpar execute "${ANALYZE}" generic "${FIXPIC}" ${PHASE2_RNDPIC} --pickle "${RESPIC}" --syms ${EXTSYMFILE} --debug ${DEBUG}
    fi
  done
  wait_subprocesses
  abortonerror
  log_info "Phase2: Statistical tests completed."
  if ! [[ -e ${RESPICFILE_PHASE2} ]]; then
    log_info "Phase2: Starting merging with random results."
    cp ${PHASE2_RNDPIC} ${RESPICFILE_PHASE2}
    log_info "Phase2: Merging results."
    for i in $(seq 1 "$PHASE2_FIXEDKEYS"); do
        CURPIC=result_gen_${i}.pickle
        execute "${ANALYZE}" merge "${CURPIC}" ${RESPICFILE_PHASE2} --syms ${EXTSYMFILE} --pickle ${RESPICFILE_PHASE2} --xml ${RESXMLFILE_PHASE2} --strip_entry 1 --debug ${DEBUG}
    done
    log_info "Phase2: Merging completed."
  fi
  getelapsedtime
  TDR=$(printf "%.2f" "$(subfloat "${CUR_TIME_REAL}" "${TSR}")")
  TDC=$(printf "%.2f" "$(subfloat "${CUR_TIME_CPU}" "${TSC}")")
  log_info "Phase2: Analysis completed in ${TDR} seconds (or ${TDC} CPU seconds)."
  log_info "Phase2: Results generated: $(readlink -f $RESXMLFILE_PHASE2)"
  leave_workdir
}

#------------------------------------------------------------------------
# Phase 3: Leakage Classification
#------------------------------------------------------------------------

# Requires function cb_run_command
# Requires function cb_genkey
# PHASE3_TRACES ... number of specific measurements to take
# LEAKFILE ... previous leaks stored in binary file format
# PHASE2_TRACES ... optional: number of generic measurements previously taken
function measure_phase3 {
  enter_workdir
  SPLEAKCB=$1
  SPLEAKCB_SUFFIX=$(basename "${SPLEAKCB}")
  SPLEAKCB_SUFFIX=${SPLEAKCB_SUFFIX%%.*}
  RESPIC="${RESPICFILE_PHASE3}_${SPLEAKCB_SUFFIX}.pickle"

  log_info "Phase3: Recording traces for specific leakage test ${SPLEAKCB_SUFFIX}."

  if [[ -f ${RESPIC} ]]; then
    log_info "Phase3: Already analyzed. Skipping."
    return
  fi

  getelapsedtime
  TSR=$CUR_TIME_REAL
  TSC=$CUR_TIME_CPU
  if ! [[ -f ${LEAKFILE} ]]; then
    log_error "No leakfile ${LEAKFILE} found! Run phase 1 first!"
    exit 1
  fi
  if [[ "${PHASE3_TRACES}" == "" ]]; then
    log_error "Please specify PHASE3_TRACES!"
    exit 1
  fi
  mkdir -p ${PHASE3_RNDDIR}
  mkdir -p ${PHASE3_KEYDIR}

  if ! [[ -f ${RESPICFILE_PHASE2} ]]; then
    log_warning "Previous ${RESPICFILE_PHASE2} file not found! Falling back to ${RESPICFILE_PHASE1}"
    log_warning "Setting DO_TRACE_REUSE=0."
    DO_TRACE_REUSE=0
    if ! [[ -f ${RESPICFILE_PHASE1} ]]; then
      log_error "Previous ${RESPICFILE_PHASE1} file not found!"
      exit 1
    fi
  fi

  if [[ "${DO_TRACE_REUSE}" -eq "1" ]]; then
    if [[ "${PHASE2_TRACES}" == "" ]]; then
      log_error "Please specify PHASE2_TRACES!"
      exit 1
    fi
    for j in $(seq 1 "$PHASE2_TRACES"); do
      RFILE_NS=${PHASE2_RNDDIR}/trace_rnd_$j.${TRACEEXT}
      RKEY_NS=${PHASE2_KEYDIR}/key_rnd_$j.key
      RFILE_SP=${PHASE3_RNDDIR}/trace_rnd_$j.${TRACEEXT}
      RKEY_SP=${PHASE3_KEYDIR}/key_rnd_$j.key
      RARTIFACTS_NS="${PHASE2_RNDDIR}/trace_rnd_${j}.${TRACEEXT}.artifacts"
      RARTIFACTS_SP="${PHASE3_RNDDIR}/trace_rnd_${j}.${TRACEEXT}.artifacts"
      if (! [[ -f ${RFILE_NS} ]]) || (! [[ -f ${RKEY_NS} ]]); then
        log_error "Cannot re-use trace/key! File does not exist: ${PWD}/${RFILE_NS}"
        exit 1
      fi
      if ! [[ -h ${RFILE_SP} ]]; then
        ln -r -s "${RFILE_NS}" "${RFILE_SP}"
      fi
      if ! [[ -h ${RKEY_SP} ]]; then
        ln -r -s "${RKEY_NS}" "${RKEY_SP}"
      fi
      if ! [[ -h ${RARTIFACTS_SP} ]]; then
        ln -r -s "${RARTIFACTS_NS}" "${RARTIFACTS_SP}"
      fi
    done
  fi
  for j in $(seq 1 "$PHASE3_TRACES"); do
    RND_FILE=${PHASE3_RNDDIR}/trace_rnd_$j.${TRACEEXT}
    RND_KEY=${PHASE3_KEYDIR}/key_rnd_$j.key
    if ! [[ -e ${RND_KEY} ]]; then
      genkey_wrapper "${RND_KEY}"
    fi
    if ! [[ -e ${RND_FILE} ]]; then
      execpar run_pin ${PHASE3} "${RND_FILE}" "${RND_KEY}" # random
    fi
  done
  wait_subprocesses
  abortonerror
  getelapsedtime
  TDR=$(printf "%.2f" "$(subfloat "${CUR_TIME_REAL}" "${TSR}")")
  TDC=$(printf "%.2f" "$(subfloat "${CUR_TIME_CPU}" "${TSC}")")
  log_info "Phase3: Recording completed in ${TDR} seconds (or ${TDC} CPU seconds)."
  leave_workdir
}

# Analyze specific leakage
#
# PHASE3_TRACES ... number of specific measurements to analyze
# PHASE3_KEYDIR ... directory where the generated keys for phase3 are stored
# $1 ... .py file that defines the specific leakage as a callback function
function analyze_phase3 {
  enter_workdir
  SPLEAKCB=$1
  SPLEAKCB_SUFFIX=$(basename "${SPLEAKCB}")
  SPLEAKCB_SUFFIX=${SPLEAKCB_SUFFIX%%.*}
  # Result files for current leakage model ${SPLEAKCB}
  RESXMLFILE_PHASE3_LM="${RESXMLFILE_PHASE3}_${SPLEAKCB_SUFFIX}.xml"
  RESPICFILE_PHASE3_LM="${RESPICFILE_PHASE3}_${SPLEAKCB_SUFFIX}.pickle"
  PREVPIC=${RESPICFILE_PHASE2}

  log_info "Phase3: Starting specific leakage analysis for ${SPLEAKCB_SUFFIX}."

  if [[ -f ${RESPICFILE_PHASE3_LM} ]]; then
    log_info "Phase3: Already analyzed. Skipping."
    return
  fi

  getelapsedtime
  TSR=$CUR_TIME_REAL
  TSC=$CUR_TIME_CPU
  if [[ "${PHASE3_TRACES}" == "" ]]; then
    log_error "Please specify PHASE3_TRACES!"
    exit 1
  fi
  if [[ "${PHASE3_KEYDIR}" == "" ]]; then
    log_error "Please specify PHASE3_KEYDIR!"
    exit 1
  fi
  if ! [[ -f ${SPLEAKCB} ]]; then
    log_error "Specific leakage callback function not specified!"
    exit 1
  fi

  if ! [[ -f ${RESPICFILE_PHASE2} ]]; then
    log_warning "Previous ${RESPICFILE_PHASE2} file not found! Falling back to ${RESPICFILE_PHASE1}"
    log_warning "Setting DO_TRACE_REUSE=0."
    PREVPIC=${RESPICFILE_PHASE1}
    DO_TRACE_REUSE=0
    if ! [[ -f ${RESPICFILE_PHASE1} ]]; then
      log_error "Previous ${RESPICFILE_PHASE1} file not found!"
      exit 1
    fi
  fi

  for j in $(seq 1 "$PHASE3_TRACES"); do
    type cb_pre_leakage_model &>/dev/null
    if [[ "$?" -eq "0" && "${PERSIST_ARTIFACTS}" -eq "1" ]]; then
      ARTIFACT_DIR=${PHASE3_RNDDIR}/trace_rnd_$j.${TRACEEXT}.artifacts
      ARTIFACT_KEY=$(readlink -e "${PHASE3_KEYDIR}/key_rnd_$j.key")
      if ! [[ -d ${ARTIFACT_DIR} ]]; then
        log_error "Phase3: ARTIFACT_DIR does not exist: ${ARTIFACT_DIR} (PWD= ${PWD})"
        exit
      fi
      pushd "${ARTIFACT_DIR}" &>/dev/null
      PHASE3_INPUT=$(cb_pre_leakage_model "${ARTIFACT_KEY}")
      if [[ "${PHASE3_INPUT}" == "" ]]; then
        RES=1
        abortonerror
      fi
      popd &>/dev/null
      ln -f -r -s "${ARTIFACT_DIR}/${PHASE3_INPUT}" "${PHASE3_KEYDIR}/leakage_model_${j}.input"
    else
      ln -f -r -s "${PHASE3_KEYDIR}/key_rnd_${j}.key" "${PHASE3_KEYDIR}/leakage_model_${j}.input"
    fi
  done

  if ! [[ -f ${PHASE3_RNDPIC} ]]; then
    log_info "Phase3: Preparing traces."
    cp ${PREVPIC} ${PHASE3_RNDPIC}
    execute "${ANALYZE}" loadleaks ${PHASE3_RNDPIC} --filepattern="${PHASE3_RNDDIR}/trace_rnd_%.${TRACEEXT}" --keypattern="${PHASE3_KEYDIR}/leakage_model_%.input" --start=1 --end="$PHASE3_TRACES" --source 1 --debug ${DEBUG}
    log_info "Phase3: Preparation of traces completed."
  fi
  if ! [[ -f ${RESPICFILE_PHASE3_LM} ]]; then
    log_info "Phase3: Running statistical tests."
    LEAKSONLY="True" # Phase 3 analyzes only phase2 leaks
    if [[ "${PHASE3_SKIP_PHASE2}" -eq "1" ]]; then
        # Phase 3 analyzes all phase1 differences
        #(and not just those (phase2 differences) that are marked as leaks
        LEAKSONLY="False"
    fi
    MP="False"
    if [[ "${DO_PARALLEL}" -eq "1" ]]; then
      MP="True"
    fi
    execute "${ANALYZE}" specific ${PHASE3_RNDPIC} "${SPLEAKCB}" ${PHASE3_KEYDIR} --pickle "${RESPICFILE_PHASE3_LM}" --syms ${EXTSYMFILE} --xml "${RESXMLFILE_PHASE3_LM}" --debug ${DEBUG} --leaksonly ${LEAKSONLY} --multiprocessing ${MP}
    log_info "Phase3: Statistical tests completed."
  fi
  getelapsedtime
  TDR=$(printf "%.2f" "$(subfloat "${CUR_TIME_REAL}" "${TSR}")")
  TDC=$(printf "%.2f" "$(subfloat "${CUR_TIME_CPU}" "${TSC}")")
  log_info "Phase3: Analysis completed in ${TDR} seconds (or ${TDC} CPU seconds)."
  log_info "Phase3: Results generated: $(readlink -f $RESXMLFILE_PHASE3_LM)"
  leave_workdir
}

#------------------------------------------------------------------------
# Report Generation
#------------------------------------------------------------------------

function export_framework_files {
  enter_workdir
  log_info "Exporting framework files"
  if ! [[ -f ${EXPORTFILE} ]]; then
    # It is enough to use phase1 results for export, since later phases
    # do not find more potential leakage
    execute "${ANALYZE}" export "${RESPICFILE_PHASE1}" "${EXPORTFILE}" --syms ${EXTSYMFILE} --debug ${DEBUG}
  fi
  log_info "Exporting completed: $(readlink -f $EXPORTFILE)"
  leave_workdir
}

# Generate final XMLs
function generate_final_result_XMLs {
  enter_workdir
  SPPIC="${RESPICFILE_PHASE3}_*.pickle"
  NSPIC="${RESPICFILE_PHASE2}"
  DIFFPIC="${RESPICFILE_PHASE1}"
  ALLPIC="${RESPICFILE_FINAL}"
  ALLXML="${RESXMLFILE_FINAL}"

  log_info "Generating final result and report files."
  if [[ -f ${NSPIC} ]]; then
    cp ${NSPIC} ${ALLPIC}
  elif [[ -f ${DIFFPIC} ]] ; then
    cp ${DIFFPIC} ${ALLPIC}
  else
    log_error "${DIFFPIC} and ${NSPIC} files not found!"
    exit 1
  fi
  for f in ${SPPIC}; do
    if [[ -f ${f} ]]; then
      execute "${ANALYZE}" merge ${ALLPIC} "${f}" --syms ${EXTSYMFILE} --pickle ${ALLPIC} --strip True --debug ${DEBUG}
    fi
  done
  execute "${ANALYZE}" show ${ALLPIC} --syms ${EXTSYMFILE} --xml ${ALLXML} --debug ${DEBUG}
  log_info "Generating completed."
  log_info "Results generated: $(readlink -f $ALLXML)"
  leave_workdir
}

function do_run {
  local ALGOCMDLINE=$1
  local CONFIG=$2

  enter_workdir
  log_info "Testing '$ALGOCMDLINE' under configuration '$CONFIG'"
  log_verbose "#TIME $(date +"%Y_%d_%m-%H:%M:%S")"
  setstarttime
  leave_workdir

  if [[ "${DO_DRY}" -eq "1" ]]; then
    dryrun_phase1
  else
    if [[ "${DO_GENKEYS}" -eq "1" ]]; then
      gen_keys
    fi
    if [[ "${DO_PHASE1_MEASURE}" -eq "1" ]]; then
      measure_phase1
    fi
    if [[ "${DO_PHASE1_ANALYZE}" -eq "1" ]]; then
      analyze_phase1
    fi

    enter_workdir
    if [[ -f ${NODIFFFILE} ]]; then
      log_info "Skipping generic/specific leakage tests, because no trace differences were found."
      leave_workdir
    else
      leave_workdir
      if [[ "${DO_PHASE2_MEASURE}" -eq "1" ]]; then
        measure_phase2
      fi
      if [[ "${DO_PHASE2_ANALYZE}" -eq "1" ]]; then
        analyze_phase2
      fi
      if [[ "${DO_PHASE3_MEASURE}" -eq "1" ]]; then
        measure_phase3 "${SPECIFIC_LEAKAGE_CALLBACK}"
      fi
      if [[ "${DO_PHASE3_ANALYZE}" -eq "1" ]]; then
        analyze_phase3 "${SPECIFIC_LEAKAGE_CALLBACK}"
      fi
      if [[ "${DO_FINAL}" -eq "1" ]]; then
        generate_final_result_XMLs
      fi
      if [[ "${DO_EXPORT}" -eq "1" ]]; then
        export_framework_files
      fi
      if [[ "${DO_GUI}" -eq "1" ]]; then
        start_gui
      fi
    fi
    if [[ "${DO_CLEANUP}" -eq "1" ]]; then
      cleanup
    fi
  fi

  enter_workdir
  log_verbose "#TIME $(date +"%Y_%d_%m-%H:%M:%S")"
  getelapsedtime
  getpeakmemory
  if [[ ${PEAK_MEMORY} == 0 ]]; then
    log_info "$(printf "Testing '$ALGOCMDLINE' completed in %.2f seconds (or %.2f CPU seconds)" "$DIFF_TIME_REAL" "$DIFF_TIME_CPU")"
  else
    log_info "$(printf "Testing '$ALGOCMDLINE' completed in %.2f seconds (or %.2f CPU seconds) with a peak RAM usage of ${PEAK_MEMORY} MiB" "$DIFF_TIME_REAL" "$DIFF_TIME_CPU")"
  fi
  leave_workdir
}

#------------------------------------------------------------------------
# Framework CLI
#------------------------------------------------------------------------

# For legacy reasons only. Set WORKDIR directly inside cb_prepare_algo
#
# $* ... workdir path without $FRAMEWORK prefix
function DATA_run {
  print_warning "Warning! DATA_run is deprecated. Set WORKDIR directly inside cb_prepare_algo"
  local WORKDIR_SUFFIX=
  for P in "$@"; do
    P=${P// /} # strip spaces
    if [[ "${P}" != "" ]]; then
      WORKDIR_SUFFIX=${WORKDIR_SUFFIX}/${P}
    fi
  done
  WORKDIR="${FRAMEWORK}/${WORKDIR_SUFFIX}"
}

function PHASE_NUM_TRACES {
  # Check if argument is a number
  if [ "$1" -eq "$1" ] 2>/dev/null
  then
    SHIFT=$((SHIFT+1))
    echo "$1"
  fi
}

# $* ... command line arguments
function DATA_parse {

  if [[ $# -eq 0 ]]; then
    help
    exit 1
  fi

  # Count number of arguments
  SHIFT=0
  SKIP_ARGS=0
  for key in "$@"; do
    # If a flag needs parameters:
    # 1. read param1, param2
    # 2. set SKIP_ARGS to the amount of parameters
    param1=${@:$((SHIFT+2)):1}
    param2=${@:$((SHIFT+3)):1}
    if [[ "${SKIP_ARGS}" -gt "0" ]]; then
      SHIFT=$((SHIFT+1))
      SKIP_ARGS=$((SKIP_ARGS-1))
      continue
    fi
    case $key in
        -h|--help)
        help
        exit
        ;;
        -l|--list)
        init_for_run
        list_targets
        exit
        ;;
        --gui)
        DO_GUI=1
        ;;
        --phase1)
        DO_GENKEYS=1
        DO_PHASE1_MEASURE=1
        DO_PHASE1_ANALYZE=1
        TRACES=$(PHASE_NUM_TRACES "$param1")
        if [[ ! -z "${TRACES}" ]]; then
          SKIP_ARGS=1
          PHASE1_TRACES=${TRACES}
          log_info "Overwriting PHASE1_TRACES=${PHASE1_TRACES}"
        fi
        ;;
        --phase2)
        DO_PHASE2_MEASURE=1
        DO_PHASE2_ANALYZE=1
        TRACES=$(PHASE_NUM_TRACES "$param1")
        if [[ ! -z "${TRACES}" ]]; then
          SKIP_ARGS=1
          PHASE2_TRACES=${TRACES}
          log_info "Overwriting PHASE2_TRACES=${PHASE2_TRACES}"
        fi
        ;;
        --phase3)
        DO_PHASE3_MEASURE=1
        DO_PHASE3_ANALYZE=1
        TRACES=$(PHASE_NUM_TRACES "$param1")
        if [[ ! -z "${TRACES}" ]]; then
          SKIP_ARGS=1
          PHASE3_TRACES=${TRACES}
          log_info "Overwriting PHASE3_TRACES=${PHASE3_TRACES}"
        fi
        ;;
        -g|--genkeys)
        DO_GENKEYS=1
        TRACES=$(PHASE_NUM_TRACES "$param1")
        if [[ ! -z "${TRACES}" ]]; then
          SKIP_ARGS=1
          PHASE1_TRACES=${TRACES}
          log_info "Overwriting PHASE1_TRACES=${PHASE1_TRACES}"
        fi
        ;;
        -d|--diff)
        DO_PHASE1_MEASURE=1
        ;;
        -ad|--alyzed)
        DO_PHASE1_ANALYZE=1
        ;;
        -ns|--generic)
        DO_PHASE2_MEASURE=1
        TRACES=$(PHASE_NUM_TRACES "$param1")
        if [[ ! -z "${TRACES}" ]]; then
          SKIP_ARGS=1
          PHASE2_TRACES=${TRACES}
          log_info "Overwriting PHASE2_TRACES=${PHASE2_TRACES}"
        fi
        ;;
        -an|--alyzens)
        DO_PHASE2_ANALYZE=1
        ;;
        -sp|--specific)
        DO_PHASE3_MEASURE=1
        TRACES=$(PHASE_NUM_TRACES "$param1")
        if [[ ! -z "${TRACES}" ]]; then
          SKIP_ARGS=1
          PHASE3_TRACES=${TRACES}
          log_info "Overwriting PHASE3_TRACES=${PHASE3_TRACES}"
        fi
        ;;
        -as|--alyzesp)
        DO_PHASE3_ANALYZE=1
        ;;
        -u|--reusetraces)
        DO_TRACE_REUSE=1
        ;;
        -p|--parallel)
        DO_PARALLEL=1
        ;;
        -c|--cleanup)
        DO_CLEANUP=1
        ;;
        -i|--final)
        DO_FINAL=1
        ;;
        -e|--export)
        DO_EXPORT=1
        ;;
        -f|--full)
        DO_GENKEYS=1
        DO_PHASE1_MEASURE=1
        DO_PHASE1_ANALYZE=1
        DO_PHASE2_MEASURE=1
        DO_PHASE2_ANALYZE=1
        DO_PHASE3_MEASURE=1
        DO_PHASE3_ANALYZE=1
        DO_FINAL=1
        ;;
        --dry)
        DO_DRY=1
        ;;
        -*)
        print_error "Invalid option $key!"
        help
        exit 1
        ;;
        *)
        break
        ;;
    esac
    SHIFT=$((SHIFT+1))
  done

  CONFIG=${@:1:${SHIFT}}
  shift ${SHIFT}

  if [[ $# -ge 1 ]]; then
    init_for_run
  fi
  while [[ $# -ge 1 ]]
  do
    SHIFT=0
    RES=0
    WORKDIR=
    # Call algorithm-specific function for parsing parameters and setting up stuff.
    # It shall set $WORKDIR to the desired algorithm directory

    type cb_prepare_algo &>/dev/null
    if [[ "$?" -eq "0" ]]; then
      cb_prepare_algo "$@"
    fi

    # Legacy only. Use cb_prepare_algo instead
    type cb_run_single &>/dev/null
    if [[ "$?" -eq "0" ]]; then
      print_warning "Warning! cb_run_single is deprecated. Use cb_prepare_algo instead"
      cb_run_single "$@"
    fi

    if [[ -z "${WORKDIR}" ]]; then
      print_error "Configure WORKDIR in cb_prepare_algo!"
      print_error "This is where all intermediate and final analysis files are placed"
      print_error 'E.g. `WORKDIR=${FRAMEWORK}/${ALGO}/${PARAM}`'
      exit 1
    fi

    # Extract args of current algorithm
    SHIFT=$((SHIFT+1))
    ALGOCMDLINE=${@:1:${SHIFT}}
    shift ${SHIFT}
    if [[ "$?" -ne "0" ]]; then
      print_error "Invalid SHIFT value specified, or invalid algorithm parameters!"
      print_error "Ensure that SHIFT equals the number of algorithm parameters"
      print_error "ALGOCMDLINE=$ALGOCMDLINE"
      exit 1
    fi

    # Match args against TARGETFILE
    if [[ -f "${TARGETFILE}" ]]; then
      FOUND=0
      while read -r ALGOSUPPORT; do
        echo "${ALGOCMDLINE}" | grep -q -x -E -e "${ALGOSUPPORT}" -
        if [[ "$?" -eq "0" ]]; then
          FOUND=1
          break
        fi
      done < "${TARGETFILE}"
      if [[ "${FOUND}" -ne "1" ]]; then
        print_error "Invalid algorithm ${ALGOCMDLINE}!"
        print_error "Choose one matching these lines (regex matching is allowed):"
        cat "${TARGETFILE}"
        exit 1
      fi
    fi

    # Run actual analysis
    do_run "${ALGOCMDLINE}" "${CONFIG}"
    abortonerror
    echo "============================================================"

  done
}

function help {
  echo "./<script>.sh [options] target1 vargs1 ... targetN vargsN"
  echo ""
  echo "                   Analysis results are stored in a directory specified via the RESULTDIR environment variable"
  echo ""
  echo "target vargs       Run given target with a variable number of arguments vargs (e.g. key size, curve parameter)"
  echo "                   Chaining of several targets is possible. cb_prepare_algo needs to extract one target at a time"
  echo "                   If vargs are used, cb_prepare_algo needs to increase SHIFT accordingly by the number of additional arguments"
  echo "options:"
  echo "-h|--help          Print this help"
  echo "-l|--list          List all available targets"
  echo "-f|--full          Run phases 1-3 and generate final result XML files"
  echo "               [n] Optional argument to overwrite PHASE[123]_TRACES"
  echo "--phase1       [n] Run the whole phase1 with PHASE1_TRACES traces (-g -d -ad)"
  echo "--phase2       [n] Run the whole phase2 with PHASE2_TRACES traces (-ns -an)"
  echo "--phase3       [n] Run the whole phase3 with PHASE3_TRACES traces (-sp -as). Optionally provide -u"
  echo ""
  echo "The individual phase steps can be invoked separately:"
  echo " -g|--genkeys  [n] Phase1: Generate PHASE1_TRACES new keys"
  echo " -d|--diff         Phase1: Generate traces with varying key for detecting differences"
  echo "-ad|--alyzed       Phase1: Analyze traces for differences and create xml reports"
  echo "-ns|--generic  [n] Phase2: Generate PHASE2_TRACES traces with fixed vs. random keys to perform generic (non-specific) leakage tests"
  echo "-an|--alyzens      Phase2: Analyze traces for generic leakage and create xml reports"
  echo "-sp|--specific [n] Phase3: Generate PHASE3_TRACES traces with random keys to perform specific leakage tests"
  echo " -u|--reusetraces  Phase3: Re-use existing traces from generic tests for specific tests to speed-up the process"
  echo "-as|--alyzesp      Phase3: Analyze traces for specific leakage and create xml reports"
  echo ""
  echo "-p|--parallel      Run tasks in parallel on all CPU cores available, as reported by 'nproc'"
  echo "-i|--final         Generate final result XML files"
  echo "-e|--export        Export framework files (ELF/asm/src) in a framework.zip archive for the DATA GUI"
  echo "-c|--cleanup       Delete trace files and intermediate pickle files"
  echo "--gui              Run the DATA GUI with the latest result"
  echo "--dry              Dry-run phase1 (-g and --diff) on a single trace to test your script with extended debug output"
}
