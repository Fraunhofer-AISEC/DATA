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
# @version 0.2
#########################################################################

#------------------------------------------------------------------------
# Settings
#------------------------------------------------------------------------

# Custom options
source "../../config.mk"

# Ensure multiple invocations of pin to have the same memory layout
export PINFLAGS="-ifeellucky -restrict_memory 0x50000000:0x70000000 -pin_memory_range 0x100000000:0xF00000000"

# PinTool arguments
export STDARGS="-debug 0 -bbl -func -mem -cs"
export OUTFMT="-raw"
export LEAKIN="-leakin"
export LEAKOUT="-leakout"

# Directories
export ANALYSISDIR=${DATA_ROOT}/analysis/
export PRELOAD=${COMMON}/preload/
export LASTRESULTS="lastresults"

# Files and scripts
export PIN=${PIN_ROOT}/pin
export PINTOOL=${DATA_ROOT}/pintool/addrtrace.so
export CLEANENV=${COMMON}/cleanenv
export CLEANENVFILE=${COMMON}/cleanenv.txt
export ANALYZE="python ${ANALYSISDIR}analyze.py"
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
DO_NEWFOLDER=0
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

# Extension for trace files
TRACEEXT=trace

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
DEBUG=0

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

#------------------------------------------------------------------------
# Helper Functions
#------------------------------------------------------------------------

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
      printf "${2}[%s/%s]${NC}" "${3}" "${4}"
    else
      printf "[${1}][%s/%s]" "${3}" "${4}"
    fi
  fi
}

function print_error {
  print_color "${LL_ERR}" "${RED}" "${FRAMEWORK}" "${ALGO}"
  echo "$*"
}

function log_error {
  echo "$*" >> ${LOGFILE}
  print_error "$*"
}

function log_warning {
  echo "$*" >> ${LOGFILE}
  print_color "${LL_WARN}" "${YELLOW}" "${FRAMEWORK}" "${ALGO}"
  echo "$*"
}

function print_info {
  print_color "${LL_INFO}" "${GREEN}" "${FRAMEWORK}" "${ALGO}"
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
  WORKDIR=${LASTRESULTS}/${FRAMEWORK}/${ALGO}/${SUBALGO}
  mkdir -p "${WORKDIR}"
  pushd "${WORKDIR}" &> /dev/null
}

function enter_frameworkdir {
  FRAMEWORKDIR=${LASTRESULTS}/${FRAMEWORK}
  mkdir -p "${FRAMEWORKDIR}"
  pushd "${FRAMEWORKDIR}" &> /dev/null
}

function leave_workdir {
  popd &> /dev/null
}

function leave_frameworkdir {
  leave_workdir
}

function new_folder {
  if [[ "${RESULTDIR}" == "" ]]; then
    log_error "Unable to create result folder. Result path not specified!"
    exit 1
  fi
  NEWDIR="${RESULTDIR}/$(date +"%Y_%m_%d-%H:%M:%S")/"
  print_info "Creating new result folder: ${NEWDIR}"
  mkdir -p "${NEWDIR}"
  rm -f ${LASTRESULTS}
  ln -s "${NEWDIR}" ${LASTRESULTS}
}
function cleanup {
  enter_workdir
  log_info "Cleaning up working directory."
  rm -f ./*.${TRACEEXT}
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
  while read -r LLINE || [[ -n "$LLINE" ]]; do
    if echo "${LLINE}" | grep -q "memory="; then
      CURMEM=$(echo "${LLINE}" | cut -f2 -d=)
      if (( CURMEM > PEAK_MEMORY )); then
        PEAK_MEMORY=${CURMEM}
      fi
    fi
  done < "${LOGFILE}"
  PEAK_MEMORY=$(divfloat "${PEAK_MEMORY}" "1024")
  PEAK_MEMORY=$(printf "%.2f" "${PEAK_MEMORY}")
  leave_workdir
}

# parallel
function execpar {
  while [ "$(jobs | wc -l)" -ge "${NUMPROC}" ]; do
    sleep 1
  done
}

#------------------------------------------------------------------------
# Framework Initialization and Preparation
#------------------------------------------------------------------------

# Is called by each framework script
function init {
  BASEDIR=$PWD
  PYENV=${ANALYSISDIR}.pyenv/bin/activate
  if [[ ! -f "${PYENV}" ]]; then
     print_color "${LL_ERR}" "${RED}" "${FRAMEWORK}" 
     echo "Virtual python environment does not exist under ${PYENV}!"
     exit -1
  else
    source "${ANALYSISDIR}"/.pyenv/bin/activate
  fi
}

# Is called before actual work is done
# FRAMEWORK is already specified but ALGO is not
function init_for_run {
  if ! [[ -L ${LASTRESULTS} ]] || ! [[ -a ${LASTRESULTS} ]]; then
    new_folder
  fi
  pushd "${PRELOAD}" &> /dev/null
  source preload.sh
  popd &> /dev/null
  cb_prepare_framework
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

# $NTRACE_DIFF ... number keys to generate for phase 1
function gen_keys {
  enter_workdir
  NK=$NTRACE_DIFF
  if [[ "$NREPS_GEN" -gt "$NK" ]]; then
    NK=$NREPS_GEN
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
  if [[ -f ${TARGETFILE} ]]; then
    echo "List of supported target algorithms:"
    echo "====================================="
    while read LINE; do
      if [[ "${LINE}" == "" ]] || [[ ${LINE} == "#*" ]]; then
        # Skip comments and empty lines
        continue
      fi
      echo "${LINE}"
    done < "${TARGETFILE}"
  else
    exit 1
  fi
  exit 0
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
  /usr/bin/time -f "system=%S\nuser=%U\ntotal=%e\nmemory=%M" -a -o "${LOGFILE}" "${CLEANENV}" ${ENVFILE} $* &>> ${LOGFILE}
  RES=$?
  log_verbose "[$BASHPID] run_status=$RES"
  abortonerror
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
  if [[ ! -f "${CLEANENVFILE}" ]]; then
    log_error "Environment file ${CLEANENVFILE} missing"
  fi
  cp "${CLEANENVFILE}" ${ENVFILE}
  # Custom pre_run has to copy other necessary files from ${WORKDIR} to ${PWD} (which is ${SUBDIR})
  RES=0
  if [[ "${DO_DRY}" -ne "0" ]]; then
    log_info "Dry-run: Executing inside ${PWD}"
  fi
  cb_pre_run "${TMPKEY}"
  abortonerror
  CURCMD=$(cb_run_command ${TMPKEY})
  if [[ "$PHASE" -eq "1" ]]; then
    FASTRECORDING=0
  else
    FASTRECORDING=1
  fi
  execute_clean "${PIN} ${PINFLAGS} -t ${PINTOOL} ${PINTOOL_ARGS} -leaks ${FASTRECORDING} ${STDARGS} ${OUTFMT} ${TMPTRACE} ${LEAKOUT} ${TMPTRACE} ${LEAKIN} ${INFILE} -syms ${SYMFILE} -- ${CURCMD}"
  RES=0
  cb_post_run "${TMPKEY}"
  abortonerror
  popd &> /dev/null
  # copy results back to main result folder
  cat "${SUBDIR}"/"${LOGFILE}" >> ${LOGFILE} # merge logfile from subdir
  if [[ "${DO_DRY}" -eq "0" ]]; then
    rm -f "${SUBDIR}"/"${LOGFILE}" "${SUBDIR}"/"${TMPKEY}" "${SUBDIR}"/"${INFILE}"
    if [[ -f ${SUBDIR}/${TMPTRACE} ]]; then
      mv "${SUBDIR}"/"${TMPTRACE}" "${OUTFILE}"
    fi
    mv "${SUBDIR}"/* .
    rm -rf "${SUBDIR}"
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
  set -e

  log_info "Dry-run: Executing cb_pre_run"
  set -x
  cb_pre_run "${KEYFILE}"
  set +x

  log_info "Dry-run: Executing cb_run_command"
  CURCMD=$(cb_run_command ${KEYFILE})
  log_info "Dry-run: cb_run_command returned '${CURCMD}'"
  log_info "Dry-run: Executing '${CURCMD}'"

  if [[ ! -f "${CLEANENVFILE}" ]]; then
    log_error "Environment file ${CLEANENVFILE} missing"
  fi
  cp "${CLEANENVFILE}" ${ENVFILE}

  execute_clean "${CURCMD}"

  log_info "Dry-run: Executing cb_post_run"
  set -x
  cb_post_run "${KEYFILE}"
  set +x

  set +e
  log_info "Dry-run: Running all again with Pin trace recording to ${TRACE}"
  run_pin ${PHASE1} "${TRACE}" "${KEYFILE}" 

  leave_workdir
}

#------------------------------------------------------------------------
# Phase 1: Difference Detection
#------------------------------------------------------------------------

# Requires function cb_run_command
# NTRACE_DIFF ... number of traces to record
function measure_phase1 {
  enter_workdir
  log_info "Phase1: Recording traces."
  getelapsedtime
  TSR=$CUR_TIME_REAL
  TSC=$CUR_TIME_CPU
  for i in $(seq 1 "$NTRACE_DIFF"); do
    TRACE=$(tracefile "$i" 1)
    KEYFILE=key$i.key
    if ! [[ -f ${TRACE} ]]; then
      if [[ "${DO_PARALLEL}" -eq "1" ]]; then
        execpar; run_pin ${PHASE1} "${TRACE}" "${KEYFILE}" &
      else
        run_pin ${PHASE1} "${TRACE}" "${KEYFILE}" 
      fi
    fi
  done
  wait
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
  N=${NTRACE_DIFF}
  ALLDIFF=0
  NODIFF=0
  # ELF symbols
  if ! [[ -f ${EXTSYMFILE} ]]; then
    log_info "Phase1: Extending ELF symbols."
    execute "${ANALYZE} addsyms ${SYMFILE} ${EXTSYMFILE} --debug ${DEBUG}"
    log_info "Phase1: Extending completed."
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
              if [[ -f ${PICKLE} ]]; then
                continue
              fi
              if [[ "${DO_PARALLEL}" -eq "1" ]]; then
                execpar; diff_full "${TRACE1}" "${TRACE2}" "${PICKLE}" &
              else
                diff_full "${TRACE1}" "${TRACE2}" "${PICKLE}"
              fi
            else
              NODIFF=$((NODIFF+1))
            fi
          else
            log_warning "analyze_phase1: files missing: ${TRACE1}, ${TRACE2}"
          fi
        fi
    done
  done
  wait
  log_info "Phase1: Scanning completed."
  log_info "Phase1: Merging results."
  if [[ "$ALLDIFF" -eq "$NODIFF" ]]; then
    log_info "Phase1: No difference found"
    touch ${NODIFFFILE}
  else
    collect_parallel_results phase1_ "${N}"
    if [[ -f phase1_merged.pickle ]]; then
        cp phase1_merged.pickle ${RESPICFILE_PHASE1}
    fi
    execute "${ANALYZE}" show ${RESPICFILE_PHASE1} --xml ${RESXMLFILE_PHASE1} --syms ${EXTSYMFILE} -${LEAKOUT} ${LEAKFILE} --debug ${DEBUG}
  fi
  log_info "Phase1: Merging completed."
  getelapsedtime
  TDR=$(printf "%.2f" "$(subfloat "${CUR_TIME_REAL}" "${TSR}")")
  TDC=$(printf "%.2f" "$(subfloat "${CUR_TIME_CPU}" "${TSC}")")
  log_info "Phase1: Analysis completed in ${TDR} seconds (or ${TDC} CPU seconds)."
  leave_workdir
}

# Analyze traces pairwise
# $1 ... prefix
# $2 ... number of traces
function collect_parallel_results {
  TYPE=$1
  N=$2
  RESPICKLE=${TYPE}merged.pickle
  rm -f "${RESPICKLE}"
  for i in $(seq 2 "$N"); do
    for j in $(seq 1 "$i"); do
      if ! [[ "$i" -eq "$j" ]]; then
        PICKLE=${TYPE}$j-$i.pickle
        if ! [[ -f ${PICKLE} ]]; then
          log_warning "collect_parallel_results: file ${PICKLE} missing"
          continue
        fi
        if ! [[ -f ${RESPICKLE} ]]; then
          cp "${PICKLE}" "${RESPICKLE}"
        else
          merge "${PICKLE}" "${RESPICKLE}" "${RESPICKLE}"
        fi
      fi
    done
    if [[ -f ${RESPICKLE} ]]; then
      cp "${RESPICKLE}" "${TYPE}collect_1-$i.pickle"
    fi
  done
}

# $1 ... pickle file A
# $2 ... pickle file B
# $3 ... merged pickle file
# $4 ... xmlfile
function merge {
  PICKLE=$3
  XML=$4
  EXEC="${ANALYZE} merge $1 $2 --syms ${EXTSYMFILE} --pickle ${PICKLE} --debug ${DEBUG}"
  if [[ "${XML}" != "" ]]; then
    EXEC+=" --xml ${XML}"
  fi
  execute "${EXEC}"
}

#------------------------------------------------------------------------
# Phase 2: Leakage Detection
#------------------------------------------------------------------------

# Requires function cb_run_command
# Requires function cb_genkey
# NREPS_GEN ... number of fixed inputs to consider
# NTRACE_GEN ... number of generic measurements to take (fixed, random)
# LEAKFILE ... previous leaks stored in binary file format
function measure_phase2 {
  enter_workdir
  FIXDIR="gen_trc_fix"
  RNDDIR="gen_trc_rnd"
  KEYDIR="gen_key_rnd"

  log_info "Phase2: Recording traces for generic leakage test."
  getelapsedtime
  TSR=$CUR_TIME_REAL
  TSC=$CUR_TIME_CPU
  if ! [[ -f ${LEAKFILE} ]]; then
    log_error "No leakfile ${LEAKFILE} found! Run phase1 analysis first!"
    exit 1
  fi
  if [[ "${NREPS_GEN}" == "" ]] || [[ "${NTRACE_GEN}" == "" ]]; then
    log_error "Please specify NREPS_GEN and NTRACE_GEN!"
    exit 1
  fi
  log_info "Phase2: Recording traces for random secret input."
  mkdir -p ${FIXDIR}
  mkdir -p ${RNDDIR}
  mkdir -p ${KEYDIR}
  for j in $(seq 1 "$NTRACE_GEN"); do
    RND_FILE=${RNDDIR}/trace_rnd_$j.${TRACEEXT}
    RND_KEY=${KEYDIR}/key_rnd_$j.key
    if ! [[ -f ${RND_KEY} ]]; then
      genkey_wrapper "${RND_KEY}"
    fi
    if ! [[ -f ${RND_FILE} ]]; then
      if [[ "${DO_PARALLEL}" -eq "1" ]]; then
        execpar; run_pin ${PHASE2} "${RND_FILE}" "${RND_KEY}" & # random
      else
        run_pin ${PHASE2} "${RND_FILE}" "${RND_KEY}" # random
      fi
    fi
  done
  wait
  log_info "Phase2: Recording completed."
  log_info "Phase2: Recording traces for fixed secret input."
  for i in $(seq 1 "$NREPS_GEN"); do
    FIX_KEY=key$i.key
    for j in $(seq 1 "$NTRACE_GEN"); do
      FIX_FILE=${FIXDIR}/trace_fix_${i}_${j}.${TRACEEXT}
      if ! [[ -f ${FIX_FILE} ]]; then
        if [[ "${DO_PARALLEL}" -eq "1" ]]; then
          execpar; run_pin ${PHASE2} "${FIX_FILE}" "${FIX_KEY}" & # fixed
        else
          run_pin ${PHASE2} "${FIX_FILE}" "${FIX_KEY}" # fixed
        fi
      fi
    done
  done
  wait
  log_info "Phase2: Recording completed."
  getelapsedtime
  TDR=$(printf "%.2f" "$(subfloat "${CUR_TIME_REAL}" "${TSR}")")
  TDC=$(printf "%.2f" "$(subfloat "${CUR_TIME_CPU}" "${TSC}")")
  log_info "Phase2: Recording completed in ${TDR} seconds (or ${TDC} CPU seconds)."
  leave_workdir
}

# Analyze fix vs. random
#
# NREPS_GEN ... number of fixed inputs to consider
# NTRACE_GEN ... number of generic measurements to analyze (fixed, random)
function analyze_phase2 {
  enter_workdir
  FIXDIR="gen_trc_fix"
  RNDDIR="gen_trc_rnd"
  KEYDIR="gen_key_rnd"
  CMD_LOAD="loadleaks"
  CMD_STAT="generic"
  CMD_MERGE="merge"
  CMD_SHOW="show"
  RNDPIC="gen_rnd.pickle"

  log_info "Phase2: Starting generic leakage analysis."
  getelapsedtime
  TSR=$CUR_TIME_REAL
  TSC=$CUR_TIME_CPU
  if [[ "${NREPS_GEN}" == "" ]] || [[ "${NTRACE_GEN}" == "" ]]; then
    log_error "Please specify NREPS_GEN and NTRACE_GEN!"
    exit 1
  fi
  if ! [[ -f ${RESPICFILE_PHASE1} ]]; then
    log_error "Previous ${RESPICFILE_PHASE1} file not found!"
    exit 1
  fi
  if ! [[ -f ${RNDPIC} ]]; then
    log_info "Phase2: Preparing random-key traces."
    cp ${RESPICFILE_PHASE1} ${RNDPIC}
    if [[ "${DO_PARALLEL}" -eq "1" ]]; then
      execpar; execute "${ANALYZE}" ${CMD_LOAD} ${RNDPIC} --filepattern="${RNDDIR}/trace_rnd_%.${TRACEEXT}" --keypattern="${KEYDIR}/key_rnd_%.key" --start=1 --end="$NTRACE_GEN" --source 0 --debug 0 &
    else
      execute "${ANALYZE}" ${CMD_LOAD} ${RNDPIC} --filepattern="${RNDDIR}/trace_rnd_%.${TRACEEXT}" --keypattern="${KEYDIR}/key_rnd_%.key" --start=1 --end="$NTRACE_GEN" --source 0 --debug 0
    fi
  fi
  # load traces into pickle file
  for i in $(seq 1 "$NREPS_GEN"); do
    FIXPIC=gen_fix_${i}.pickle
    FIX_KEY=key$i.key
    if ! [[ -f ${FIXPIC} ]]; then
      log_info "Phase2: Preparing fixed-key traces."
      cp ${RESPICFILE_PHASE1} "${FIXPIC}"
      if [[ "${DO_PARALLEL}" -eq "1" ]]; then
        execpar; execute "${ANALYZE}" ${CMD_LOAD} "${FIXPIC}" --filepattern="${FIXDIR}/trace_fix_${i}_%.${TRACEEXT}" --keypattern="${FIX_KEY}" --start=1 --end="$NTRACE_GEN" --source 0 --debug 0 &
      else
        execute "${ANALYZE}" ${CMD_LOAD} "${FIXPIC}" --filepattern="${FIXDIR}/trace_fix_${i}_%.${TRACEEXT}" --keypattern="${FIX_KEY}" --start=1 --end="$NTRACE_GEN" --source 0 --debug 0
      fi
    fi
  done
  wait
  log_info "Phase2: Preparation of traces completed."
  log_info "Phase2: Running statistical tests."
  # analyze above generated pickle files
  for i in $(seq 1 "$NREPS_GEN"); do
    FIXPIC=gen_fix_${i}.pickle
    RESPIC=result_gen_${i}.pickle
    FIX_KEY=key$i.key
    if ! [[ -f ${RESPIC} ]]; then
      if [[ "${DO_PARALLEL}" -eq "1" ]]; then
        execpar; execute "${ANALYZE}" ${CMD_STAT} "${FIXPIC}" ${RNDPIC} --pickle "${RESPIC}" --syms ${EXTSYMFILE} --debug 0 &
      else
        execute "${ANALYZE}" ${CMD_STAT} "${FIXPIC}" ${RNDPIC} --pickle "${RESPIC}" --syms ${EXTSYMFILE} --debug 0
      fi
    fi
  done
  wait
  log_info "Phase2: Statistical tests completed."
  if ! [[ -e ${RESPICFILE_PHASE2} ]]; then
    log_info "Phase2: Merging results."
    if [[ "$NREPS_GEN" -eq "1" ]]; then
      FIRSTPIC="result_gen_1.pickle"
      ln -s ${FIRSTPIC} ${RESPICFILE_PHASE2}
      execute "${ANALYZE}" ${CMD_SHOW} "${FIRSTPIC}" --syms ${EXTSYMFILE} --xml ${RESXMLFILE_PHASE2} --debug 0
    else
      for i in $(seq 2 "$NREPS_GEN"); do
        PREVPIC=result_gen_$((i-1)).pickle
        CURPIC=result_gen_${i}.pickle
        if [[ "${i}" -eq "2" ]]; then
          execute "${ANALYZE}" ${CMD_MERGE} ${PREVPIC} "${CURPIC}" --syms ${EXTSYMFILE} --pickle ${RESPICFILE_PHASE2} --xml ${RESXMLFILE_PHASE2} --debug 0
        else
          execute "${ANALYZE}" ${CMD_MERGE} "${CURPIC}" ${RESPICFILE_PHASE2} --syms ${EXTSYMFILE} --pickle ${RESPICFILE_PHASE2} --xml ${RESXMLFILE_PHASE2} --debug 0
        fi
      done
    fi
    log_info "Phase2: Merging completed."
  fi
  getelapsedtime
  TDR=$(printf "%.2f" "$(subfloat "${CUR_TIME_REAL}" "${TSR}")")
  TDC=$(printf "%.2f" "$(subfloat "${CUR_TIME_CPU}" "${TSC}")")
  log_info "Phase2: Analysis completed in ${TDR} seconds (or ${TDC} CPU seconds)."
  leave_workdir
}

#------------------------------------------------------------------------
# Phase 3: Leakage Classification
#------------------------------------------------------------------------

# Requires function cb_run_command
# Requires function cb_genkey
# NTRACE_SPE ... number of specific measurements to take
# LEAKFILE ... previous leaks stored in binary file format
# NTRACE_GEN ... optional: number of generic measurements previously taken
function measure_phase3 {
  enter_workdir
  RNDDIR="spe_trc_rnd"
  KEYDIR="spe_key_rnd"
  RNDDIR_NS="gen_trc_rnd"
  KEYDIR_NS="gen_key_rnd"

  log_info "Phase3: Recording traces for specific leakage test."
  getelapsedtime
  TSR=$CUR_TIME_REAL
  TSC=$CUR_TIME_CPU
  if ! [[ -f ${LEAKFILE} ]]; then
    log_error "No leakfile ${LEAKFILE} found! Run phase 1 first!"
    exit 1
  fi
  if [[ "${NTRACE_SPE}" == "" ]]; then
    log_error "Please specify NTRACE_SPE!"
    exit 1
  fi
  mkdir -p ${RNDDIR}
  mkdir -p ${KEYDIR}
  if [[ "${DO_TRACE_REUSE}" -eq "1" ]]; then
    if [[ "${NTRACE_GEN}" == "" ]]; then
      log_error "Please specify NTRACE_GEN!"
      exit 1
    fi
    for j in $(seq 1 "$NTRACE_GEN"); do
      RFILE_NS=${RNDDIR_NS}/trace_rnd_$j.${TRACEEXT}
      RKEY_NS=${KEYDIR_NS}/key_rnd_$j.key
      RFILE_SP=${RNDDIR}/trace_rnd_$j.${TRACEEXT}
      RKEY_SP=${KEYDIR}/key_rnd_$j.key
      if (! [[ -f ${RFILE_NS} ]]) || (! [[ -f ${RKEY_NS} ]]); then
        log_error "Cannot re-use trace/key! File does not exist."
        exit 1
      fi
      if ! [[ -h ${RFILE_SP} ]]; then
        ln -r -s "${RFILE_NS}" "${RFILE_SP}"
      fi
      if ! [[ -h ${RKEY_SP} ]]; then
        ln -r -s "${RKEY_NS}" "${RKEY_SP}"
      fi
    done
  fi
  for j in $(seq 1 "$NTRACE_SPE"); do
    RND_FILE=${RNDDIR}/trace_rnd_$j.${TRACEEXT}
    RND_KEY=${KEYDIR}/key_rnd_$j.key
    if ! [[ -e ${RND_KEY} ]]; then
      genkey_wrapper "${RND_KEY}"
    fi
    if ! [[ -e ${RND_FILE} ]]; then
      if [[ "${DO_PARALLEL}" -eq "1" ]]; then
        execpar; run_pin ${PHASE3} "${RND_FILE}" "${RND_KEY}" & # random
      else
        run_pin ${PHASE3} "${RND_FILE}" "${RND_KEY}"   # random
      fi
    fi
  done
  wait
  getelapsedtime
  TDR=$(printf "%.2f" "$(subfloat "${CUR_TIME_REAL}" "${TSR}")")
  TDC=$(printf "%.2f" "$(subfloat "${CUR_TIME_CPU}" "${TSC}")")
  log_info "Phase3: Recording completed in ${TDR} seconds (or ${TDC} CPU seconds)."
  leave_workdir
}

# Analyze specific leakage
#
# NTRACE_SPE ... number of specific measurements to analyze
# $1 ... .py file that defines the specific leakage as a callback function
function analyze_phase3 {
  enter_workdir
  SPLEAKCB=$1
  SPLEAKCB_SUFFIX=$(basename "${SPLEAKCB}")
  SPLEAKCB_SUFFIX=${SPLEAKCB_SUFFIX%%.*}
  RNDDIR="spe_trc_rnd"
  KEYDIR="spe_key_rnd"
  CMD_LOAD="loadleaks"
  CMD_STAT="specific"
  CMD_SHOW="show"
  RNDPIC="spe_rnd.pickle"
  RESXML="${RESXMLFILE_PHASE3}_${SPLEAKCB_SUFFIX}.xml"
  RESPIC="${RESPICFILE_PHASE3}_${SPLEAKCB_SUFFIX}.pickle"

  log_info "Phase3: Starting specific leakage analysis."
  getelapsedtime
  TSR=$CUR_TIME_REAL
  TSC=$CUR_TIME_CPU
  if [[ "${NTRACE_SPE}" == "" ]]; then
    log_error "Please specify NTRACE_SPE!"
    exit 1
  fi
  if ! [[ -f ${SPLEAKCB} ]]; then
    log_error "Specific leakage callback function not specified!"
    exit 1
  fi
  if ! [[ -f ${RESPICFILE_PHASE2} ]]; then
    log_error "Previous ${RESPICFILE_PHASE2} file not found!"
    exit 1
  fi
  if ! [[ -f ${RNDPIC} ]]; then
    log_info "Phase3: Prepararing traces."
    cp ${RESPICFILE_PHASE2} ${RNDPIC}
    execute "${ANALYZE}" ${CMD_LOAD} ${RNDPIC} --filepattern="${RNDDIR}/trace_rnd_%.${TRACEEXT}" --keypattern="${KEYDIR}/key_rnd_%.key" --start=1 --end="$NTRACE_SPE" --source 1 --debug 0
    log_info "Phase3: Preparation of traces completed."
  fi
  if ! [[ -f ${RESPIC} ]]; then
    log_info "Phase3: Running statistical tests."
    execute "${ANALYZE}" ${CMD_STAT} ${RNDPIC} "${SPLEAKCB}" --pickle "${RESPIC}" --syms ${EXTSYMFILE} --debug 0
    log_info "Phase3: Statistical tests completed."
  fi
  if ! [[ -f ${RESXML} ]]; then
    execute "${ANALYZE}" ${CMD_SHOW} "${RESPIC}" --syms ${EXTSYMFILE} --xml "${RESXML}" --debug 0
  fi
  getelapsedtime
  TDR=$(printf "%.2f" "$(subfloat "${CUR_TIME_REAL}" "${TSR}")")
  TDC=$(printf "%.2f" "$(subfloat "${CUR_TIME_CPU}" "${TSC}")")
  log_info "Phase3: Analysis completed in ${TDR} seconds (or ${TDC} CPU seconds)."
  leave_workdir
}

#------------------------------------------------------------------------
# Report Generation
#------------------------------------------------------------------------

function export_framework_files {
  enter_workdir
  CMD_EXPORT="export"
  log_info "Exporting framework files"
  if ! [[ -f ${EXPORTFILE} ]]; then
    execute "${ANALYZE}" ${CMD_EXPORT} "${RESPICFILE_PHASE1}" "${EXPORTFILE}" --syms ${EXTSYMFILE} --debug 0
  fi
  log_info "Exporting completed."
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
  CMD_MERGE="merge"
  CMD_SHOW="show"

  log_info "Generating final result and report files."
  if ! [[ -f ${ALLPIC} ]]; then
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
        execute "${ANALYZE}" ${CMD_MERGE} ${ALLPIC} "${f}" --syms ${EXTSYMFILE} --pickle ${ALLPIC} --debug 0
      fi
    done
  fi
  if ! [[ -f ${ALLXML} ]]; then
    execute "${ANALYZE}" ${CMD_SHOW} ${ALLPIC} --syms ${EXTSYMFILE} --xml ${ALLXML} --debug 0
  fi
  log_info "Generating completed."
  leave_workdir
}

#------------------------------------------------------------------------
# Framework CLI
#------------------------------------------------------------------------

function DATA_run {
  SUBALGO=
  for SA in "$@"; do
    SUBALGO=${SUBALGO}/${SA}
  done

  enter_workdir
  log_verbose "#TIME $(date +"%Y_%d_%m-%H:%M:%S")"
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
    if [[ "${DO_EXPORT}" -eq "1" ]]; then
      export_framework_files
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
        measure_phase3
      fi
      if [[ "${DO_PHASE3_ANALYZE}" -eq "1" ]]; then
        analyze_phase3 "${SPECIFIC_LEAKAGE_CALLBACK}"
      fi
      if [[ "${DO_FINAL}" -eq "1" ]]; then
        generate_final_result_XMLs
      fi
    fi
    if [[ "${DO_CLEANUP}" -eq "1" ]]; then
      cleanup
    fi
  fi

  enter_workdir
  log_verbose "#TIME $(date +"%Y_%d_%m-%H:%M:%S")"
  leave_workdir
}

# $* ... command line arguments
function DATA_parse {
  
  if [[ $# -eq 0 ]]; then
    help
  fi
  
  while [[ $# -gt 0 ]]
  do
    key="$1"
    case $key in
        -h|--help)
        help
        ;;
        -l|--list)
        list_targets
        ;;
        -n|--newfolder)
        DO_NEWFOLDER=1
        shift
        ;;
        -g|--genkeys)
        DO_GENKEYS=1
        shift
        ;;
        -d|--diff)
        DO_PHASE1_MEASURE=1
        shift
        ;;
        -ad|--alyzed)
        DO_PHASE1_ANALYZE=1
        shift
        ;;
        -ns|--generic)
        DO_PHASE2_MEASURE=1
        shift
        ;;
        -an|--alyzens)
        DO_PHASE2_ANALYZE=1
        shift
        ;;
        -sp|--specific)
        DO_PHASE3_MEASURE=1
        shift
        ;;
        -as|--alyzesp)
        DO_PHASE3_ANALYZE=1
        shift
        ;;
        -u|--reusetraces)
        DO_TRACE_REUSE=1
        shift
        ;;
        -p|--parallel)
        DO_PARALLEL=1
        shift
        ;;
        -c|--cleanup)
        DO_CLEANUP=1
        shift
        ;;
        -i|--final)
        DO_FINAL=1
        shift
        ;;
        -e|--export)
        DO_EXPORT=1
        shift
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
        shift
        ;;
        --dry)
        DO_DRY=1
        shift
        ;;
        *)
        break
        ;;
    esac
  done
  if [[ "${DO_NEWFOLDER}" -eq "1" ]]; then
    new_folder
  fi
  
  if [[ "$1" = "all" ]]; then
    if ! [[ ${TARGETFILE} ]]; then
      print_error "Missing TARGETFILE ${TARGETFILE}"
      exit 1
    fi
    init_for_run
    while read LINE; do
      if [[ "${LINE}" == "" ]] || [[ ${LINE} == "#*" ]]; then
        # Skip comments and empty lines
        continue
      fi
      enter_frameworkdir
      print_info "Testing '$LINE'"
      leave_frameworkdir
      
      setstarttime
      cb_run_single "${LINE}"
      getelapsedtime
      getpeakmemory
      
      enter_frameworkdir
      if [[ ${PEAK_MEMORY} == 0 ]]; then
        print_info "$(printf "Testing '$LINE' completed in %.2f seconds (or %.2f CPU seconds)" "$DIFF_TIME_REAL" "$DIFF_TIME_CPU")"
      else
        print_info "$(printf "Testing '$LINE' completed in %.2f seconds (or %.2f CPU seconds) with a peak RAM usage of ${PEAK_MEMORY} MiB" "$DIFF_TIME_REAL" "$DIFF_TIME_CPU")"
      fi
      leave_frameworkdir
      echo "============================================================"
    done < "${TARGETFILE}"
  else
    if [[ $# -ge 1 ]]; then
      init_for_run
    fi
    while [[ $# -ge 1 ]]
    do
      SHIFT=0
      ALGOCMDLINE="$*"
      grep -q -e "^${ALGOCMDLINE}$" "${TARGETFILE}"
      if [[ "$?" -ne "0" ]]; then
        print_error "Invalid algorithm ${ALGOCMDLINE}!"
        print_error "Choose one of:"
        cat "${TARGETFILE}"
        exit 1
      fi
      enter_frameworkdir
      print_info "Testing '$ALGOCMDLINE'"
      leave_frameworkdir
      
      setstarttime
      cb_run_single "$@"
      getelapsedtime
      getpeakmemory
      
      enter_frameworkdir
      if [[ ${PEAK_MEMORY} == 0 ]]; then
        print_info "$(printf "Testing '$ALGOCMDLINE' completed in %.2f seconds (or %.2f CPU seconds)" "$DIFF_TIME_REAL" "$DIFF_TIME_CPU")"
      else
        print_info "$(printf "Testing '$ALGOCMDLINE' completed in %.2f seconds (or %.2f CPU seconds) with a peak RAM usage of ${PEAK_MEMORY} MiB" "$DIFF_TIME_REAL" "$DIFF_TIME_CPU")"
      fi
      leave_frameworkdir
      echo "============================================================"
      shift
      shift ${SHIFT}
    done
  fi
}

function help {
  echo "./<script>.sh [options] [all | target1 bs1 ... targetN bsN]"
  echo "all               Run all known targets"
  echo "target1 ks1 ...   Run given target (e.g. des3) with given key bit size (e.g. 192)"
  echo "                  Chaining of several targets is possible"
  echo "options:"
  echo "-l|--list         List all available targets"
  echo "-n|--newfolder    Create a new result folder with current time. Does not require target"
  echo "-g|--genkeys      Phase1: Generate new keys"
  echo "-d|--diff         Phase1: Generate traces with varying key for detecting differences"
  echo "-ad|--alyzed      Phase1: Analyze traces for differences and create xml reports"
  echo "-ns|--generic     Phase2: Generate traces with fixed vs. random keys to perform generic leakage tests"
  echo "-an|--alyzens     Phase2: Analyze traces for generic leakage and create xml reports"
  echo "-sp|--specific    Phase3: Generate traces with random keys to perform specific leakage tests"
  echo "-u|--reusetraces  Phase3: Re-use existing traces from generic tests for specific tests"
  echo "-as|--alyzesp     Phase3: Analyze traces for specific leakage and create xml reports"
  echo "-p|--parallel     Run tasks in parallel"
  echo "-i|--final        Generate final result XML files"
  echo "-e|--export       Export framework files (ELF/asm/src) in a zip archive"
  echo "-c|--cleanup      Delete phase1 trace files afterwards"
  echo "--dry             Dry-run phase1 (-g and --diff) to test your script with extended debug output"
  echo "-f|--full         Run -g -d -ad -ns -an -sp -as -i"
  exit
}

init
