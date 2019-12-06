#!/bin/bash

MAINDIR=$PWD
DATADIR=${MAINDIR}/../../
export RESULTDIR=$PWD/results

# Run phase 1 and 3
# Use multiprocessing (-p)
# Create final files (-i)
# Do cleanup to save disk space (-c)
#
DATAFLAGS="--phase1 --phase3 -p -i -c"

# FASTER: If you want to speed up phase1 analysis, uncomment the next line
DATAFLAGS="--phase1 5 --phase3 -p -i -c"

# FASTEST: To skip phase3, uncomment the next line
#DATAFLAGS="--phase1 5 -p -c"

# After each analysis, the GUI is opened to display the result
#
# Export framework for GUI (-e)
# Start GUI on last results (--gui)
DATAGUIFLAGS="-e --gui"

# To deactivate opening the GUI for each result, uncomment the next line
#DATAGUIFLAGS=


########################################################################
# Setup DATA
########################################################################
make -C "${DATADIR}"
source "${DATADIR}/data.sh" || { echo "DATA is not installed!" && exit 1; }

########################################################################
# BoringSSL
########################################################################
cd "${MAINDIR}/boringssl"
# Test BoringSSL secp521r1 in default configuration
./asymmetric.sh ${DATAFLAGS} ec_nonce P-521
# Start GUI in background process
./asymmetric.sh ${DATAGUIFLAGS} ec_nonce P-521 &

########################################################################
# OpenSSL
########################################################################
cd "${MAINDIR}/openssl"
# Test OpenSSL DSA-256 in default configuration
./asymmetric.sh ${DATAFLAGS} dsa_nonce 256
# Start GUI in background process
./asymmetric.sh ${DATAGUIFLAGS} dsa_nonce 256 &

# Test OpenSSL secp521r1 optimized implementation
FLAGS="enable-ec_nistp_64_gcc_128" ./asymmetric.sh ${DATAFLAGS} ec_nonce secp521r1
# Start GUI in background process
FLAGS="enable-ec_nistp_64_gcc_128" ./asymmetric.sh ${DATAGUIFLAGS} ec_nonce secp521r1 &

# Test OpenSSL secp521 with artificially introduced leak
set -e # Halt on errors
cd "${MAINDIR}/openssl"
source config.sh
./fetch_openssl.sh
# Copy original OpenSSL
if ! [[ -d "${BUILDDIR}-artificial" ]]; then
  cp -r "${BUILDDIR}" "${BUILDDIR}-artificial"
fi

# Introduce artificial leak
cd "${BUILDDIR}-artificial/openssl"
git reset --hard
git apply "${MAINDIR}/supplementary/openssl_artificial_leak.patch"
# OpenSSL sometimes needs two make invocations. First one might fail
set +e # Ignore errors
make -j`nproc`
set -e # Halt on errors
make -j`nproc`
set +e # Ignore errors
cd "${MAINDIR}/openssl"
FLAGS="artificial" ./asymmetric.sh ${DATAFLAGS} ec_nonce secp521r1
# Start GUI in background process
FLAGS="artificial" ./asymmetric.sh ${DATAGUIFLAGS} ec_nonce secp521r1 &

# Test Edwards curves (phase1 only)
./other.sh --phase1 -p -c edwards 448 edwards 25519
./other.sh ${DATAGUIFLAGS} edwards 448 edwards 25519 &

########################################################################
# LibreSSL
########################################################################
cd "${MAINDIR}/libressl"
# Test LibreSSL sect131r1 in default configuration.
# NOTE: PHASE3 CAN TAKE QUITE SOME TIME! CONSIDER USING A MULTICORE CLUSTER!
#./asymmetric.sh ${DATAFLAGS} ec_nonce sect131r1
# Start GUI in background process
#./asymmetric.sh ${DATAGUIFLAGS} ec_nonce sect131r1 &

echo "FINISHED run.sh"
