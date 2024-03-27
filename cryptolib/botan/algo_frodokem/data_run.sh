#!/bin/bash

set -e

PINFLAGS="--phase1 --phase2 --export --parallel"
export RESULTDIR=/new_data/ssd1/data/wagner/bsi/DATA/results/algo_frodokem


pushd ${BASH_SOURCE%/*}

if [[ $1 == "clean" || $2 == "clean" ]]; then
    rm -rf $RESULTDIR
fi

./framework.sh ${PINFLAGS} KEM640_SHAKE

if [[ $1 == "test" || $2 == "test" ]]; then
    popd
    exit 0
fi

./framework.sh ${PINFLAGS} KEM976_SHAKE
./framework.sh ${PINFLAGS} KEM1344_SHAKE
./framework.sh ${PINFLAGS} eKEM640_SHAKE
./framework.sh ${PINFLAGS} eKEM976_SHAKE
./framework.sh ${PINFLAGS} eKEM1344_SHAKE

./framework.sh ${PINFLAGS} KEM640_AES
./framework.sh ${PINFLAGS} KEM976_AES
./framework.sh ${PINFLAGS} KEM1344_AES
./framework.sh ${PINFLAGS} eKEM640_AES
./framework.sh ${PINFLAGS} eKEM976_AES
./framework.sh ${PINFLAGS} eKEM1344_AES

popd
