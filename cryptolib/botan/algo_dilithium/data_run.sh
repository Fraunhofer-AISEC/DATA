#!/bin/bash

set -e

PINFLAGS="--phase1 --phase2 --export --parallel"
export RESULTDIR=results


pushd ${BASH_SOURCE%/*}

if [[ $1 == "clean" || $2 == "clean" ]]; then
    rm -rf results
fi

./framework.sh ${PINFLAGS} 4x4

if [[ $1 == "test" || $2 == "test" ]]; then
    popd
    exit 0
fi

./framework.sh ${PINFLAGS} 4x4_AES
./framework.sh ${PINFLAGS} 6x5
./framework.sh ${PINFLAGS} 6x5_AES
./framework.sh ${PINFLAGS} 8x7
./framework.sh ${PINFLAGS} 8x7_AES

popd
