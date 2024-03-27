#!/bin/bash

set -e

# PINFLAGS="--phase1 --export"
PINFLAGS="--phase1 --phase2 --export --parallel"
# PINFLAGS="--phase1 --export --parallel"
export RESULTDIR=results


pushd ${BASH_SOURCE%/*}

if [[ $1 == "clean" || $2 == "clean" ]]; then
    rm -rf $RESULTDIR
fi

./framework.sh ${PINFLAGS} minimal

if [[ $1 == "test" || $2 == "test" ]]; then
    popd
    exit 0
fi

./framework.sh ${PINFLAGS} mceliece348864
./framework.sh ${PINFLAGS} mceliece6688128
./framework.sh ${PINFLAGS} mceliece6688128f
./framework.sh ${PINFLAGS} mceliece6688128pc
./framework.sh ${PINFLAGS} mceliece6688128pcf

popd
