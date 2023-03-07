#!/bin/bash

set -e

PINFLAGS="--phase1 --phase2 --export --parallel"
export RESULTDIR=results


pushd ${BASH_SOURCE%/*}

if [[ $1 == "clean" || $2 == "clean" ]]; then
    rm -rf results
fi

./framework.sh ${PINFLAGS} DES 64 CBC

if [[ $1 == "test" || $2 == "test" ]]; then
    popd
    exit 0
fi

./framework.sh ${PINFLAGS} 3DES 192 CBC

popd
