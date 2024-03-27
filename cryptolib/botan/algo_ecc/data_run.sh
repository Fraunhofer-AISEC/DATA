#!/bin/bash

set -e

PINFLAGS="--phase1 --phase2 --export --parallel"
export RESULTDIR=results


pushd ${BASH_SOURCE%/*}

if [[ $1 == "clean" || $2 == "clean" ]]; then
    rm -rf results
fi

./framework.sh ${PINFLAGS} ECDSA brainpool192r1

if [[ $1 == "test" || $2 == "test" ]]; then
    popd
    exit 0
fi

./framework.sh ${PINFLAGS} ECDSA brainpool256r1
./framework.sh ${PINFLAGS} ECDSA brainpool384r1
./framework.sh ${PINFLAGS} ECDSA brainpool512r1

popd