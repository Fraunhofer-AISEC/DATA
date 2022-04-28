#!/bin/bash

set -e

OPTIONS="--phase1 --phase2 --export --parallel"
export RESULTDIR=results

pushd ${BASH_SOURCE%/*}
./framework.sh ${OPTIONS} basic 8
popd
