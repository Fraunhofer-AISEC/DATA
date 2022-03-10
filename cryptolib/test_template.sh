#!/bin/bash

set -e

PINFLAGS="--full --export --parallel"
export RESULTDIR=${PWD}/test_results

cd template
./template.sh ${PINFLAGS} TEST 128
cd ..
