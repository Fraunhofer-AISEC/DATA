#!/bin/bash

set -e

# OPTIONS="--phase1 --phase2 --export --parallel"
OPTIONS="--phase1"
export RESULTDIR=${PWD}/results

cd selftest-heap
./framework.sh ${OPTIONS} basic 8
cd ..
