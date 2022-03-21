#!/bin/bash

set -e

OPTIONS="--full --export --parallel"
export RESULTDIR=${PWD}/results

cd selftest
./framework.sh ${OPTIONS} basic 8
./framework.sh ${OPTIONS} basic 64
sed -i 's/sym_nibble_high.py/sym_msb_byte.py/g' framework.sh
./framework.sh --phase3 --final --parallel basic 8
./framework.sh --phase3 --final --parallel basic 64
sed -i 's/sym_msb_byte.py/sym_nibble_high.py/g' framework.sh
cd ..
