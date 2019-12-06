#!/bin/bash

MAINDIR=$PWD
DATADIR=${MAINDIR}/../../

########################################################################
# Setup DATA
########################################################################
make -C "${DATADIR}"
source "${DATADIR}/data.sh" || { echo "DATA is not installed!" && exit 1; }

datagui
