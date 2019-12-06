#!/bin/bash

#########################################################################
# Copyright (C) 2017-2018 IAIK TU Graz and Fraunhofer AISEC
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#########################################################################
# @file fetch_openssl.sh
# @brief Retrieves and compiles OpenSSL.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3
#########################################################################

source config.sh

#------------------------------------------------------------------------
# Settings
#------------------------------------------------------------------------
OPENSSLDIR=$BUILDDIR/openssl
set -e

#------------------------------------------------------------------------
# Fetch and Build
#------------------------------------------------------------------------
if [[ ! -d "${BUILDDIR}" ]]; then
  mkdir -p "${BUILDDIR}"
fi
cd "${BUILDDIR}"

if [[ ! -d "${OPENSSLDIR}" ]]; then
  git clone https://github.com/openssl/openssl.git
fi
cd "${OPENSSLDIR}"

if [[ ! -f apps/openssl ]]; then
  MOREFLAGS=
  if [[ "${SETARCH}" == "i386" ]]; then
    MOREFLAGS="-m32"
  fi
  # Build openssl with debug symbols
  setarch ${SETARCH} ./config -g ${FLAGS} ${MOREFLAGS}
  make -j"$(nproc)"
fi
