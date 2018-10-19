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
# @version 0.2
#########################################################################

#------------------------------------------------------------------------
# Settings
#------------------------------------------------------------------------
OPENSSLDIR=openssl
set -e

#------------------------------------------------------------------------
# Fetch and Build
#------------------------------------------------------------------------
if [[ ! -d ${OPENSSLDIR} ]]; then
  git clone --depth 1 --branch OpenSSL_1_1_1 git://git.openssl.org/openssl.git
fi
cd ${OPENSSLDIR}
if [[ ! -f libcrypto.so ]]; then
  # Build openssl with debug symbols
  ./config -g
  make -j"$(nproc)"
fi

