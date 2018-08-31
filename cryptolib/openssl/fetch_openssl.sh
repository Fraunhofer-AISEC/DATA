#!/bin/bash

#########################################################################
# Copyright (C) 2017-2018
# Samuel Weiser (IAIK TU Graz) and Andreas Zankl (Fraunhofer AISEC)
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
# @author Samuel Weiser <samuel.weiser@iaik.tugraz.at>
# @author Andreas Zankl <andreas.zankl@aisec.fraunhofer.de>
# @license This project is released under the GNU GPLv3 License.
# @version 0.1
#########################################################################

#------------------------------------------------------------------------
# Settings
#------------------------------------------------------------------------
OPENSSLDIR=openssl

#------------------------------------------------------------------------
# Fetch and Build
#------------------------------------------------------------------------
if [[ ! -d ${OPENSSLDIR} ]]; then
  git clone --depth 1 --branch OpenSSL_1_1_0f git://git.openssl.org/openssl.git
else
  echo "Skipping repo cloning"
fi
cd ${OPENSSLDIR}
if [[ ! -f libcrypto.so ]]; then
  # Build openssl with debug symbols
  ./config -g
  make -j4
else
  echo "Skipping build"
fi
echo "Done."

