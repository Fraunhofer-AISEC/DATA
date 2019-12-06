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
# @file fetch_libressl.sh
# @brief Retrieves and compiles LibreSSL.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3
#########################################################################

source config.sh

#------------------------------------------------------------------------
# Settings
#------------------------------------------------------------------------
set -e

#------------------------------------------------------------------------
# Fetch and prepare
#------------------------------------------------------------------------
if [[ ! -d "${LIBRESSLDIR}" ]]; then
  git clone --depth 1 --branch v3.0.0 https://github.com/libressl-portable/portable.git
  cd "${LIBRESSLDIR}"
  git apply ../patches/00_version3.0.0.patch
  ./autogen.sh
fi

mkdir -p "${BUILDDIR}"
cd "${BUILDDIR}"

#------------------------------------------------------------------------
# Cmake + Make
#------------------------------------------------------------------------
if [[ ! -f "${BUILDDIR}/apps/openssl/openssl" ]]; then
  MOREFLAGS="-g"
  if [[ "${SETARCH}" == "i386" ]]; then
    MOREFLAGS+=" -m32"
  fi
  cd "${BUILDDIR}"
  setarch ${SETARCH} cmake "${LIBRESSLDIR}" -DCMAKE_C_FLAGS="${MOREFLAGS}" -DBUILD_SHARED_LIBS=ON ${FLAGS}
  make -j"$(nproc)"
fi
