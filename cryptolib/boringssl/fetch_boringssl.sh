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
# @file fetch_boringssl.sh
# @brief Retrieves and compiles BoringSSL.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3
#########################################################################

source config.sh

#------------------------------------------------------------------------
# Settings
#------------------------------------------------------------------------
set -e
GO_FILE=go1.12.7.linux-amd64.tar.gz

#------------------------------------------------------------------------
# Install Go. Needed during compilation only
#------------------------------------------------------------------------
if ! which go; then
  if ! [[ -d "go" ]]; then
    wget https://dl.google.com/go/"${GO_FILE}"
    tar -xvf ${GO_FILE}
  fi
  export PATH=$PATH:$PWD/go/bin
fi
rm -f ${GO_FILE}

#------------------------------------------------------------------------
# Fetch and build BoringSSL
#------------------------------------------------------------------------

if [[ ! -d "${BORINGSSLDIR}" ]]; then
  git clone https://github.com/google/boringssl.git
  cd "${BORINGSSLDIR}"
fi

mkdir -p "${BUILDDIR}"
cd "${BUILDDIR}"

if [[ ! -f tool/bssl ]]; then
  MOREFLAGS="-DCMAKE_CXX_FLAGS=-Wno-error=unused-result "
  if [[ "${SETARCH}" == "i386" ]]; then
    # Install `sudo apt-get install g++-multilib`
    #
    # 32-bit does not fully compile yet
    # Try to add to the 32-bit-toolchain.cmake file:
    #   add_compile_options(-m32)
    #   add_link_options(-m32)
    MOREFLAGS+=" -DCMAKE_TOOLCHAIN_FILE=${BORINGSSLDIR}/util/32-bit-toolchain.cmake"
  fi
  #Note that the default build flags in the top-level CMakeLists.txt are for debugging
  # - optimisation isn't enabled.
  #Pass -DCMAKE_BUILD_TYPE=Release to cmake to configure a release build.
  #
  cmake ${BORINGSSLDIR} -DCMAKE_BUILD_TYPE=Release ${MOREFLAGS} ${FLAGS}
  make -j"$(nproc)"
fi
