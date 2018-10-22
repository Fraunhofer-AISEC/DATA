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
# @file glibc_bind.sh
# @brief Allows to preload libc.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.2
#########################################################################

#------------------------------------------------------------------------
# Bind
#------------------------------------------------------------------------
if [[ "${PRELOAD}" == "" ]]; then
  echo "This script is only to be sourced from common.sh"
else
  # (re)generate clean environment file
  rm -rf "${CLEANENVFILE}"
  echo "LD_BIND_NOW=1" >> "${CLEANENVFILE}"
  # Link all shared libraries for pre-loading
  PRELOAD_LIBS=""
  for f in *.so; do
    if [[ -e "$f" ]]; then
      if [[ "${PRELOAD_LIBS}" == "" ]]; then
        PRELOAD_LIBS="${PRELOAD}/$f"
      else
        PRELOAD_LIBS="${PRELOAD_LIBS}:${PRELOAD}/$f"
      fi
    fi
  done
  echo "LD_PRELOAD=${PRELOAD_LIBS}" >> "${CLEANENVFILE}"
fi
