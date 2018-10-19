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
# @file release.sh
# @brief Increases the version number in all license headers.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.2
#########################################################################

#------------------------------------------------------------------------
# Settings
#------------------------------------------------------------------------
VER=0.2

#------------------------------------------------------------------------
# Update version number in all license headers
#------------------------------------------------------------------------
for f in $(git ls-files); do
  grep "@version" "$f" > /dev/null
  if [[ "$?" -eq "0" ]]; then
    echo "Setting version number in $f"
    # search for '@version' string and 
    # replace the following version number with ${VER}
    # xxx can be digits and dots
    sed -i "s/\(@version\s\+\)[.0-9]\+/\1${VER}/g" "$f"
  fi
done

UNTRACKED=$(git status --porcelain | grep -e "^??")
if ! [[ -z "${UNTRACKED}" ]]; then
  echo "You have untracked files. They are not be updated!"
  echo "${UNTRACKED}"
fi

