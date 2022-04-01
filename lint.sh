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
# @file lint.sh
# @brief Performs code linting and reports results.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3
#########################################################################

#------------------------------------------------------------------------
# Settings
#------------------------------------------------------------------------

# check if data.sh is sourced
if [[ "${DATA_ROOT}" == "" ]]; then
  echo "DATA not loaded! 'source data.sh' first"
  return 1
fi

# global return value
rv=0

#------------------------------------------------------------------------
# black
#------------------------------------------------------------------------

black --check --diff --extend-exclude data-gui . &> black.log
rv1=$?
if [ $rv1 -ne 0 ]; then
  echo "black detected some problems. please check black.log!"
fi
rv=$(( rv | rv1 ))

#------------------------------------------------------------------------
# flake8
#
# E203 ... whitespace before ',', ';', or ':'
# E266 ... too many leading '#' for block comment
# E501 ... line too long (82 > 79 characters)
# W503 ... line break before binary operator
#------------------------------------------------------------------------

pushd analysis &> /dev/null || (echo "Error: pushd failed!"; exit)
flake8 --statistics --max-line-length=88 --ignore=E203,E266,E501,W503 --exclude __pycache__,.pyenv > "${DATA_ROOT}"/flake8.log
rv1=$?
popd &> /dev/null || (echo "Error: popd failed!"; exit)

pushd cryptolib/common &> /dev/null || (echo "Error: pushd failed!"; exit)
flake8 --statistics --max-line-length=88 --ignore=E203,E266,E501,W503 --exclude openssl >> "${DATA_ROOT}"/flake8.log
rv2=$?
popd &> /dev/null || (echo "Error: popd failed!"; exit)

if [ $rv1 -ne 0 ] || [ $rv2 -ne 0 ]; then
  echo "flake8 detected some problems. please check flake8.log!"
fi
rv=$(( rv | rv1 ))
rv=$(( rv | rv2 ))

#------------------------------------------------------------------------
# Clean-up
#------------------------------------------------------------------------

if [ $rv -eq 0 ]; then
  echo "No linting issues found!"
  rm -f black.log
  rm -f flake8.log
fi
