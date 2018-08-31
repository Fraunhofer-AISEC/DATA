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
# @file pyenv.sh
# @brief Sets up a Python virtual environment.
# @author Samuel Weiser <samuel.weiser@iaik.tugraz.at>
# @author Andreas Zankl <andreas.zankl@aisec.fraunhofer.de>
# @license This project is released under the GNU GPLv3 License.
# @version 0.1
#########################################################################

#------------------------------------------------------------------------
# Settings
#------------------------------------------------------------------------
ENV=.pyenv

#------------------------------------------------------------------------
# Create Environment
#------------------------------------------------------------------------
if ! [[ -f ${ENV}/.done ]]; then
  LOAD_PYENV_INTERPRETER=/usr/bin/python2.7
  virtualenv -p ${LOAD_PYENV_INTERPRETER} ${ENV} || exit 1
  source ${ENV}/bin/activate
  pip install -U setuptools
  pip install click cffi ipaddress enum34 numpy scipy scikit-learn cryptography pycrypto || exit 1
  python kuipertest_setup.py build install || exit 1
  touch ${ENV}/.done
else
  echo "Skipping virtualenv setup"
fi
source ${ENV}/bin/activate
echo "Done."

