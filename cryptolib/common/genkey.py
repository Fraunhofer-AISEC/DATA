#!/usr/bin/env python3

"""
Copyright (C) 2017-2018 IAIK TU Graz and Fraunhofer AISEC

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

##
# @package cryptolib.common.genkey
# @file genkey.py
# @brief Creates a random key of the byte length provided as commandline argument.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3

"""
*************************************************************************
"""

import os
import sys
import codecs

kbytes = int(sys.argv[-1])
fmt = "%0" + str(kbytes * 2) + "x"
sys.stdout.write(str.format(fmt % int(os.urandom(kbytes).hex(), 16)))
