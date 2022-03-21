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
# @package cryptolib.common.genhexstr
# @file genhexstr.py
# @brief Creates a random hex string of the length provided as commandline argument.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3


import os
import sys
import math

rlen = int(sys.argv[-1])
rnum = math.ceil(rlen / 2)
rnd = os.urandom(rnum).hex()
sys.stdout.write(str.format("%s" % rnd[:rlen]))
