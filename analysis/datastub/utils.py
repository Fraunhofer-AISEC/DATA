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
# @package analysis.datastub.utils
# @file utils.py
# @brief Util functions.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3


import sys

debug_level = 0
do_assert = False


def debuglevel(level):
    return debug_level >= level


def set_debuglevel(level):
    global debug_level
    if level >= 0:
        debug_level = level


def debug(level, fstr, values=()):
    if debug_level >= level:
        print(fstr % values)
        sys.stdout.flush()


def sorted_keys(mymap):
    return sorted(mymap.keys())


def progress(idx, number):
    percentage = (idx + 1) / number * 100.0
    msg = f"[Progress] {percentage:6.2f}%%"
    if number > 10:
        if (idx % int(number / 10)) == 0:
            debug(0, msg)
    else:
        debug(0, msg)
