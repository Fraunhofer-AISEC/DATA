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
# @package analysis.datastub.ipinfoshort
# @file IpInfoShort.py
# @brief Class for storing assembly and source code infos.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3

"""
*************************************************************************
"""

IP_INFO_FILE = u'ip_info.pickle'

class IpInfoShort:
    def __init__(self, asm_file, asm_line_nr, src_file, src_line_nr):
        self.asm_file = asm_file
        self.asm_line_nr = asm_line_nr
        self.src_file = src_file
        self.src_line_nr = src_line_nr

