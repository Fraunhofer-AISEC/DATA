"""
Copyright (C) 2017-2018
Samuel Weiser (IAIK TU Graz) and Andreas Zankl (Fraunhofer AISEC)

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
# @package analysis.leakage_models.sym_byte_value
# @file sym_byte_value.py
# @brief Specific leakage test callback (Symmetric key byte-wise)
# @author Samuel Weiser <samuel.weiser@iaik.tugraz.at>
# @author Andreas Zankl <andreas.zankl@aisec.fraunhofer.de>
# @license This project is released under the GNU GPLv3 License.
# @version 0.1

"""
*************************************************************************
"""

import numpy

"""
Input: Symmetric keys -- 2D list/array, one key per row
Output: Values of key bytes -- 2D numpy array, one key per row
"""
def specific_leakage_callback(inputs):
    blist = [bytearray.fromhex(inputs[i]) for i in range(0, len(inputs))]
    iconv = numpy.asarray(blist, dtype=numpy.uint8)
    return (iconv)

