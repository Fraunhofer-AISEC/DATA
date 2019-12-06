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
# @package analysis.leakage_models.dsa_nonce
# @file dsa_nonce.py
# @brief Specific leakage test callback (DSA private key HW)
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3

"""
*************************************************************************
"""

import numpy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

"""
Input: DSA nonces -- 2D list/array.
       Each input (in inputs) contains several lines.
       Each line consists of a name and a value seperated by \t.
       The value can be decimal or hexadecimal (starting with 0x).
Output: THINGS of all private key members -- 2D numpy array, row = THINGS(nonces)
"""
def specific_leakage_callback(inputs):
    def input_to_lines(input):
        # each input is mapped to multiple lines containing a key & value each
        #prefixes = ('bit', 'hw(')
        prefixes = ('bits(', 'hw(')
        lines = input.decode('ASCII').split('\n')
        lines = [x.split('\t') for x in lines if x.strip() != '']
        return [l for l in lines if l[0].startswith(prefixes)]

    # prepare output data structure:
    labels = [k for k,v in input_to_lines(inputs[0]) ]
    num_lines_per_input = len(input_to_lines(inputs[0]))
    result = numpy.ndarray((len(inputs), num_lines_per_input), dtype=numpy.int)

    for (i, input) in enumerate(inputs):
        result[i][:] = [v for k,v in input_to_lines(input) ]

    return (result,labels)
