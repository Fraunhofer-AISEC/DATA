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
# @package analysis.leakage_models.ecdsa_privkey_hw
# @file ecdsa_privkey_hw.py
# @brief Specific leakage test callback (ECDSA private key HW)
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3


import numpy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

"""
Input: ECDSA keys -- 2D list/array. one key per row
Output: Hamming weight of all private key members -- 2D numpy array, row = HW(entire key)
"""


def specific_leakage_callback(inputs):
    hw = numpy.ndarray((len(inputs), 1), dtype=numpy.int)
    for i in range(0, len(inputs)):
        # load key and prep
        keyobj = serialization.load_pem_private_key(
            inputs[i], password=None, backend=default_backend()
        )

        if hasattr(keyobj, "key_size"):
            bytelen = int(keyobj.key_size / 8)
            fstr = "%0" + ("%d" % (2 * bytelen)) + "x"
        else:
            fstr = "%x"

        if hasattr(keyobj, "private_numbers"):
            xhex = fstr % keyobj.private_numbers().private_value
            keybytes = bytearray.fromhex(xhex)
        elif hasattr(keyobj, "private_bytes"):
            # Ed25519 curve
            keybytes = keyobj.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            keybytes = bytearray(keybytes)
        else:
            raise ValueError("Unsupported key type")

        # convert to bits and count HW
        hw[i][0] = numpy.count_nonzero(
            numpy.unpackbits(numpy.asarray(keybytes, dtype=numpy.uint8))
        )
    return hw
