#!/usr/bin/python2

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
# @package cryptolib.python.symmetric
# @file symmetric.py
# @brief Creates a random key for the cipher provided as commandline argument.
# @author Samuel Weiser <samuel.weiser@iaik.tugraz.at>
# @author Andreas Zankl <andreas.zankl@aisec.fraunhofer.de>
# @license This project is released under the GNU GPLv3 License.
# @version 0.1

"""
*************************************************************************
"""

import click
import os
import sys
from Crypto.Cipher import *
import Crypto

"""
*************************************************************************
"""

@click.group()
def cli():
    pass

# Returns the maximum number of supported key bytes
def getkeybytes(algo):
    A = eval(algo)
    keysize = A.key_size
    if type(keysize) is tuple:
      keybytes = keysize[-1]
    elif type(keysize) is xrange:
      keybytes = keysize[-1]
    else:
      keybytes = keysize
    return keybytes

@cli.command('genkey')
@click.argument('algo', type=str)
@click.argument('keyfile', type=click.File('wb'))
def genkey(algo, keyfile):
    keyfile.write(os.urandom(getkeybytes(algo)))

@cli.command('run')
@click.argument('algo', type=str)
@click.argument('keyfile', type=click.File('rb'), required=False)
@click.argument('textfile', type=click.File('rb'), required=False)
def run(algo, keyfile=None, textfile=None):
    A = eval(algo)
    keybytes = getkeybytes(algo)
    if keyfile is not None:
      key = keyfile.read()
    else:
      key = os.urandom(keybytes)
    
    if textfile is not None:
      text = textfile.read()
    else:
      text = 64 * "0"
    
    IV = A.block_size * '\x00'
    if algo == "ARC4":
      cipher = A.new(str(key))
    else:
      cipher = A.new(str(key), A.MODE_CBC, IV=IV)
    cipher.encrypt(text)

@cli.command('version')
def version():
    print("Python: " + sys.version)
    print("Crypto: " + Crypto.__version__)

if __name__ == "__main__":
    cli()

