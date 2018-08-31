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
# @package analysis.kuipertest_setup
# @file kuipertest_setup.py
# @brief Script to compile kuipertest.c for a specific machine.
# @author Samuel Weiser <samuel.weiser@iaik.tugraz.at>
# @author Andreas Zankl <andreas.zankl@aisec.fraunhofer.de>
# @license This project is released under the GNU GPLv3 License.
# @version 0.1

"""
*************************************************************************
"""

from distutils.core import setup, Extension
import numpy

"""
*************************************************************************
python kuipertest_setup.py build
python kuipertest_setup.py install
*************************************************************************
"""

kuipertest = Extension('kuipertest',
                       sources=['kuipertest.c'],
                       include_dirs=[numpy.get_include()])

setup (name = 'kuipertest',
       version = '0.1',
       description = 'Calculate Kuiper test statistic.',
       ext_modules = [kuipertest])

