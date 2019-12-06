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
# @package analysis.kuipertest.setup
# @file setup.py
# @brief Script to compile kuipertest.c for a specific machine.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3

"""
*************************************************************************
"""

from distutils.core import setup, Extension
import numpy

"""
*************************************************************************
python setup.py build
python setup.py install
*************************************************************************
"""

kuipertest = Extension('kuipertest',
                       sources=['kuipertest.c'],
                       include_dirs=[numpy.get_include()])

setup (name = 'kuipertest',
       version = '0.2',
       license='GPLv3+',
       author='TUGraz IAIK, Fraunhofer AISEC',
       author_email='data@iaik.tugraz.at',
       url='https://github.com/Fraunhofer-AISEC/DATA',
       description = 'Calculate Kuiper test statistic.',
       classifiers=[
         "Programming Language :: Python :: 2",
         "Programming Language :: Python :: 3",
         "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",],
       ext_modules = [kuipertest])

