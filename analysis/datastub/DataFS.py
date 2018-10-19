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
# @package analysis.datastub.datafs
# @file DataFS.py
# @brief Everything related to control-flow and data leaks.
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.2

"""
*************************************************************************
"""

import os
from fs import zipfs, copy, osfs

"""
*************************************************************************
"""

class DataFS:
    """
    write ... if True, creates a new empty container
              if False, opens existing container as read-only
    """
    def __init__(self, fsname, write):
        # Writable Zip fs
        self.datafs = zipfs.ZipFS(fsname, write)
        self.osfs = None
        self.write = write
        if write:
            self.osfs = osfs.OSFS(u'/')
            self.cwd = os.getcwd()
            with self.create_file(u'/cwd') as f:
                f.write(self.cwd.encode('utf-8'))
        else:
            assert(os.path.exists(fsname))
            with self.datafs.open(u'/cwd', encoding='utf-8') as f:
                self.cwd = f.read()
                if os.path.altsep is not None:
                    self.cwd += os.path.altsep
                else:
                    self.cwd += os.path.sep

    def create_file(self, fname):
        assert(self.write)
        if not os.path.isabs(fname):
            fname = os.path.join(self.cwd, fname)
        fdir = os.path.dirname(fname)
        self.datafs.makedirs(fdir, recreate = True)
        return self.datafs.openbin(fname, 'w+b')

    def add_file(self, fname):
        assert(self.write)
        if not os.path.isabs(fname):
            fname = os.path.join(self.cwd, fname)
        fdir = os.path.dirname(fname)
        self.datafs.makedirs(fdir, recreate = True)
        copy.copy_file(self.osfs, fname, self.datafs, fname)

    def get_binfile(self, fname):
        assert(not self.write)
        if not os.path.isabs(fname):
            fname = os.path.join(self.cwd, fname)
        return self.datafs.openbin(fname)

    def get_file(self, fname, **kwargs):
        assert(not self.write)
        if not os.path.isabs(fname):
            fname = os.path.join(self.cwd, fname)
        return self.datafs.open(fname, **kwargs)

    def close(self):
        self.datafs.close()

