#########################################################################
# Copyright (C) 2017-2018 IAIK TU Graz and Fraunhofer AISEC
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#########################################################################
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3
#########################################################################

#------------------------------------------------------------------------
# Settings
#------------------------------------------------------------------------

# Project Name
PROJ := DATA - Pin

# Pin Version and Source

VER_STRING=pin-3.11-97998-g7ecce2dac-gcc-linux

TAR=$(VER_STRING).tar.gz
URL=https://software.intel.com/sites/landingpage/pintool/downloads/$(TAR)

#------------------------------------------------------------------------
# Targets
#------------------------------------------------------------------------
.PHONY: all clean

all: $(TAR) source.sh

$(TAR):
	wget $(URL)

$(VER_STRING)/pin:
	tar -xvf $(TAR)

source.sh: $(VER_STRING)/pin
	echo "export PIN_ROOT=$(CURDIR)/$(VER_STRING)" > $@
	echo "export PIN_VER_STRING=$(VER_STRING)" >> $@

clean:
	rm -f pin
	rm -f $(TAR)
	rm -f source.sh
	rm -rf $(VER_STRING)*

help:
	@echo
	@echo "$(PROJ)"
	@echo
	@echo "  make [all] ............. Prepare and/or compile."
	@echo "  make help .............. Show this text."
	@echo "  make clean ............. Clean up."
	@echo
