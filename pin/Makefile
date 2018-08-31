#########################################################################
# Copyright (C) 2017-2018
# Samuel Weiser (IAIK TU Graz) and Andreas Zankl (Fraunhofer AISEC)
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
# @author Samuel Weiser <samuel.weiser@iaik.tugraz.at>
# @author Andreas Zankl <andreas.zankl@aisec.fraunhofer.de>
# @license This project is released under the GNU GPLv3 License.
# @version 0.1
#########################################################################

#------------------------------------------------------------------------
# Settings
#------------------------------------------------------------------------

# Project Name
PROJ := DATA - Pin

# Pin Version and Source
VER=pin-3.7-97619-g0d0c92f4f-gcc-linux
TAR=$(VER).tar.gz
URL=https://software.intel.com/sites/landingpage/pintool/downloads/$(TAR)

# config.mk Handling
REPL=$(shell echo $(CURDIR) | sed 's/\//\\\//g')

#------------------------------------------------------------------------
# Targets
#------------------------------------------------------------------------
.PHONY: all clean

all: $(TAR) pin config.mk

$(TAR):
	wget $(URL)

$(VER)/pin:
	tar -xvf $(TAR)

pin: $(VER)/pin
	ln -sf $^ $@

config.mk:
	@if [ -f ../config.mk ] && grep -q PIN_ROOT ../config.mk; then \
		sed -i 's/PIN_ROOT=.*/PIN_ROOT=$(REPL)\/$(VER)/g' ../config.mk; \
	else \
		echo "PIN_ROOT=$(CURDIR)/$(VER)" >> ../config.mk; \
	fi;

clean:
	rm -f pin
	rm -f $(TAR)
	rm -rf $(VER)

help:
	@echo
	@echo "$(PROJ)"
	@echo
	@echo "  make [all] ............. Prepare and/or compile."
	@echo "  make help .............. Show this text."
	@echo "  make clean ............. Clean up."
	@echo

