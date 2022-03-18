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
PROJ := DATA - Pintool

# Pintool Name
TEST_TOOL_ROOTS := addrtrace

#------------------------------------------------------------------------
# Targets
#------------------------------------------------------------------------
.PHONY: all clean clean2 i386 x86_64 32 64

all: x86_64 64 #i386 x86_64 32 64

# Pin Root
ifneq ($(MAKECMDGOALS),help)
ifneq ($(MAKECMDGOALS),clean)
  ifndef PIN_ROOT
    $(error PIN_ROOT is undefined!)
  endif
  CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
  include $(CONFIG_ROOT)/makefile.config
  include $(TOOLS_ROOT)/Config/makefile.default.rules
endif
endif

32:
	make TARGET=ia32 obj-ia32/$(TEST_TOOL_ROOTS).so

64: obj-intel64/$(TEST_TOOL_ROOTS).so

i386:
	ln -sf obj-ia32 $@

x86_64:
	ln -sf obj-intel64 $@

# Submakefile already defines 'clean' target
# To avoid re-defining clean, we make our own
# clean2 target
clean: clean2

clean2: clean
	rm -f  i386 x86_64
	rm -rf obj-ia32
	rm -rf obj-intel64

help:
	@echo
	@echo "$(PROJ)"
	@echo
	@echo "  make [all] ............. Prepare and/or compile."
	@echo "  make help .............. Show this text."
	@echo "  make clean ............. Clean up."
	@echo
