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
# @version 0.2
#########################################################################

#------------------------------------------------------------------------
# Settings
#------------------------------------------------------------------------
include ../config.mk

# Project Name
PROJ := DATA - Pintool

# Pintool Name
TEST_TOOL_ROOTS := addrtrace

# Pin Root
ifneq ($(MAKECMDGOALS),help)
  ifndef PIN_ROOT
    $(error PIN_ROOT is undefined!)
  endif
  CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
  include $(CONFIG_ROOT)/makefile.config
  include $(TOOLS_ROOT)/Config/makefile.default.rules
endif

#------------------------------------------------------------------------
# Targets
#------------------------------------------------------------------------
.PHONY: all clean clearfiles

all: $(TEST_TOOL_ROOTS).so

$(TEST_TOOL_ROOTS).so: obj-intel64/$(TEST_TOOL_ROOTS).so
	rm -f $@
	ln -s $^ $(TEST_TOOL_ROOTS).so

clean: clearfiles

clearfiles:
	rm -f $(TEST_TOOL_ROOTS).so

help:
	@echo
	@echo "$(PROJ)"
	@echo
	@echo "  make [all] ............. Prepare and/or compile."
	@echo "  make help .............. Show this text."
	@echo "  make clean ............. Clean up."
	@echo

