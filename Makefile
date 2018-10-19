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
-include config.mk

# Project Name
PROJ := DATA - Differential Address Trace Analysis

# Target shell must be bash!
SHELL := /bin/bash

#------------------------------------------------------------------------
# User-configurable settings
#------------------------------------------------------------------------

# Enable parallelism (on by default)
PARALLEL ?= -p

# Enable trace re-use (on by default)
TREUSE ?= -u

# Target framework
FRAMEWORK ?= openssl

# Target script
SCRIPT ?= symmetric.sh

# Target algorithm
ALGO ?= des-ecb

# Target keysize. Some targets do not need to specify keysizes.
KS ?= 64

#------------------------------------------------------------------------
# End of user-configurable settings
#------------------------------------------------------------------------

#------------------------------------------------------------------------
# Targets
#------------------------------------------------------------------------
.PHONY: all run setup phase1 phase2 phase3 clean mrproper

setup: .setup
	@$(MAKE) -s -C pin
	@$(MAKE) -s -C pintool
	@$(MAKE) -s -C cryptolib/common
	@$(MAKE) -s -C analysis

.setup:
	echo "DATA_ROOT=$(PWD)" > config.mk
	echo "RESULTDIR=$(PWD)/results" >> config.mk
	git submodule init
	git submodule update --remote
	touch .setup

all: setup
run: phase1 phase2 phase3

phase1: setup
	@source analysis/.pyenv/bin/activate ;\
	cd cryptolib/$(FRAMEWORK) ;\
	./$(SCRIPT) -g -d -ad $(PARALLEL) $(ALGO) $(KS)
	@echo "Results generated: cryptolib/$(FRAMEWORK)/lastresults/$(FRAMEWORK)/$(ALGO)/result_phase1.xml"

phase2: setup
	@source analysis/.pyenv/bin/activate ;\
	cd cryptolib/$(FRAMEWORK) ;\
	./$(SCRIPT) -ns -an $(PARALLEL) $(ALGO) $(KS)
	@echo "Results generated: cryptolib/$(FRAMEWORK)/lastresults/$(FRAMEWORK)/$(ALGO)/result_phase2.xml"

phase3: setup
	@source analysis/.pyenv/bin/activate ;\
	cd cryptolib/$(FRAMEWORK) ;\
	./$(SCRIPT) -sp -as -i $(PARALLEL) $(TREUSE) $(ALGO) $(KS)
	@echo "Results generated: cryptolib/$(FRAMEWORK)/lastresults/$(FRAMEWORK)/$(ALGO)/result_final.xml"

export: setup
	@source analysis/.pyenv/bin/activate ;\
	cd cryptolib/$(FRAMEWORK) ;\
	./$(SCRIPT) -e $(ALGO) $(KS)
	@echo "Export generated: cryptolib/$(FRAMEWORK)/lastresults/$(FRAMEWORK)/$(ALGO)/framework.zip"

gui:	export
	@source analysis/.pyenv/bin/activate ;\
	datagui cryptolib/$(FRAMEWORK)/lastresults/$(FRAMEWORK)/$(ALGO)/result_phase1.pickle cryptolib/$(FRAMEWORK)/lastresults/$(FRAMEWORK)/$(ALGO)/framework.zip &

clean:
	$(MAKE) clean -C pintool
	$(MAKE) clean -C cryptolib/common

mrproper: clean
	$(MAKE) clean -C cryptolib/openssl
	$(MAKE) clean -C cryptolib/python
	$(MAKE) clean -C pin
	$(MAKE) clean -C analysis
	rm -f config.mk
	rm -f .setup

help:
	@echo
	@echo "$(PROJ)"
	@echo
	@echo "  make [setup] ........... Prepare the framework."
	@echo "  make run ............... Execute full example run."
	@echo "  make all ............... Prepare framework and execute full run."
	@echo "  make phase1 ............ Execute only phase 1 of the example run."
	@echo "  make phase2 ............ Execute only phase 2 of the example run."
	@echo "  make phase3 ............ Execute only phase 3 of the example run."
	@echo "  make gui ............... Open analysis result in GUI."
	@echo "  make help .............. Show this text."
	@echo "  make clean ............. Clean up lightweight."
	@echo "  make mrproper .......... Clean up everything."
	@echo

