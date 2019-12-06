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

# Project Name
PROJ := DATA - Differential Address Trace Analysis
VER := $(shell cat VERSION)

.PHONY: clean mrproper

setup: .gitsetup data.sh
	@$(MAKE) -s -C pin
	@# pintool requires $PIN_ROOT
	@bash -c "source pin/source.sh && $(MAKE) -s -C pintool"
	@$(MAKE) -s -C cryptolib/common
	@$(MAKE) -s -C analysis

.gitsetup:
	git submodule init
	git submodule update --remote
	touch .gitsetup

########################################################################
define DATASH_BODY
# Source this script to enable DATA
if [[ ! -z "$${DATA_ROOT}" ]]; then
  echo "DATA already loaded! Reloading..."
fi

# Installation path
export DATA_ROOT=$(CURDIR)
export DATA_COMMON=$${DATA_ROOT}/cryptolib/common/
export DATA_LEAKAGE_MODELS=$${DATA_ROOT}/analysis/leakage_models/

# Load PIN and python environment
export VIRTUAL_ENV_DISABLE_PROMPT=1
source "$${DATA_ROOT}/pin/source.sh"
source "$${DATA_ROOT}/analysis/.pyenv/bin/activate"

# Check for data + datagui
which datagui && echo "datagui available"

# Set (DATA) in BASH prompt
export PS1="(DATA $(VER)) $$PS1"
endef
export DATASH_BODY
########################################################################

data.sh:
	@echo "$$DATASH_BODY" > $@

install: setup data.sh
	cp data.sh ~/
	@echo "Installation complete. To run data, source ~/data.sh"

clean:
	$(MAKE) clean -C pintool
	$(MAKE) clean -C cryptolib/common

mrproper: clean
	$(MAKE) clean -C cryptolib/openssl
	$(MAKE) clean -C cryptolib/python
	$(MAKE) clean -C pin
	$(MAKE) clean -C analysis
	rm -f config.mk
	rm -f .gitsetup
	rm -f data.sh

help:
	@echo
	@echo "$(PROJ)"
	@echo
	@echo "  make [setup] ........... Prepare the framework."
	@echo "  make install ........... Install data.sh in HOME."
	@echo "  make help .............. Show this text."
	@echo "  make clean ............. Clean up lightweight."
	@echo "  make mrproper .......... Clean up everything."
	@echo
