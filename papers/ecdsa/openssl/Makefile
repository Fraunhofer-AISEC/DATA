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
PROJ := DATA - Cryptolib OpenSSL

ifndef BUILDDIR
$(error BUILDDIR is not set. Source config.sh first!)
endif

OPENSSLDIR=$(BUILDDIR)/openssl
CFLAGS=-I$(OPENSSLDIR)/include/
ifeq ($(SETARCH),i386)
CFLAGS+=-m32
endif
LIBRARY=-Wl,-rpath,$(OPENSSLDIR) $(OPENSSLDIR)/libcrypto.so
#LIBRARY=-L$(OPENSSLDIR) -lcrypto

#------------------------------------------------------------------------
# Targets
#------------------------------------------------------------------------
.PHONY: all fetch clean edwards ecmul

all: fetch edwards ecmul

edwards: $(BUILDDIR)/edwards

$(BUILDDIR)/edwards: edwards.c | fetch
	$(CC) $(CFLAGS) $^ $(LIBRARY) -o $@

ecmul: $(BUILDDIR)/ecmul

$(BUILDDIR)/ecmul: ecmul.c | fetch
	$(CC) $(CFLAGS) $^ $(LIBRARY) -o $@

fetch:
	./fetch_openssl.sh

clean:
	rm -rf $(BUILDDIR)/edwards
	rm -rf $(BUILDDIR)/ecmul

help:
	@echo
	@echo "$(PROJ)"
	@echo
	@echo "  make [all] ............. Prepare and/or compile."
	@echo "  make help .............. Show this text."
	@echo "  make clean ............. Clean up."
	@echo
