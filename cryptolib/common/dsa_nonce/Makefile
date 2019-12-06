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

OPENSSLDIR=../openssl/
CFLAGS=-I$(OPENSSLDIR)/include/
LIBRARY=-Wl,-rpath,$(OPENSSLDIR) $(OPENSSLDIR)/libcrypto.so
#LIBRARY=-L$(OPENSSLDIR) -lcrypto

#------------------------------------------------------------------------
# Targets
#------------------------------------------------------------------------
.PHONY: fetch clean

all: dsa_nonce ecdsa_nonce

# Generic build rule
%.o: %.c
	$(CC) -c $(CFLAGS) $^ -o $@

# Build shared nonce extractors
dsa_nonce: dsa_nonce.o common.o
	$(CC) $(CFLAGS) $^ $(LIBRARY) -o $@

ecdsa_nonce: ecdsa_nonce.o common.o
	$(CC) $(CFLAGS) $^ $(LIBRARY) -o $@

clean:
	rm -f *.o dsa_nonce ecdsa_nonce

help:
	@echo
	@echo "$(PROJ)"
	@echo
	@echo "  make [all] ............. Prepare and/or compile."
	@echo "  make help .............. Show this text."
	@echo "  make clean ............. Clean up."
	@echo
