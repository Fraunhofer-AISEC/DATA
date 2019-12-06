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
PROJ := DATA - Cryptolib BoringSSL

ifndef BUILDDIR
$(error BUILDDIR is not set. Source config.sh first!)
endif

SRC = ecdsatest.cc dsatest.cc
#LDFLAGS = -lunwind-generic -lunwind -lpthread
LDFLAGS = -lpthread

#------------------------------------------------------------------------
# Targets
#------------------------------------------------------------------------
.PHONY: all fetch clean dsawrapper

all: fetch dsawrapper

fetch:
	./fetch_boringssl.sh

dsawrapper: $(BUILDDIR)/dsawrapper fetch

$(BUILDDIR)/dsawrapper:
	c++ -std=c++11 -g -Iboringssl/include/ $(SRC) -o $@ $(BUILDDIR)/crypto/libcrypto.a $(LDFLAGS)

# TODO: adapt
# Copied from common/dsa_nonce

#~ CXXFLAGS=-std=c++11 -I../../boringssl/boringssl/include/
#~ BSSLLIB=../../boringssl/boringssl/build/crypto/libcrypto.a \
#~ 				-lunwind-generic -lunwind -lpthread

#~ %.o: %.cc
#~ 	$(CXX) -c $(CXXFLAGS) $^ -o $@

#~ bssl_brainpool_nonce: bssl_brainpool_nonce.o common.o ../../boringssl/ecdsatest.o
#~ 		$(CXX) $(CXXFLAGS) $^ -o $@ $(BSSLLIB)


clean:
	rm -rf $(BUILDDIR)

mrproper:
	rm -rf boringssl/ go/

help:
	@echo
	@echo "$(PROJ)"
	@echo
	@echo "  make [all] ............. Prepare and/or compile."
	@echo "  make help .............. Show this text."
	@echo "  make clean ............. Clean up build files."
	@echo "  make mrproper........... Delete any generated files."
	@echo
