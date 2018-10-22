#!/bin/bash

set -x

# Get source files
DIR=$(eval "echo glibc-*")
if ! [[ -d $DIR ]]; then
	apt-get source libc-dev-bin
fi

# Check source files
DIR=$(eval "echo glibc-*")
if ! [[ -d $DIR ]]; then
	echo "Unknown error"
	exit 1
fi

# Compile libc
LIBCSO=$(realpath ${DIR}/build-tree/amd64-libc/libc.so)
if ! [[ -e "${LIBCSO}" ]]; then
	pushd $DIR
	dpkg-buildpackage
	popd
fi

# Check compilation output
LIBCSO=$(realpath ${DIR}/build-tree/amd64-libc/libc.so)
if ! [[ -e "${LIBCSO}" ]]; then
	echo "Unknown error"
	exit 1
fi

# Create symlink
rm -f ../libc.so
ln -s "${LIBCSO}" ../
