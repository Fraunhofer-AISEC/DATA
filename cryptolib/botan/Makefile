all: fetch configure build

fetch:
	git submodule update --init --recursive

configure:
	cd botan &&                                                                     \
	./configure.py --prefix=./build --cc=gcc --cc-bin=g++-11 --cc-abi=-fno-plt      \
    --disable-modules tls,locking_allocator --disable-sse2 --disable-ssse3              \
    --disable-sse4.1 --disable-sse4.2 --disable-avx2 --disable-bmi2 --disable-rdrand    \
    --disable-rdseed --disable-aes-ni --disable-sha-ni --disable-altivec                \
    --disable-neon --disable-armv8crypto --disable-powercrypto                          \
    --without-os-feature=threads --with-debug-info --build-targets=static,cli

build:
	$(MAKE) -C botan botan
	$(MAKE) -C algo_dilithium
	$(MAKE) -C algo_kyber
	$(MAKE) -C algo_xmss

clean:
	make -C botan clean
