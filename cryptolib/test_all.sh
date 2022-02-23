#!/bin/bash

set -e

PINFLAGS="--full --export --parallel"
export RESULTDIR=${PWD}/test_results

cd template
./framework.sh ${PINFLAGS} TEST 128
cd ..

########################################################################
cd openssl
########################################################################
# # Test Default OpenSSL
# ./symmetric.sh ${PINFLAGS} aes-128-ecb 128 # bf-ecb 128 camellia-128-ecb 128 cast5-ecb 128 des-ecb 64 des3 192
# ./asymmetric.sh ${PINFLAGS} rsa dsa 160 ec secp112r1 ec secp256k1 ec secp384r1 ec secp521r1 ec prime256v1 ec sect571r1 ec brainpoolP512t1

# ./asymmetric.sh ${PINFLAGS} ec secp112r1 # ec secp256k1 ec secp384r1 ec secp521r1 ec prime256v1 ec sect571r1 ec brainpoolP512t1

# # Test 32-bit OpenSSL. This requires `sudo apt-get install gcc-multilib`
# SETARCH="i386" ./asymmetric.sh ${PINFLAGS} rsa dsa 160 ec secp256k1
# # Test noasm OpenSSL (slow)
# FLAGS="no-asm" ./asymmetric.sh ${PINFLAGS} rsa dsa 160 ec secp256k1
# # Test OpenSSL secp521r1 optimized implementation
# FLAGS="enable-ec_nistp_64_gcc_128" ./asymmetric.sh ${PINFLAGS} ec_nonce secp521r1
# # Test other OpenSSL algorithms
# ./other.sh ${PINFLAGS} edwards 448 edwards 25519 ecmul secp256k1 ecmul secp521r1
cd ..

# ########################################################################
# cd boringssl
# ########################################################################
# # Test Default BoringSSL
# ./asymmetric.sh ${PINFLAGS} dsa 256 ec P-224 ec P-256 ec P-384 ec P-521 ec brainpoolP192r1
# # Test nonce
# ./asymmetric.sh ${PINFLAGS} dsa_nonce 256 ec_nonce P-256
# cd ..
# 
# ########################################################################
# cd libressl
# ########################################################################
# # Test Default LibreSSL
# ./asymmetric.sh ${DATAFLAGS} ec_nonce sect131r1
# cd ..

