#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/asn1t.h>
#include "openssl/sha.h"
#include <sys/mman.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>

#include <openssl/rand.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Error: Invalid argument count. Expecting: <Private key (PEM)>\n");
        return 1;
    }

    char *filename_key_private = argv[1];
    FILE *file_key_private     = fopen(filename_key_private, "rb");

    // Read private key
    EVP_PKEY *pkey = NULL;
    EC_KEY *ecdsa_pkey = NULL;
    PEM_read_PrivateKey(file_key_private, &pkey, NULL, NULL );
    if (pkey == NULL) {
      fprintf(stderr, "Error loading key %s\n", filename_key_private);
      return 1;
    }
    ecdsa_pkey = EVP_PKEY_get1_EC_KEY(pkey);
    EVP_PKEY_free(pkey);

    const BIGNUM   *x         = EC_KEY_get0_private_key(ecdsa_pkey);
    const EC_GROUP *curve     = EC_KEY_get0_group(ecdsa_pkey);
    const BIGNUM   *q         = EC_GROUP_get0_order(curve);
    const EC_POINT *gen       = EC_GROUP_get0_generator(curve);
    BN_CTX *ctx = BN_CTX_new();

    //EC_POINT_mul calculates the value generator * n + q * m and stores the result in r
    //The value n may be NULL in which case the result is just q * m (variable point multiplication)
    EC_POINT *r = EC_POINT_new(curve);
    BIGNUM *tmp = BN_new();
    int res = 0;

    res = BN_rand_range(tmp, q);
    if(res != 1) {
        fprintf(stderr, "Error during BN_rand\n");
        return 1;
    }
    BN_set_flags(tmp, BN_FLG_CONSTTIME);
    res = BN_num_bits(tmp);

    //Arbitrary point mult
    res = EC_POINT_mul(curve, r, NULL, gen, tmp, ctx); // r = tmp * generator
    if(res != 1) { fprintf(stderr, "Error during EC_POINT_mul\n"); return 1; }

    //Base point mult
    res = EC_POINT_mul(curve, r, tmp, NULL, NULL, ctx); // r = tmp * generator
    if(res != 1) { fprintf(stderr, "Error during EC_POINT_mul\n"); return 1; }

    return 0;
}
