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
#include <sys/mman.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>

static int hamming_weight(const BIGNUM *a){
    int res = 0;
    for (size_t i = 0; i < BN_num_bits(a); i++) {
        res += BN_is_bit_set(a, i);
    }
    return res;
}

void printResults(const BIGNUM *k, const BIGNUM *kq, const BIGNUM *kqq, const BIGNUM *kinv) {
    //print nonce to stdout
    printf("k\t0x"   );        BN_print_fp(stdout, k   ); printf("\n");
    printf("k+q\t0x" );        BN_print_fp(stdout, kq  ); printf("\n");
    printf("k+2q\t0x");        BN_print_fp(stdout, kqq ); printf("\n");
    printf("kinv\t0x");        BN_print_fp(stdout, kinv); printf("\n");
    printf("bits(k)\t%d\n",    BN_num_bits(k   ));
    printf("bits(k+q)\t%d\n",  BN_num_bits(kq  ));
    printf("bits(k+2q)\t%d\n", BN_num_bits(kqq ));
    printf("bits(kinv)\t%d\n", BN_num_bits(kinv));
    printf("hw(k)\t%d\n",      hamming_weight(k   ));
    printf("hw(k+q)\t%d\n",    hamming_weight(kq  ));
    printf("hw(k+2q)\t%d\n",   hamming_weight(kqq ));
    printf("hw(kinv)\t%d\n",   hamming_weight(kinv));
    printf("bit0(k)\t%d\n",    BN_is_bit_set(k,   0));
    printf("bit0(k+q)\t%d\n",  BN_is_bit_set(kq,  0));
    printf("bit0(k+2q)\t%d\n", BN_is_bit_set(kqq, 0));
    printf("bit1(k)\t%d\n",    BN_is_bit_set(k,   1));
    printf("bit1(k+q)\t%d\n",  BN_is_bit_set(kq,  1));
    printf("bit1(k+2q)\t%d\n", BN_is_bit_set(kqq, 1));
}

void printDebug(const BIGNUM *a, char const *name) {
    if(!a || !name) {
        fprintf(stderr, "\n");
        return;
    }
    fprintf(stderr, "%10s = 0x", name);
    BN_print_fp(stderr, a);
    fprintf(stderr, "\n");
}

int calculateNonce(
    BN_CTX *ctx, 
    //inputs:
    const BIGNUM *m, const BIGNUM *r, const BIGNUM *s, const BIGNUM *x, const BIGNUM *q,
    //intermediate results:
    BIGNUM **w, BIGNUM **xr, BIGNUM **mxr,
    //results:
    BIGNUM **k, BIGNUM **kq, BIGNUM **kqq, BIGNUM **kinv
) {
    int res = 0;
    *w    = BN_new();
    *xr   = BN_new();
    *mxr  = BN_new();
    *k    = BN_new();
    *kq   = BN_new();
    *kqq  = BN_new();
    *kinv = BN_new();

     // w = s^-1
    if ((*w = BN_mod_inverse(NULL, s, q, ctx)) == NULL) {
        fprintf(stderr, "Error while calculating w\n"); return 1;
    }

    res = BN_mod_mul(*xr, x, r, q, ctx);
    if(res != 1) { fprintf(stderr, "Error while calculating x*r\n"); return 1; }

    res = BN_mod_add(*mxr, m, *xr, q, ctx);
    if(res != 1) { fprintf(stderr, "Error while calculating m+(x*r)\n"); return 1; }

    res = BN_mod_mul(*k, *w, *mxr, q, ctx);
    if(res != 1) { fprintf(stderr, "Error while calculating k = (s^-1) * (m+xr)\n"); return 1; }

    res = BN_add(*kq, *k, q);
    if(res != 1) { fprintf(stderr, "Error while calculating k + q\n"); return 1; }

    res = BN_add(*kqq, *kq, q);
    if(res != 1) { fprintf(stderr, "Error while calculating (k + q) + q\n"); return 1; }

    if ((*kinv = BN_mod_inverse(NULL, *k, q, ctx)) == NULL) {
        fprintf(stderr, "Error while calculating kinv\n"); return 1;
    }
    return 0;
}
