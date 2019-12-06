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

EC_KEY* brainpoolP192r1_load_key_from_file(const char* in_key);

/*
    This file calculates the nonce from a given signature (+ private key + input message).
    It prints the nonce (k) as well as k+q and k+2*q to stdout.

    G ...  curve base point
    n ... integer order of G
    m = left most bits of Hash(message)
    x = private key integer
    curve point (x1,y1) = k * G
    r = x1 mod n
    s = k^-1 (m + r*x) mod n

    k = s^-1 (m + r*x) mod n

*/

extern "C" {
void printResults(const BIGNUM *k, const BIGNUM *kq, const BIGNUM *kqq, const BIGNUM *kinv);
void printDebug(const BIGNUM *a, char const *name);

int calculateNonce(
    BN_CTX *ctx, 
    const BIGNUM *m, const BIGNUM *r, const BIGNUM *s, const BIGNUM *x, const BIGNUM *q,
    BIGNUM **w, BIGNUM **xr, BIGNUM **mxr,
    BIGNUM **k, BIGNUM **kq, BIGNUM **kqq, BIGNUM **kinv
);
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Error: Invalid argument count. Expecting: Private key (PEM), Signature, Message\n");
    }

    char *filename_key_private = argv[1];
    char *filename_signature   = argv[2];
    char *filename_message     = argv[3];
    FILE *file_key_private     = fopen(filename_key_private, "rb");
    int file_key_signature     = open(filename_signature,    O_RDONLY);
    int file_key_message       = open(filename_message,      O_RDONLY);
    struct stat st_sig;
    struct stat st_msg;

    // Map message file
    stat((const char*)filename_message, &st_msg);
    unsigned char *msgbuf = (unsigned char*)mmap(NULL, st_msg.st_size + 4096, PROT_READ, MAP_PRIVATE, file_key_message, 0);
    if (msgbuf == MAP_FAILED) {
        fprintf(stderr, "Error loading message file %s\n", filename_message);
        return 1;
    }
    // Read message file
    BIGNUM* m   = BN_new();
    BN_bin2bn(msgbuf, st_msg.st_size, m);
    //BN_zero(m);

    // Map signature file
    stat((const char*)filename_signature, &st_sig);
    unsigned char *sigbuf = (unsigned char*)mmap(NULL, st_sig.st_size, PROT_READ, MAP_PRIVATE, file_key_signature, 0);
    if (sigbuf == MAP_FAILED) {
        fprintf(stderr, "Error loading signature file %s\n", filename_signature);
        return 1;
    }

    //Read signature file
    ECDSA_SIG* sig = NULL;
    if (!d2i_ECDSA_SIG(&sig, (const unsigned char**)&sigbuf, st_sig.st_size) || !sig) {
        fprintf(stderr, "Error loading signature: %s\n", filename_signature);
        return 1;
    }
    const BIGNUM* r = NULL;
    const BIGNUM* s = NULL;
    ECDSA_SIG_get0(sig, &r, &s);

    // Read private key
    EC_KEY *ecdsa_pkey = brainpoolP192r1_load_key_from_file(filename_key_private);
    if (ecdsa_pkey == NULL) {
      fprintf(stderr, "brainpoolP192r1_load_key_from_file failed.\n");
      return 1;
    }

    const BIGNUM   *x         = EC_KEY_get0_private_key(ecdsa_pkey);
    const EC_GROUP *curve     = EC_KEY_get0_group(ecdsa_pkey);
    const BIGNUM   *q         = EC_GROUP_get0_order(curve);

    int res = 0;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *k, *kq, *kqq, *kinv, *w, *xr, *mxr;
    res = calculateNonce(ctx, m, r, s, x, q, &w, &xr, &mxr, &k, &kq, &kqq, &kinv);
    if(res) { fprintf(stderr, "Error during calculateNonce\n"); return 1; }

    // Sanity check:
    // (x1,y1)=k * G
    // r = x1 mod n
    // if calculated r is the same as from signature,
    // then our calculated nonce k is probably correct

    EC_POINT *x1y1 = EC_POINT_new(curve);
    // x1y1 = generator * n + q * m
    res = EC_POINT_mul(curve, x1y1, k, NULL, NULL, ctx);
    if(res != 1) { fprintf(stderr, "Error while calculating x1y1 = k * G\n"); return 1; }

    BIGNUM *x1 = BN_new();
    BIGNUM *y1 = BN_new();
    res = EC_POINT_get_affine_coordinates_GFp(curve, x1y1, x1, y1, NULL);
    if(res != 1) { fprintf(stderr, "Error while getting x1,y1 from x1y1\n"); return 1; }
    //BIGNUM *x1n = BN_new();
    //res = BN_add(x1n, x1, n);
    //if(res != 1) { fprintf(stderr, "Error while calculating x1n = k1 mod n\n"); return 1; }

    res = BN_cmp(x1, r);
    if(res != 0) {
        fprintf(stderr, "Error x1 != r\n");

        printDebug(m,     "m");
        printDebug(q,     "q");
        printDebug(x,     "x");
        printDebug(r,     "r");
        printDebug(s,     "s");
        printDebug(NULL,  NULL);
        printDebug(w,     "s^-1 = w");
        printDebug(xr,    "x*r");
        printDebug(mxr,   "m+x*r");
        printDebug(NULL,  NULL);
        printDebug(k,     "k");
        printDebug(kq,    "k+q");
        printDebug(kqq,   "k+2q");
        printDebug(kinv,  "kinv");
        printDebug(NULL,  NULL);
        printDebug(x1,    "x1");
        printDebug(y1,    "y1");

        return 1;
    }

    //print nonce to stdout
    printResults(k, kq, kqq, kinv);

    return 0;
}
