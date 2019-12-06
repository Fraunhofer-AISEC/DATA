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


/*
    This file calculates the nonce from a given signature (+ private key + input message).
    It prints the nonce (k) as well as k+q and k+2*q to stdout.

    Compatible with OpenSSL, LibreSSL.

    G ...  curve base point
    n ... integer order of G
    m = left most bits of Hash(message)
    x = private key integer
    curve point (x1,y1) = k * G
    r = x1 mod n
    s = k^-1 (m + r*x) mod n

    k = s^-1 (m + r*x) mod n

*/

void printResults(const BIGNUM *k, const BIGNUM *kq, const BIGNUM *kqq, const BIGNUM *kinv);
void printDebug(const BIGNUM *a, char *name);
int calculateNonce(
    BN_CTX *ctx, 
    const BIGNUM *m, const BIGNUM *r, const BIGNUM *s, const BIGNUM *x, const BIGNUM *q,
    BIGNUM **w, BIGNUM **xr, BIGNUM **mxr,
    BIGNUM **k, BIGNUM **kq, BIGNUM **kqq, BIGNUM **kinv
);

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Error: Invalid argument count. Expecting: <Private key (PEM)> <Signature>, <Message>, [optional: hashing algorithm]\n");
    }

    char *filename_key_private = argv[1];
    char *filename_signature   = argv[2];
    char *filename_message     = argv[3];
    FILE *file_key_private     = fopen(filename_key_private, "rb");
    int file_signature         = open(filename_signature,    O_RDONLY);
    int file_message           = open(filename_message,      O_RDONLY);
    struct stat st_sig;
    struct stat st_msg;

    // Map message file
    stat((const char*)filename_message, &st_msg);
    unsigned char *msgbuf = (unsigned char*)mmap(NULL, st_msg.st_size + 4096, PROT_READ, MAP_PRIVATE, file_message, 0);
    if (msgbuf == MAP_FAILED) {
        fprintf(stderr, "Error loading message file %s\n", filename_message);
        return 1;
    }
    // Read message file
    BIGNUM* m   = BN_new();
    int dgst_len = st_msg.st_size;

    //Hash message file
    if (argc == 5 && strcmp("sha256",argv[4]) == 0) {
        SHA256_CTX ctx;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, (u_int8_t *)msgbuf, dgst_len);
        SHA256_Final(hash, &ctx);
        // Copy results back
        munmap(msgbuf, st_msg.st_size + 4096);
        dgst_len = SHA256_DIGEST_LENGTH;
        msgbuf = malloc(dgst_len);
        if (!msgbuf) {
            fprintf(stderr, "Out of memory");
            return 1;
        }
        memcpy(msgbuf, hash, dgst_len);
    } else if (argc == 5) {
        fprintf(stderr, "Error: Invalid hashing algorithm \"%s\"\n", argv[4]);
        fprintf(stderr, "Available options: sha256\n");
    }

    // Map signature file
    stat((const char*)filename_signature, &st_sig);
    unsigned char *sigbuf = (unsigned char*)mmap(NULL, st_sig.st_size, PROT_READ, MAP_PRIVATE, file_signature, 0);
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

    int i = BN_num_bits(q);
    /*
     * Need to truncate digest if it is too long: first truncate whole bytes.
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7) / 8;
    if (!BN_bin2bn(msgbuf, dgst_len, m)) {
        return 1;
    }
    /* If still too long, truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7))) {
        return 1;
    }

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

    res = BN_mod(x1, x1, q, ctx);
    if(res != 1) { fprintf(stderr, "Error reducing x1 mod q\n"); return 1; }
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
