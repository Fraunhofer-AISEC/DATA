#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/dsa.h>
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

/*
    This file calculates the nonce from a given signature (+ private key + input message).
    It prints the nonce (k) as well as k+q and k+2*q to stdout.

    Compatible with OpenSSL, LibreSSL.
    r = g^k mod q
    s = k^-1 (m + x * r) mod p
    k = s^-1 (m + x * r) mod p
    Signature = (r,s)
    Nonce = k
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
    int dlen = st_msg.st_size;

    // Map signature file
    stat((const char*)filename_signature, &st_sig);
    unsigned char *sigbuf = (unsigned char*)mmap(NULL, st_sig.st_size, PROT_READ, MAP_PRIVATE, file_key_signature, 0);
    if (sigbuf == MAP_FAILED) {
        fprintf(stderr, "Error loading signature file %s\n", filename_signature);
        return 1;
    }

    //Read signature file
    DSA_SIG* sig = NULL;
    if (!d2i_DSA_SIG(&sig, (const unsigned char**)&sigbuf, st_sig.st_size) || !sig) {
        fprintf(stderr, "Error loading signature: %s\n", filename_signature);
        return 1;
    }
    const BIGNUM* r = NULL;
    const BIGNUM* s = NULL;
    DSA_SIG_get0(sig, &r, &s);

    // Read private key
    DSA *dsa_pkey = NULL;
    if(!PEM_read_DSAPrivateKey(file_key_private, &dsa_pkey, NULL, NULL) || !dsa_pkey) {
        fprintf(stderr, "Error loading key %s\n", filename_key_private);
        return 1;
    }
    const BIGNUM* x   = DSA_get0_priv_key(dsa_pkey);
    const BIGNUM* p   = DSA_get0_p(dsa_pkey);
    const BIGNUM* q   = DSA_get0_q(dsa_pkey);
    const BIGNUM* g   = DSA_get0_g(dsa_pkey);

    if (dlen > BN_num_bytes(q)) {
        /*
         * if the digest length is greater than the size of q use the
         * BN_num_bits(dsa->q) leftmost bits of the digest, see fips 186-3,
         * 4.2
         */
        dlen = BN_num_bytes(q);
    }
    if (BN_bin2bn(msgbuf, dlen, m) == NULL) {
        return 1;
    }

    int res = 0;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *k, *kq, *kqq, *kinv, *w, *xr, *mxr;
    res = calculateNonce(ctx, m, r, s, x, q, &w, &xr, &mxr, &k, &kq, &kqq, &kinv);
    if(res) { fprintf(stderr, "Error during calculateNonce\n"); return 1; }

    // Sanity check: r = g^k mod p mod q
    BIGNUM* r_new = BN_new();
    res = BN_mod_exp(r_new, g, k, p,  ctx);
    if(res != 1) { fprintf(stderr, "Error while calculating r_new = g^k mod p\n"); return 1; }
    res = BN_mod(r_new, r_new, q,  ctx);
    if(res != 1) { fprintf(stderr, "Error while calculating r_new = (g^k mod p) mod q\n"); return 1; }

    res = BN_cmp(r_new, r);
    if(res != 0) {
        fprintf(stderr, "Error r_new != r\n");

        printDebug(m,     "m");
        printDebug(q,     "q");
        printDebug(x,     "x");
        printDebug(r,     "r");
        printDebug(s,     "s");
        printDebug(p,     "p");
        printDebug(g,     "g");
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
        printDebug(r,     "r");
        printDebug(r_new, "r_new ");

        return 1;
    }

    //print nonce to stdout
    printResults(k, kq, kqq, kinv);

    return 0;
}
