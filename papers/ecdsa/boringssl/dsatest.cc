/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 *
 * The DSS routines are based on patches supplied by
 * Steven Schoch <schoch@sheba.arc.nasa.gov>. */

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/ec.h>
#include <openssl/dsa.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "boringssl/crypto/internal.h"

int brainpoolP192r1_generate_and_store_key(const char* out_key);
EC_KEY* brainpoolP192r1_load_key_from_file(const char* in_key);
EC_GROUP* get_brainpool_192r1(BN_CTX* ctx);
int print_key(EC_GROUP* group, EC_KEY* key, BN_CTX* ctx);

const uint8_t digest_hardcoded[] = { 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00 };

static int Run(int argc, const char* argv[]) {
  int counter, i, j;
  uint8_t buf[256];
  unsigned long h;
  uint8_t sig[256];
  unsigned int siglen;

  if(argc == 6 && strcmp(argv[1], "genpkey") == 0) {
    const char* algorithm = argv[2];
    const char* pkeyopt   = argv[3];
    const char* out_param = argv[4];
    const char* out_key   = argv[5];
    //dsa_paramgen_q_bits:256
    if(strcmp(algorithm, "dsa") == 0) {
      if(strcmp(pkeyopt, "dsa_paramgen_q_bits:256") != 0) {
        fprintf(stderr, "pkeyopt must be dsa_paramgen_q_bits:256\n");
        return false;
      }
      bssl::UniquePtr<DSA> dsa(DSA_new());
      if (!dsa ||
          !DSA_generate_parameters_ex(dsa.get(), 1024, NULL, 0, &counter, &h,
                                      NULL)) {
        fprintf(stderr, "DSA_generate_parameters_ex failed\n");
        return false;
      }

      if (!DSA_generate_key(dsa.get())) {
        fprintf(stderr, "DSA_generate_key failed\n");
        return false;
      }

      FILE* fp_out_param = fopen(out_param, "wb");
      if(!PEM_write_DSAparams(fp_out_param, dsa.get())){
        fprintf(stderr, "PEM_write_DSAparams failed\n");
        return false;
      }

      FILE* fp_out_key = fopen(out_key, "wb");
      if(!PEM_write_DSAPrivateKey(fp_out_key, dsa.get(), NULL, NULL, 0, NULL, NULL)){
        fprintf(stderr, "PEM_write_DSAPrivateKey failed\n");
        return false;
      }


    }else if(strcmp(algorithm, "ec") == 0) {
      char *pkeyopt_prefix = (char*)"ec_paramgen_curve:";
      if(strncmp(pkeyopt, pkeyopt_prefix, strlen(pkeyopt_prefix)) != 0) {
        fprintf(stderr, "pkeyopt must start with '%s'\n", pkeyopt_prefix);
        return false;
      }
      char *curve_name = (char*)pkeyopt + strlen(pkeyopt_prefix);
      if(strcmp(curve_name, "brainpoolP192r1") != 0) {
        fprintf(stderr, "curve must be brainpoolP192r1\n");
        return false;
      }
      return brainpoolP192r1_generate_and_store_key(out_key);
/*
      int nid = nid = EC_curve_nist2nid(curve_name);
      if (nid == NID_undef)
          nid = OBJ_sn2nid(curve_name);
      if (nid == NID_undef){
          nid = OBJ_ln2nid(curve_name);
      if (nid == NID_undef){
        fprintf(stderr, "Failed to get NID for curve_name = '%s'\n", curve_name);
        return false;
      }
      fprintf(stderr, "curve_name = '%s, nid = %d'\n", curve_name, nid);

      EC_KEY *ec_key = EC_KEY_new_by_curve_name(nid);
      if (!ec_key){
        fprintf(stderr, "EC_KEY_new_by_curve_name failed\n");
        return false;
      }
*/

    }else{
      fprintf(stderr, "unknown algorithm\n");
      return false;
    }
  }else if(argc == 5 && strcmp(argv[1], "sign") == 0) {
    const char* in_msg = argv[2];
    const char* in_key = argv[3];
    const char* out    = argv[4];

    // Read private key
    EVP_PKEY *pkey = NULL;
    FILE *file_key_private = fopen(in_key,  "rb");
    EC_KEY *ecdsa_pkey = NULL;
    DSA *dsa           = NULL;
    PEM_read_PrivateKey(file_key_private, &pkey, NULL, NULL );
    if (!pkey) {
      //Try loading brainpoolP192r1 key if PEM loading failed
      ecdsa_pkey = brainpoolP192r1_load_key_from_file(in_key);
      if (!ecdsa_pkey){
        fprintf(stderr, "Error loading key %s\n", in_key);
        return 1;
      }
    }else{
      ecdsa_pkey = EVP_PKEY_get1_EC_KEY(pkey);
      dsa        = EVP_PKEY_get1_DSA(pkey);
    }

    if(!ecdsa_pkey && !dsa) {
      fprintf(stderr, "Failed to get key\n");
      return false;
    }

    //Read message file
    int file_msg       = open(in_msg,      O_RDONLY);
    struct stat st_msg;
    stat((const char*)in_msg,     &st_msg);
    const char *msgbuf = (const char*)mmap(NULL, st_msg.st_size + 4096, PROT_READ, MAP_PRIVATE, file_msg, 0);
    if (msgbuf == MAP_FAILED) {
        fprintf(stderr, "Error loading message file %s\n", in_msg);
        return 1;
    }

    uint8_t *digest  = (uint8_t*)msgbuf;
    size_t digestlen = st_msg.st_size;
    //uint8_t *digest = (uint8_t*)digest_hardcoded;
    //size_t digestlen = sizeof(digest_hardcoded);

    //Create signature
    uint8_t* sig = NULL;
    unsigned int sig_len;
    if(dsa){
      sig = (uint8_t*)malloc(DSA_size(dsa));
      if(!DSA_sign(0, digest, digestlen, sig, &sig_len, dsa) || sig_len > DSA_size(dsa)) {
        fprintf(stderr, "DSA_do_sign failed\n");
        return false;
      }
      //if (!DSA_verify(0, digest, digestlen, sig, sig_len, dsa)) {
      //  fprintf(stderr, "DSA_verify failed\n");
      //  return false;
      //}
    }else{
      sig = (uint8_t*)malloc(ECDSA_size(ecdsa_pkey));
      if(!ECDSA_sign(0, digest, digestlen, sig, &sig_len, ecdsa_pkey) || sig_len > ECDSA_size(ecdsa_pkey)) {
        fprintf(stderr, "ECDSA_sign failed\n");
        return false;
      }
      //if (!ECDSA_verify(0, digest, digestlen, sig, sig_len, ecdsa_pkey)) {
      //  fprintf(stderr, "ECDSA_verify failed\n");
      //  return false;
      //}
    }

    /* Write signature file */
    FILE *out_file = fopen(out, "wb");
    fwrite(sig, sig_len, 1, out_file);
    fclose(out_file);


  }else{
    fprintf(stderr, "Usage: %s genpkey dsa dsa_paramgen_q_bits:256 <out-param> <out-key>\n", argv[0]);
    fprintf(stderr, "Usage: %s genpkey ec ec_paramgen_curve:brainpoolP192r1 <out-param> <out-key>\n", argv[0]);
    fprintf(stderr, "Usage: %s sign <in_digest> <in-key> <out-sig>\n", argv[0]);
    return false;
  }

  return true;
}

int main(int argc, const char* argv[]) {
  if (!Run(argc, argv)) {
    fprintf(stderr, "error\n");
    return 1;
  }
  return 0;
}
