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

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/dsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

//#include "boringssl/crypto/internal.h"

#include <sys/mman.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


static const uint8_t pb[] = {
        /* p */
        0xC3, 0x02, 0xF4, 0x1D, 0x93, 0x2A, 0x36, 0xCD, 0xA7, 0xA3, 0x46, 0x30,
        0x93, 0xD1, 0x8D, 0xB7, 0x8F, 0xCE, 0x47, 0x6D, 0xE1, 0xA8, 0x62, 0x97,
};
static const uint8_t ab[] = {
        /* a */
        0xC3, 0x02, 0xF4, 0x1D, 0x93, 0x2A, 0x36, 0xCD, 0xA7, 0xA3, 0x46, 0x30,
        0x93, 0xD1, 0x8D, 0xB7, 0x8F, 0xCE, 0x47, 0x6D, 0xE1, 0xA8, 0x62, 0x94,
};
static const uint8_t bb[] = {
        /* b */
        0x13, 0xD5, 0x6F, 0xFA, 0xEC, 0x78, 0x68, 0x1E, 0x68, 0xF9, 0xDE, 0xB4,
        0x3B, 0x35, 0xBE, 0xC2, 0xFB, 0x68, 0x54, 0x2E, 0x27, 0x89, 0x7B, 0x79,
};
static const uint8_t xb[] = {
        /* x */
        0x3A, 0xE9, 0xE5, 0x8C, 0x82, 0xF6, 0x3C, 0x30, 0x28, 0x2E, 0x1F, 0xE7,
        0xBB, 0xF4, 0x3F, 0xA7, 0x2C, 0x44, 0x6A, 0xF6, 0xF4, 0x61, 0x81, 0x29,
};
static const uint8_t yb[] = {
        /* y */
        0x09, 0x7E, 0x2C, 0x56, 0x67, 0xC2, 0x22, 0x3A, 0x90, 0x2A, 0xB5, 0xCA,
        0x44, 0x9D, 0x00, 0x84, 0xB7, 0xE5, 0xB3, 0xDE, 0x7C, 0xCC, 0x01, 0xC9,
};
static const uint8_t orderb [] = {
        /* order */
        0xC3, 0x02, 0xF4, 0x1D, 0x93, 0x2A, 0x36, 0xCD, 0xA7, 0xA3, 0x46, 0x2F,
        0x9E, 0x9E, 0x91, 0x6B, 0x5B, 0xE8, 0xF1, 0x02, 0x9A, 0xC4, 0xAC, 0xC1
};
static const uint8_t hb [] = {
        /* cofactor h */
        0x01,
};

EC_GROUP* get_brainpool_192r1(BN_CTX* ctx) {
  EC_GROUP *group = NULL;
  EC_POINT *gen = NULL;
  
  BIGNUM *p = BN_bin2bn(pb, sizeof(pb), NULL);
  BIGNUM *a = BN_bin2bn(ab, sizeof(ab), NULL);
  BIGNUM *b = BN_bin2bn(bb, sizeof(bb), NULL);
  BIGNUM *x = BN_bin2bn(xb, sizeof(xb), NULL);
  BIGNUM *y = BN_bin2bn(yb, sizeof(yb), NULL);
  BIGNUM *cof = BN_bin2bn(hb, sizeof(hb), NULL);
  BIGNUM *order = BN_bin2bn(orderb, sizeof(orderb), NULL);
  if (!ctx || !p || !a || !b || !x || !y || !order) {
    printf("Error generating curve params\n");
    return NULL;
  }
  group = EC_GROUP_new_curve_GFp(p, a, b, ctx);
  if (!group) {
    printf("Error in EC_GROUP_new_curve_GFp\n");
    return NULL;
  }
  gen = EC_POINT_new(group);
  if (!group) {
    printf("Error in EC_POINT_new\n");
    return NULL;
  }
  if (!EC_POINT_set_affine_coordinates_GFp(group, gen, x, y, ctx)) {
    printf("Error in EC_POINT_set_affine_coordinates_GFp\n");
    return NULL;
  }

  if (!EC_GROUP_set_generator(group, gen, order, cof)) {
    printf("Error in EC_GROUP_set_generator\n");
    return NULL;
  }
  return group;
}

int print_key(EC_GROUP* group, EC_KEY* key, BN_CTX* ctx) {
    const EC_POINT *pub = EC_KEY_get0_public_key(key);
    const BIGNUM *prv = EC_KEY_get0_private_key(key);
    if (!pub) {
      fprintf(stderr, "EC_KEY_get0_public_key failed\n");
      return false;
    }
    if (!prv) {
      fprintf(stderr, "EC_KEY_get0_private_key failed\n");
      return false;
    }
    BIGNUM* pubX = BN_new();
    BIGNUM* pubY = BN_new();
    if (!pubX || !pubY || !EC_POINT_get_affine_coordinates_GFp(group, pub, pubX, pubY, ctx)) {
      fprintf(stderr, "EC_POINT_get_affine_coordinates_GFp failed\n");
      return false;
    }
    printf("prv: ");   BN_print_fp(stdout, prv);  printf("\n");
    printf("pub.X: "); BN_print_fp(stdout, pubX); printf("\n");
    printf("pub.Y: "); BN_print_fp(stdout, pubY); printf("\n");
    return true;
}

int brainpoolP192r1_generate_and_store_key(const char* out_key) {
  int counter, i, j;
  uint8_t buf[256];
  unsigned long h;
  uint8_t sig[256];
  unsigned int siglen;
  BN_CTX* ctx = BN_CTX_new();

  EC_GROUP* group = get_brainpool_192r1(ctx);
  if (!group) {
  fprintf(stderr, "get_brainpool_192r1 failed\n");
  return false;
  }

  EC_KEY* key = EC_KEY_new();
  if (!key) {
  fprintf(stderr, "EC_KEY_new failed\n");
  return false;
  }

  if (!EC_KEY_set_group(key, group)) {
  fprintf(stderr, "EC_KEY_set_group failed\n");
  return false;
  }

  if (!EC_KEY_generate_key(key)) {
  fprintf(stderr, "EC_KEY_set_group failed\n");
  return false;
  }

  //print_key(group, key, ctx);

  const BIGNUM *prv = EC_KEY_get0_private_key(key);
  if (!prv) {
    fprintf(stderr, "EC_KEY_get0_private_key failed\n");
    return false;
  }
  unsigned char* keybuf = (unsigned char*)malloc(BN_num_bytes(prv));
  if (!keybuf) {
    fprintf(stderr, "malloc failed\n");
    return false;
  }
  int keylen = BN_bn2bin(prv, keybuf);
  if (!keylen) {
    fprintf(stderr, "BN_bn2bin failed\n");
    return false;
  }
  FILE* fp_out_key = fopen(out_key, "wb");
  if(1 != fwrite(keybuf, keylen, 1, fp_out_key)){
    fprintf(stderr, "fwrite failed\n");
    return false;
  }
  fclose(fp_out_key);
  return true;
}

EC_KEY* brainpoolP192r1_load_key_from_file(const char* in_key) {
  EC_KEY* key = EC_KEY_new();
  if (!key) {
    fprintf(stderr, "EC_KEY_new failed\n");
    return NULL;
  }

  BN_CTX* ctx = BN_CTX_new();
  EC_GROUP* group = get_brainpool_192r1(ctx);
  if (!group) {
    fprintf(stderr, "get_brainpool_192r1 failed\n");
    return NULL;
  }
  if (!EC_KEY_set_group(key, group)) {
    fprintf(stderr, "EC_KEY_set_group failed\n");
    return NULL;
  }

  /* Load private key */
  FILE* fp_in_key = fopen(in_key, "rb");
  int keylen = 0;
  unsigned char keybuf[1024];
  if((keylen = fread(keybuf, 1, sizeof(keybuf), fp_in_key)) <= 0){
    fprintf(stderr, "fread failed\n");
    return NULL;
  }
  fclose(fp_in_key);

  BIGNUM* prv = BN_bin2bn(keybuf, keylen, NULL);
  if (!prv) {
    fprintf(stderr, "BN_bin2bn failed\n");
    return NULL;
  }

  if (!EC_KEY_set_private_key(key, prv)) {
    fprintf(stderr, "EC_KEY_set_private_key failed\n");
    return NULL;
  }

  /* Recover public key */
  EC_POINT* pub = EC_POINT_new(group);
  if (!pub || !EC_POINT_mul(group, pub, prv, NULL, NULL, ctx)) {
    fprintf(stderr, "EC_POINT_mul failed\n");
    return NULL;
  }
  if (!EC_KEY_set_public_key(key, pub)) {
    fprintf(stderr, "EC_KEY_set_public_key failed\n");
    return NULL;
  }
  
  //print_key(group, key, ctx);
  
  return key;
}
