#include <string.h>
#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

void print_help(const char* argv0) {
  printf("Usage: \n");
  printf("  %s   genkey <keyfile> <curve>       Generate private key for curve ed25519|ed448\n", argv0);
  printf("  %s   sign   <keyfile> <sigfile>     Create a signature in <sigfile>\n", argv0);
  printf("  %s   verify <keyfile> <sigfile>     Verify signature in <sigfile>\n", argv0);
}

int main(int argc, char* argv[]) {
  if (argc < 4) {
    print_help(argv[0]);
    return 1;
  }

  if (strcmp(argv[1], "genkey") == 0) {
    int id = 0;
    if (strcmp(argv[3], "ed25519") == 0) {
      id = EVP_PKEY_ED25519;
    } else if (strcmp(argv[3], "ed448") == 0) {
      id = EVP_PKEY_ED448;
    } else {
      printf("Error: invalid curve parameter\n");
      return 1;
    }
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(id, NULL);
    if (!pctx) {
      printf("Error creating new context\n");
      return 1;
    }
    if (!EVP_PKEY_keygen_init(pctx)) {
      printf("Error initializing context\n");
      return 1;
    }
    EVP_PKEY *pkey = NULL;
    if (!EVP_PKEY_keygen(pctx, &pkey) || !pkey) {
      printf("Error generating key\n");
      return 1;
    }

    FILE* fout = fopen(argv[2], "w");
    if (!fout) {
      printf("Error creating key file %s\n", argv[2]);
      return 1;
    }

    if (!PEM_write_PrivateKey(fout, pkey, NULL, NULL, 0, NULL, NULL)) {
      printf("Error writing key file\n");
      return 1;
    }
    fclose(fout);
  } else if (strcmp(argv[1], "sign") == 0) {
    FILE* fp = fopen(argv[2], "r");
    if (!fp) {
      printf("Error loading private key from file %s\n", argv[2]);
      return 1;
    }

    EVP_PKEY *pkey = NULL;
    if (!PEM_read_PrivateKey(fp, &pkey, NULL, NULL) || !pkey) {
      printf("Error reading private key\n");
      return 1;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx) {
      printf("Error creating pkey context\n");
      return 1;
    }

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
      printf("Error creating md context\n");
      return 1;
    }

    size_t siglen = EVP_PKEY_size(pkey);
    unsigned char* sig = OPENSSL_malloc(siglen);
    if (sig == NULL) {
      printf("Error allocating signature\n");
      return 1;
    }

    if (EVP_DigestSignInit(mctx, &pctx, NULL, NULL, pkey) <= 0) {
      printf("Error initializing signature\n");
      return 1;
    }
    
    unsigned char message[20] = {0};
    if (EVP_DigestSign(mctx, sig, &siglen, message, sizeof(message)) <= 0) {
      printf("Error creating signature\n");
      return 1;
    }

    FILE* fout = fopen(argv[3], "w");
    if (!fout) {
      printf("Error creating signature file %s\n", argv[3]);
      return 1;
    }

    if(fwrite(sig, siglen, 1, fout) != 1) {
      printf("Error writing signature file\n");
      return 1;
    }
    fclose(fout);
  } else if (strcmp(argv[1], "verify") == 0) {
    FILE* fp = fopen(argv[2], "r");
    if (!fp) {
      printf("Error loading private key from file %s\n", argv[2]);
      return 1;
    }

    EVP_PKEY *pkey = NULL;
    if (!PEM_read_PrivateKey(fp, &pkey, NULL, NULL) || !pkey) {
      printf("Error reading private key\n");
      return 1;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx) {
      printf("Error creating pkey context\n");
      return 1;
    }

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
      printf("Error creating md context\n");
      return 1;
    }

    size_t siglen = EVP_PKEY_size(pkey);
    unsigned char* sig = OPENSSL_malloc(siglen);
    if (sig == NULL) {
      printf("Error allocating signature\n");
      return 1;
    }

    FILE* fsig = fopen(argv[3], "r");
    if (!fsig) {
      printf("Error opening signature file %s\n", argv[3]);
      return 1;
    }

    if (fread(sig, siglen, 1, fsig) != 1) {
      printf("Error reading signature\n");
      return 1;
    }

    if (EVP_DigestVerifyInit(mctx, &pctx, NULL, NULL, pkey) <= 0) {
      printf("Error initializing signature\n");
      return 1;
    }

    unsigned char message[20] = {0};
    if (EVP_DigestVerify(mctx, sig, siglen, message, sizeof(message)) <= 0) {
      printf("Error validating signature\n");
      return 1;
    }
  }
  return 0;
}
