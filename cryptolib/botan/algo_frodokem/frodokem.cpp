#include <cassert>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
using namespace std;

#include <botan/block_cipher.h>
#include <botan/auto_rng.h>
#include <botan/rng.h>
#include <botan/hex.h>
#include <botan/frodokem.h>
#include <botan/pubkey.h>

vector<string> modes = {
  "KEM640_SHAKE",
};

vector<string> operations = {
  "keygen",
  "kem"
};

const size_t shared_secret_length = 32;

Botan::FrodoKEMMode name_to_mode(const std::string& algo_name) {
 if(algo_name == "KEM640_SHAKE")
    { return Botan::FrodoKEMMode::FrodoKEM640_SHAKE; }
 if(algo_name == "KEM976_SHAKE")
    { return Botan::FrodoKEMMode::FrodoKEM976_SHAKE; }
 if(algo_name == "KEM1344_SHAKE")
    { return Botan::FrodoKEMMode::FrodoKEM1344_SHAKE; }
 if(algo_name == "eKEM640_SHAKE")
    { return Botan::FrodoKEMMode::eFrodoKEM640_SHAKE; }
 if(algo_name == "eKEM976_SHAKE")
    { return Botan::FrodoKEMMode::eFrodoKEM976_SHAKE; }
 if(algo_name == "eKEM1344_SHAKE")
    { return Botan::FrodoKEMMode::eFrodoKEM1344_SHAKE; }
 if(algo_name == "KEM640_AES")
    { return Botan::FrodoKEMMode::FrodoKEM640_AES; }
 if(algo_name == "KEM976_AES")
    { return Botan::FrodoKEMMode::FrodoKEM976_AES; }
 if(algo_name == "KEM1344_AES")
    { return Botan::FrodoKEMMode::FrodoKEM1344_AES; }
 if(algo_name == "eKEM640_AES")
    { return Botan::FrodoKEMMode::eFrodoKEM640_AES; }
 if(algo_name == "eKEM976_AES")
    { return Botan::FrodoKEMMode::eFrodoKEM976_AES; }
 if(algo_name == "eKEM1344_AES")
    { return Botan::FrodoKEMMode::eFrodoKEM1344_AES; }

 assert(false);
}

void frodokem_encrypt(
        Botan::FrodoKEM_PublicKey pub_key,
        Botan::secure_vector<uint8_t> &cipher_text,
        Botan::secure_vector<uint8_t> &sym_key
        ) {
    Botan::AutoSeeded_RNG rng;
    auto encryptor = Botan::PK_KEM_Encryptor(pub_key, "KDF2(SHA-256)", "");
    encryptor.encrypt(cipher_text, sym_key, rng, shared_secret_length);
}

void frodokem_decrypt(
        Botan::FrodoKEM_PrivateKey priv_key,
        Botan::secure_vector<uint8_t> &cipher_text,
        Botan::secure_vector<uint8_t> &sym_key
        ) {
    Botan::AutoSeeded_RNG rng;
    auto decryptor = Botan::PK_KEM_Decryptor(priv_key, rng, "KDF2(SHA-256)", "");
    sym_key = decryptor.decrypt(cipher_text.data(), cipher_text.size(), shared_secret_length);
}

int main(int argc, char* argv[]) {
  Botan::AutoSeeded_RNG rng;

  if (argc != 4) {
    cout << "Usage:\n\n"
              << "  frodokem <mode> <operation> <frodokemkeyfile>\n\n"
              << "    <mode> ..... asymmetric cipher mode\n"
              << "    <operation> ..... operation to execute, e.g. keygen or kem\n"
              << "    <frodokemkeyfile> ... frodokem key file, read as text\n"
              << endl;
    cout << "List of available modes:" << endl;
    for(vector<string>::size_type i = 0; i != modes.size(); i++) {
      cout << "  " << modes[i] << endl;
    }
    cout << endl;
    cout << "List of available operations:" << endl;
    for(vector<string>::size_type i = 0; i != operations.size(); i++) {
      cout << "  " << operations[i] << endl;
    }
    cout << endl;
    return (1);
  }

  string str_mode (argv[1]);
  string str_operation (argv[2]);
  string str_frodokemkeyfile (argv[3]);

  Botan::FrodoKEMMode mode = name_to_mode(str_mode);

  std::string frodokemkeyfile_buffer_sk(str_frodokemkeyfile);

  if (str_operation == "keygen") {
    // Alice KeyGen
    const Botan::FrodoKEM_PrivateKey priv_key(rng, mode);
    const auto priv_key_bits = priv_key.private_key_bits();

    // Store key pair
    ofstream frodokemkeyfile_sk;
    frodokemkeyfile_sk.open(frodokemkeyfile_buffer_sk);
    frodokemkeyfile_sk << Botan::hex_encode(priv_key_bits);
    frodokemkeyfile_sk.close();
  } else if (str_operation == "kem") {
    Botan::secure_vector<uint8_t> cipher_text, key_bob, key_alice;

    // Load key pair
    string line_sk;
    ifstream frodokemkeyfile_sk;
    frodokemkeyfile_sk.open(frodokemkeyfile_buffer_sk);
    getline(frodokemkeyfile_sk, line_sk);
    frodokemkeyfile_sk.close();
    Botan::secure_vector<uint8_t> priv_key_bits = Botan::hex_decode_locked(line_sk);

    Botan::FrodoKEM_PrivateKey priv_key(priv_key_bits, mode);
    const auto pk = priv_key.public_key();
    const auto pk_bits = pk->public_key_bits();
    Botan::FrodoKEM_PublicKey pub_key(pk_bits, mode);

    frodokem_encrypt(pub_key, cipher_text, key_bob);
    frodokem_decrypt(priv_key, cipher_text, key_alice);

    assert(key_bob == key_alice);
  } else {
    cout << str_operation << " is no valid operation!" << endl;
    assert(false);
  }

  return (0);
}

