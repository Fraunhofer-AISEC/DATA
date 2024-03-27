#include <cassert>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
using namespace std;

#include <botan/auto_rng.h>
#include <botan/rng.h>
#include <botan/hex.h>
#include <botan/cmce.h>
#include <botan/pubkey.h>

vector<string> modes = {
  "mceliece348864",
  "mceliece348864f",
};

vector<string> operations = {
  "keygen",
  "kem"
};

const size_t shared_secret_length = 32;

void mceliece_encrypt(
        Botan::Classic_McEliece_PrivateKey priv_key,
        Botan::secure_vector<uint8_t> &cipher_text,
        Botan::secure_vector<uint8_t> &sym_key
        ) {
    Botan::AutoSeeded_RNG rng;
    auto encryptor = Botan::PK_KEM_Encryptor(priv_key, "Raw", "base");
    encryptor.encrypt(cipher_text, sym_key, rng, shared_secret_length);
}

void mceliece_decrypt(
        Botan::Classic_McEliece_PrivateKey priv_key,
        Botan::secure_vector<uint8_t> &cipher_text,
        Botan::secure_vector<uint8_t> &sym_key
        ) {
    Botan::AutoSeeded_RNG rng;
    auto decryptor = Botan::PK_KEM_Decryptor(priv_key, rng, "Raw");
    sym_key = decryptor.decrypt(cipher_text.data(), cipher_text.size(), shared_secret_length);
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    cout << "Usage:\n\n"
              << "  mceliece <mode> <operation> <mceliecekeyfile>\n\n"
              << "    <mode> ..... asymmetric cipher mode\n"
              << "    <operation> ..... operation to execute, e.g. keygen or kem\n"
              << "    <mceliecekeyfile> ... mceliece key file, read as text\n"
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
  string str_mceliecekeyfile (argv[3]);

  Botan::Classic_McEliece_Parameter_Set params = Botan::cmce_param_set_from_str(str_mode);

  std::string mceliecekeyfile_buffer_sk(str_mceliecekeyfile);

  if (str_operation == "keygen") {
    Botan::AutoSeeded_RNG rng;
    // Alice KeyGen
    const Botan::Classic_McEliece_PrivateKey priv_key(rng, params);
    const auto priv_key_bits = priv_key.private_key_bits();

    // Store key pair
    ofstream mceliecekeyfile_sk;
    mceliecekeyfile_sk.open(mceliecekeyfile_buffer_sk);
    mceliecekeyfile_sk << Botan::hex_encode(priv_key_bits);
    mceliecekeyfile_sk.close();
  } else if (str_operation == "kem") {
    Botan::secure_vector<uint8_t> cipher_text, key_bob, key_alice;

    // Load key pair
    string line_sk;
    ifstream mceliecekeyfile_sk;
    mceliecekeyfile_sk.open(mceliecekeyfile_buffer_sk);
    getline(mceliecekeyfile_sk, line_sk);
    mceliecekeyfile_sk.close();
    Botan::secure_vector<uint8_t> priv_key_bits = Botan::hex_decode_locked(line_sk);

    Botan::Classic_McEliece_PrivateKey priv_key(priv_key_bits, params);

    mceliece_encrypt(priv_key, cipher_text, key_bob);
    mceliece_decrypt(priv_key, cipher_text, key_alice);

    assert(key_bob == key_alice);
  } else {
    cout << str_operation << " is no valid operation!" << endl;
    assert(false);
  }

  return (0);
}

