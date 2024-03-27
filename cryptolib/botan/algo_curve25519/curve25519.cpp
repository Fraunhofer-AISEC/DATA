#include <cassert>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
using namespace std;



#include <botan/auto_rng.h>
#include <botan/curve25519.h>
#include <botan/ecdh.h>
#include <botan/hex.h>
#include <botan/pubkey.h>

vector<string> modes = {
  "curve25519",
};

vector<string> operations = {
  "keygen",
  "ecdh"
};

int main(int argc, char* argv[]) {
  Botan::AutoSeeded_RNG rng;

  if (argc != 4) {
    cout << "Usage:\n\n"
              << "  ecdh <mode> <operation> <keyfile>\n\n"
              << "    <mode> ..... asymmetric cipher mode\n"
              << "    <operation> ..... operation to execute, e.g. keygen or kem\n"
              << "    <keyfile> ... ecc key file, read as text\n"
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
  string str_keyfile (argv[3]);

  // ec domain and KDF
  const std::string kdf = "KDF2(SHA-256)";

  std::string keyfile_buffer_sk(str_keyfile);

  if (str_operation == "keygen") {
    // KeyGen
    const Botan::Curve25519_PrivateKey key(rng);
    const auto key_bits = key.private_key_bits();

    // Store key pair
    ofstream keyfile_sk;
    keyfile_sk.open(keyfile_buffer_sk);
    keyfile_sk << hex_encode(key_bits);
    keyfile_sk.close();

  } else if (str_operation == "ecdh") {
        // std::vector<uint8_t> signature;
        string line_sk;
        ifstream keyfile_sk;

        Botan::AlgorithmIdentifier aid;

        // // Load server key
        Botan::Curve25519_PrivateKey server_key(
            aid,
            Botan::hex_decode(
                "042014F9395B906AD12E57E10E0CC0694A747322B6FFEF4B8FB3803F6F2AFE972B2C"
            )
        );
        // keyfile_sk.open(keyfile_buffer_sk);
        // getline(keyfile_sk, line_sk);
        // keyfile_sk.close();
        // const auto server_sk(Botan::hex_decode(line_sk));
        // Botan::Curve25519_PrivateKey server_key(aid, server_sk);

        // Load experiment key
        keyfile_sk.open(keyfile_buffer_sk);
        getline(keyfile_sk, line_sk);
        keyfile_sk.close();
        const auto sk(Botan::hex_decode(line_sk));
        Botan::Curve25519_PrivateKey key(aid, sk);

        // now they exchange their public values
        const auto server_key_pub = server_key.public_value();
        const auto key_pub = key.public_value();

        // Construct key agreements and agree on a shared secret
        Botan::PK_Key_Agreement ka_server(server_key, rng, kdf);
        const auto sA = ka_server.derive_key(32, key_pub).bits_of();

        Botan::PK_Key_Agreement ka_client(key, rng, kdf);
        const auto sB = ka_client.derive_key(32, server_key_pub).bits_of();

        assert(sA == sB);
  } else {
    cout << str_operation << " is no valid operation!" << endl;
    assert(false);
  }

  return (0);
}
