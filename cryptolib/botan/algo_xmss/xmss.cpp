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
#include <botan/xmss.h>
#include <botan/oids.h>
#include <botan/pubkey.h>

vector<string> modes = {
  "SHAKE_2_256",
  "SHAKE_10_256",
  "SHA2_2_192",
  "SHA2_10_192",
};

vector<string> operations = {
  "keygen",
  "sign"
};

int main(int argc, char* argv[]) {
  Botan::AutoSeeded_RNG rng;

  if (argc != 4) {
    cout << "Usage:\n\n"
              << "  kyber <mode> <operation> <keyfile>\n\n"
              << "    <mode> ..... asymmetric cipher mode\n"
              << "    <operation> ..... operation to execute, e.g. keygen or kem\n"
              << "    <keyfile> ... kyber key file, read as text\n"
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

  std::string mode_buffer("XMSS-");
  mode_buffer.append(str_mode);
  const auto xmss_algo = Botan::XMSS_Parameters::xmss_id_from_string(mode_buffer);

  std::string keyfile_buffer_sk(str_keyfile);

  if (str_operation == "keygen") {
    // Alice KeyGen
    const Botan::XMSS_PrivateKey priv_key(xmss_algo, rng);
    const auto priv_key_bits = priv_key.private_key_bits();

    // Store key pair
    ofstream keyfile_sk;
    keyfile_sk.open(keyfile_buffer_sk);
    keyfile_sk << Botan::hex_encode(priv_key_bits);
    keyfile_sk.close();
    } else if (str_operation == "sign") {
        std::vector<uint8_t> signature;
        auto message = Botan::hex_decode("deadbeef");

        // Load key pair
        string line_sk;
        ifstream keyfile_sk;
        keyfile_sk.open(keyfile_buffer_sk);
        getline(keyfile_sk, line_sk);
        keyfile_sk.close();
        Botan::secure_vector<uint8_t> priv_key_bits =
            Botan::hex_decode_locked(line_sk);

        Botan::XMSS_PrivateKey priv_key(priv_key_bits);

        Botan::PK_Signer sig(priv_key, rng, str_mode);
        signature = sig.sign_message(message, rng);

        Botan::PK_Verifier ver(priv_key, "");
        ver.update(message);
        assert(ver.check_signature(signature));
  } else {
    cout << str_operation << " is no valid operation!" << endl;
    assert(false);
  }

  return (0);
}

