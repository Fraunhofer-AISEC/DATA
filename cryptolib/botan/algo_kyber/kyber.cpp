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
#include <botan/kyber.h>
#include <botan/oids.h>
#include <botan/pubkey.h>

vector<string> modes = {
  "512",
  "512-90s",
  "768",
  "768-90s",
  "1024",
  "1024-90s"
};

vector<string> operations = {
  "keygen",
  "kem"
};

const size_t shared_secret_length = 32;

Botan::KyberMode name_to_mode(const std::string& algo_name) {
 if(algo_name == "Kyber-512")
    { return Botan::KyberMode::Kyber512; }
 if(algo_name == "Kyber-512-90s")
    { return Botan::KyberMode::Kyber512_90s; }
 if(algo_name == "Kyber-768")
    { return Botan::KyberMode::Kyber768; }
 if(algo_name == "Kyber-768-90s")
    { return Botan::KyberMode::Kyber768_90s; }
 if(algo_name == "Kyber-1024")
    { return Botan::KyberMode::Kyber1024; }
 if(algo_name == "Kyber-1024-90s")
    { return Botan::KyberMode::Kyber1024_90s; }

 assert(false);
}

void kyber_kem_encrypt(
        Botan::Kyber_PublicKey pub_key,
        Botan::secure_vector<uint8_t> &cipher_text,
        Botan::secure_vector<uint8_t> &sym_key
        ) {
    Botan::AutoSeeded_RNG rng;
    auto encryptor = Botan::PK_KEM_Encryptor(pub_key, rng, "HKDF(SHA-256)", "");
    encryptor.encrypt(cipher_text, sym_key, shared_secret_length, rng);
}

void kyber_kem_decrypt(
        Botan::Kyber_PrivateKey priv_key,
        Botan::secure_vector<uint8_t> &cipher_text,
        Botan::secure_vector<uint8_t> &sym_key
        ) {
    Botan::AutoSeeded_RNG rng;
    auto decryptor = Botan::PK_KEM_Decryptor(priv_key, rng, "HKDF(SHA-256)", "");
    sym_key = decryptor.decrypt(cipher_text.data(), cipher_text.size(), shared_secret_length);
}

int main(int argc, char* argv[]) {
  Botan::AutoSeeded_RNG rng;

  if (argc != 4) {
    cout << "Usage:\n\n"
              << "  kyber <mode> <operation> <infile> <outfile> <kyberkeyfile>\n\n"
              << "    <mode> ..... asymmetric cipher mode\n"
              << "    <operation> ..... operation to execute, e.g. keygen or kem\n"
              << "    <kyberkeyfile> ... kyber key file, read as text\n"
              // << "    <symkeyfile> ..... symmetric key file, read as text\n"
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
  string str_kyberkeyfile (argv[3]);

  std::string mode_buffer("Kyber-");
  mode_buffer.append(str_mode);
  Botan::KyberMode mode = name_to_mode(mode_buffer);

  std::string kyberkeyfile_buffer_sk(str_kyberkeyfile);

  if (str_operation == "keygen") {
    // Alice KeyGen
    const Botan::Kyber_PrivateKey priv_key(rng, mode);
    const auto priv_key_bits = priv_key.private_key_bits();

    // Store key pair
    ofstream kyberkeyfile_sk;
    kyberkeyfile_sk.open(kyberkeyfile_buffer_sk);
    kyberkeyfile_sk << Botan::hex_encode(priv_key_bits);
    kyberkeyfile_sk.close();
  } else if (str_operation == "kem") {
    Botan::secure_vector<uint8_t> cipher_text, key_bob, key_alice;

    // Load key pair
    string line_sk;
    ifstream kyberkeyfile_sk;
    kyberkeyfile_sk.open(kyberkeyfile_buffer_sk);
    getline(kyberkeyfile_sk, line_sk);
    kyberkeyfile_sk.close();
    Botan::secure_vector<uint8_t> priv_key_bits = Botan::hex_decode_locked(line_sk);

    Botan::Kyber_PrivateKey priv_key(priv_key_bits, mode, Botan::KyberKeyEncoding::Full);
    const auto pk = priv_key.public_key();
    const auto pk_bits = pk->public_key_bits();
    Botan::Kyber_PublicKey pub_key(pk_bits, mode, Botan::KyberKeyEncoding::Full);

    kyber_kem_encrypt(pub_key, cipher_text, key_bob);
    kyber_kem_decrypt(priv_key, cipher_text, key_alice);

    assert(key_bob == key_alice);
  } else {
    cout << str_operation << " is no valid operation!" << endl;
    assert(false);
  }

  return (0);
}

