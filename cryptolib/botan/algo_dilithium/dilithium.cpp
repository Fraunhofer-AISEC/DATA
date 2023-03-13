#include <cassert>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
using namespace std;

#include <botan/auto_rng.h>
#include <botan/block_cipher.h>
#include <botan/dilithium.h>
#include <botan/hex.h>
#include <botan/oids.h>
#include <botan/pubkey.h>
#include <botan/rng.h>

vector<string> modes = {
    "4x4", "4x4_AES", "6x5", "6x5_AES", "8x7", "8x7_AES",
};

vector<string> operations = {"keygen", "sign"};

Botan::DilithiumMode name_to_mode(const std::string &algo_name) {
    if (algo_name == "4x4") {
        return Botan::DilithiumMode::Dilithium4x4;
    }
    if (algo_name == "4x4_AES") {
        return Botan::DilithiumMode::Dilithium4x4_AES;
    }
    if (algo_name == "6x5") {
        return Botan::DilithiumMode::Dilithium6x5;
    }
    if (algo_name == "6x5_AES") {
        return Botan::DilithiumMode::Dilithium6x5_AES;
    }
    if (algo_name == "8x7") {
        return Botan::DilithiumMode::Dilithium8x7;
    }
    if (algo_name == "8x7_AES") {
        return Botan::DilithiumMode::Dilithium8x7_AES;
    }

    assert(false);
}

int main(int argc, char *argv[]) {
    Botan::AutoSeeded_RNG rng;

    if (argc != 4) {
        cout << "Usage:\n\n"
             << "  dilithium <mode> <operation> <keyfile>\n\n"
             << "    <mode> ..... asymmetric cipher mode\n"
             << "    <operation> ..... operation to execute, e.g. keygen or "
                "kem\n"
             << "    <keyfile> ... kyber key file, read as text\n"
             << endl;
        cout << "List of available modes:" << endl;
        for (vector<string>::size_type i = 0; i != modes.size(); i++) {
            cout << "  " << modes[i] << endl;
        }
        cout << endl;
        cout << "List of available operations:" << endl;
        for (vector<string>::size_type i = 0; i != operations.size(); i++) {
            cout << "  " << operations[i] << endl;
        }
        cout << endl;
        return (1);
    }

    string str_mode(argv[1]);
    string str_operation(argv[2]);
    string str_keyfile(argv[3]);

    Botan::DilithiumMode mode = name_to_mode(str_mode);
    // auto encoding = Botan::DilithiumKeyEncoding::DER;
    auto encoding = Botan::DilithiumKeyEncoding::Raw;

    std::string keyfile_buffer_sk(str_keyfile);

    if (str_operation == "keygen") {
        const Botan::Dilithium_PrivateKey priv_key(rng, mode);
        const auto priv_key_bits = priv_key.private_key_bits();

        ofstream keyfile_sk;
        keyfile_sk.open(keyfile_buffer_sk);
        keyfile_sk << Botan::hex_encode(priv_key_bits);
        keyfile_sk.close();
    } else if (str_operation == "sign") {
        std::vector<uint8_t> message, signature;
        message.push_back(0xde);
        message.push_back(0xad);
        message.push_back(0xbe);
        message.push_back(0xef);

        // Load key pair
        string line_sk;
        ifstream keyfile_sk;
        keyfile_sk.open(keyfile_buffer_sk);
        getline(keyfile_sk, line_sk);
        keyfile_sk.close();
        Botan::secure_vector<uint8_t> priv_key_bits =
            Botan::hex_decode_locked(line_sk);

        Botan::Dilithium_PrivateKey priv_key(priv_key_bits, mode, encoding);

        Botan::PK_Signer sig(priv_key, rng, "Deterministic");
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
