#include "vpn/crypto/curve25519.hpp"
#include "vpn/util/base64.hpp"
#include <iostream>
#include <fstream>
#include <cstring>
#include <sodium.h>

void print_usage(const char* program) {
    std::cerr << "Usage: " << program << " [COMMAND]\n"
              << "\n"
              << "Generate WireGuard keys and pre-shared keys.\n"
              << "\n"
              << "Commands:\n"
              << "  genkey      Generate a new private key\n"
              << "  pubkey      Derive public key from private key (reads from stdin)\n"
              << "  genpsk      Generate a random pre-shared key\n"
              << "  keypair     Generate and print both private and public keys\n"
              << "\n"
              << "Examples:\n"
              << "  " << program << " genkey > private.key\n"
              << "  " << program << " pubkey < private.key > public.key\n"
              << "  " << program << " genpsk > preshared.key\n"
              << "  " << program << " keypair\n";
}

int cmd_genkey() {
    auto keypair = vpn::crypto::Curve25519KeyPair::generate();
    std::cout << keypair.private_key_base64() << "\n";
    return 0;
}

int cmd_pubkey() {
    std::string private_key_b64;
    if (!std::getline(std::cin, private_key_b64)) {
        std::cerr << "Error: Failed to read private key from stdin\n";
        return 1;
    }

    // Trim whitespace
    while (!private_key_b64.empty() && std::isspace(private_key_b64.back())) {
        private_key_b64.pop_back();
    }

    auto keypair = vpn::crypto::Curve25519KeyPair::from_base64(private_key_b64);
    if (!keypair) {
        std::cerr << "Error: Invalid private key\n";
        return 1;
    }

    std::cout << keypair->public_key_base64() << "\n";
    return 0;
}

int cmd_genpsk() {
    // Ensure sodium is initialized
    if (sodium_init() < 0) {
        std::cerr << "Error: Failed to initialize libsodium\n";
        return 1;
    }

    // Generate 32 random bytes
    std::array<uint8_t, 32> psk;
    randombytes_buf(psk.data(), psk.size());

    // Encode and print
    std::cout << vpn::util::base64_encode({psk.data(), psk.size()}) << "\n";

    // Securely clear
    sodium_memzero(psk.data(), psk.size());

    return 0;
}

int cmd_keypair() {
    auto keypair = vpn::crypto::Curve25519KeyPair::generate();

    std::cout << "Private key: " << keypair.private_key_base64() << "\n";
    std::cout << "Public key:  " << keypair.public_key_base64() << "\n";

    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string command = argv[1];

    if (command == "genkey") {
        return cmd_genkey();
    } else if (command == "pubkey") {
        return cmd_pubkey();
    } else if (command == "genpsk") {
        return cmd_genpsk();
    } else if (command == "keypair") {
        return cmd_keypair();
    } else if (command == "-h" || command == "--help" || command == "help") {
        print_usage(argv[0]);
        return 0;
    } else {
        std::cerr << "Unknown command: " << command << "\n\n";
        print_usage(argv[0]);
        return 1;
    }
}
