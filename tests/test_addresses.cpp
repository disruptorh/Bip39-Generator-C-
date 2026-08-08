#include <array>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <sodium.h>

#include "address/addresses.hpp"
#include "address/btc.hpp"
#include "address/evm.hpp"
#include "bip32/bip32.hpp"
#include "crypto/base58.hpp"
#include "crypto/keccak256.hpp"
#include "crypto/ripemd160.hpp"
#include "test_util.hpp"

namespace {

// String-aware equality check (CHECK_EQ only supports arithmetic types).
void check_str(const std::string& actual, const std::string& expected) {
  if (actual != expected) {
    throw std::runtime_error("string mismatch: got '" + actual +
                             "' expected '" + expected + "'");
  }
}

// Minimal JSON string extractor (trezor vectors format). Returns the vector
// records of the english section: [entropy_hex, mnemonic, seed_hex, xprv].
std::vector<std::array<std::string, 4>> parse_english_vectors(
    const std::string& path) {
  std::ifstream in(path);
  if (!in) throw std::runtime_error("cannot open " + path);
  std::ostringstream ss;
  ss << in.rdbuf();
  const std::string text = ss.str();

  std::vector<std::string> tokens;
  std::size_t i = 0;
  while (i < text.size()) {
    if (text[i] == '"') {
      std::size_t j = i + 1;
      while (j < text.size() && text[j] != '"') ++j;
      tokens.push_back(text.substr(i + 1, j - i - 1));
      i = j + 1;
    } else {
      ++i;
    }
  }
  if (tokens.empty() || tokens[0] != "english") {
    throw std::runtime_error("vectors file does not start with 'english'");
  }

  std::vector<std::array<std::string, 4>> out;
  for (std::size_t k = 1; k + 3 < tokens.size(); k += 4) {
    if (out.size() == 24) break;
    out.push_back({tokens[k], tokens[k + 1], tokens[k + 2], tokens[k + 3]});
  }
  return out;
}

// Serialize a master key pair to a BIP-32 master xprv (depth 0).
std::string master_xprv(const bip32::key_pair& mk) {
  std::uint8_t payload[78] = {};
  payload[0] = 0x04; payload[1] = 0x88; payload[2] = 0xad; payload[3] = 0xe4;
  payload[45] = 0x00;
  std::memcpy(payload + 13, mk.chain_code, 32);
  std::memcpy(payload + 46, mk.key, 32);
  return crypto::base58check(payload, sizeof(payload));
}

std::uint32_t hardened(std::uint32_t i) { return 0x80000000U + i; }

void check_evm(const char* mnemonic, const char* passphrase,
               std::uint32_t index, const char* expected) {
  std::uint8_t seed[64];
  bip32::mnemonic_to_seed(mnemonic, passphrase, seed);
  bip32::key_pair master = bip32::master_from_seed(seed, sizeof(seed));
  sodium_memzero(seed, sizeof(seed));

  const std::uint32_t path[] = {hardened(44), hardened(60), hardened(0), 0,
                                index};
  bip32::key_pair leaf;
  bip32::derive_path(master, path, 5, leaf);
  check_str(address::evm_address_checksummed(leaf.key), expected);
  sodium_memzero(master.key, sizeof(master.key));
  sodium_memzero(master.chain_code, sizeof(master.chain_code));
  sodium_memzero(leaf.key, sizeof(leaf.key));
  sodium_memzero(leaf.chain_code, sizeof(leaf.chain_code));
}

void check_btc(const char* mnemonic, const char* passphrase,
               std::uint32_t index, const char* expected) {
  std::uint8_t seed[64];
  bip32::mnemonic_to_seed(mnemonic, passphrase, seed);
  bip32::key_pair master = bip32::master_from_seed(seed, sizeof(seed));
  sodium_memzero(seed, sizeof(seed));

  const std::uint32_t path[] = {hardened(44), hardened(0), hardened(0), 0,
                                index};
  bip32::key_pair leaf;
  bip32::derive_path(master, path, 5, leaf);
  check_str(address::btc_p2pkh(leaf.key), expected);
  sodium_memzero(master.key, sizeof(master.key));
  sodium_memzero(master.chain_code, sizeof(master.chain_code));
  sodium_memzero(leaf.key, sizeof(leaf.key));
  sodium_memzero(leaf.chain_code, sizeof(leaf.chain_code));
}

}  // namespace

TEST(keccak256_vectors) {
  std::uint8_t out[32];
  crypto::keccak256(out, nullptr, 0);
  check_str(test_util::to_hex(out, 32),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  const unsigned char abc[] = {'a', 'b', 'c'};
  crypto::keccak256(out, abc, 3);
  check_str(test_util::to_hex(out, 32),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
}

TEST(ripemd160_vectors) {
  std::uint8_t out[20];
  crypto::ripemd160(out, nullptr, 0);
  check_str(test_util::to_hex(out, 20), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
  const unsigned char abc[] = {'a', 'b', 'c'};
  crypto::ripemd160(out, abc, 3);
  check_str(test_util::to_hex(out, 20), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
}

TEST(base58check_vectors) {
  // WIF for private key 1 (compressed): payload [0x80][32-byte key][0x01].
  std::uint8_t wif[34] = {};
  wif[0] = 0x80;
  wif[32] = 0x01;
  wif[33] = 0x01;
  check_str(crypto::base58check(wif, sizeof(wif)),
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
}

TEST(mnemonic_to_seed_vectors) {
  const char* abandon = "abandon abandon abandon abandon abandon abandon "
                        "abandon abandon abandon abandon abandon about";
  std::uint8_t seed[64];

  bip32::mnemonic_to_seed(abandon, "", seed);
  check_str(
      test_util::to_hex(seed, 64),
      "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40"
      "b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4");

  bip32::mnemonic_to_seed(abandon, "TREZOR", seed);
  check_str(
      test_util::to_hex(seed, 64),
      "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a698"
      "7599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");

  const char* junk =
      "test test test test test test test test test test test junk";
  bip32::mnemonic_to_seed(junk, "", seed);
  check_str(
      test_util::to_hex(seed, 64),
      "9dfc3c64c2f8bede1533b6a79f8570e5943e0b8fd1cf77107adf7b72cef42185d564a3ae"
      "e24cab43f80e3c4538087d70fc824eabbad596a23c97b6ee8322ccc0");
}

TEST(bip32_test_vector_1) {
  const auto seed = test_util::from_hex("000102030405060708090a0b0c0d0e0f");
  bip32::key_pair master =
      bip32::master_from_seed(seed.data(), seed.size());
  check_str(
      master_xprv(master),
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJx"
      "WUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");

  bip32::key_pair child;
  CHECK(bip32::child_key(master, 0x80000000U, child));
  check_str(test_util::to_hex(child.key, 32),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea");

  bip32::key_pair child2;
  CHECK(bip32::child_key(child, 1, child2));
  check_str(test_util::to_hex(child2.key, 32),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368");
  sodium_memzero(master.key, sizeof(master.key));
  sodium_memzero(child.key, sizeof(child.key));
  sodium_memzero(child2.key, sizeof(child2.key));
}

TEST(trezor_english_seed_and_master_xprv) {
  const auto vectors =
      parse_english_vectors(std::string(TEST_DATA_DIR) + "/bip39_vectors.json");
  CHECK_EQ(vectors.size(), static_cast<std::size_t>(24));
  for (const auto& v : vectors) {
    std::uint8_t seed[64];
    bip32::mnemonic_to_seed(v[1].c_str(), "TREZOR", seed);
    check_str(test_util::to_hex(seed, 64), v[2]);
    bip32::key_pair master = bip32::master_from_seed(seed, sizeof(seed));
    check_str(master_xprv(master), v[3]);
    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(master.key, sizeof(master.key));
    sodium_memzero(master.chain_code, sizeof(master.chain_code));
  }
}

TEST(metamask_hardhat_addresses) {
  const char* junk =
      "test test test test test test test test test test test junk";
  check_evm(junk, "", 0, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
  check_evm(junk, "", 1, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
  check_btc(junk, "", 0, "1Ei9UmLQv4o4UJTy5r5mnGFeC9auM3W5P1");
  check_btc(junk, "", 1, "14RBPsg6mBkLSJokkzeuoCkTtoeD3nK2Kz");
}

TEST(bip44_test_vector_1_btc_address) {
  // Official BIP-44 test vector 1: seed 000102030405060708090a0b0c0d0e0f,
  // m/44'/0'/0'/0/0 must yield P2PKH address 1NQpH6Nf8QtR2HphLRcvuVqfhXBXsiWn8r.
  const auto seed = test_util::from_hex("000102030405060708090a0b0c0d0e0f");
  bip32::key_pair master =
      bip32::master_from_seed(seed.data(), seed.size());
  const std::uint32_t path[] = {hardened(44), hardened(0), hardened(0), 0, 0};
  bip32::key_pair leaf;
  bip32::derive_path(master, path, 5, leaf);
  check_str(address::btc_p2pkh(leaf.key), "1NQpH6Nf8QtR2HphLRcvuVqfhXBXsiWn8r");
  sodium_memzero(master.key, sizeof(master.key));
  sodium_memzero(leaf.key, sizeof(leaf.key));
}

TEST(derive_from_mnemonic_integration) {
  const char* junk =
      "test test test test test test test test test test test junk";
  const address::addresses addr = address::derive_from_mnemonic(junk);
  check_str(addr.evm, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
  check_str(addr.btc, "1Ei9UmLQv4o4UJTy5r5mnGFeC9auM3W5P1");
}
