#include <array>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <sodium.h>

#include "bip39/mnemonic.hpp"
#include "bip39/wordlist.hpp"
#include "secure_mem/secure_buffer.hpp"
#include "test_util.hpp"

namespace {

// Minimal parser for the official BIP-39 vectors.json (trezor format):
// arrays of [entropy_hex, mnemonic, seed_hex, xprv]. Extracts every quoted
// token and groups them in records of four.
std::vector<std::array<std::string, 4>> parse_vectors(const std::string& path) {
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
  // Only the 'english' section is parsed: stop at the next top-level language
  // key, which is the first token after the section that is not part of a
  // vector record (the file contains 12 languages x 24 vectors).
  for (std::size_t k = 1; k + 3 < tokens.size(); k += 4) {
    if (out.size() == 24) break;  // english section has exactly 24 vectors
    out.push_back({tokens[k], tokens[k + 1], tokens[k + 2], tokens[k + 3]});
  }
  return out;
}

// PBKDF2-HMAC-SHA512 (RFC 8018/2898) built on libsodium's HMAC-SHA512, used
// purely to validate the official BIP-39 seed vectors in tests.
void pbkdf2_hmac_sha512(std::uint8_t* out, std::size_t out_len,
                        const std::uint8_t* password, std::size_t pass_len,
                        const std::uint8_t* salt, std::size_t salt_len,
                        std::uint32_t iterations) {
  std::uint8_t block[crypto_auth_hmacsha512_BYTES];
  std::uint8_t tmp[crypto_auth_hmacsha512_BYTES];
  std::uint8_t salt_block[sizeof(std::uint32_t)];

  for (std::uint32_t block_index = 1; out_len > 0; ++block_index) {
    crypto_auth_hmacsha512_state st;
    crypto_auth_hmacsha512_init(&st, password, pass_len);
    crypto_auth_hmacsha512_update(&st, salt, salt_len);
    salt_block[0] = static_cast<std::uint8_t>(block_index >> 24);
    salt_block[1] = static_cast<std::uint8_t>(block_index >> 16);
    salt_block[2] = static_cast<std::uint8_t>(block_index >> 8);
    salt_block[3] = static_cast<std::uint8_t>(block_index);
    crypto_auth_hmacsha512_update(&st, salt_block, sizeof(salt_block));
    crypto_auth_hmacsha512_final(&st, block);
    std::memcpy(tmp, block, sizeof(tmp));

    for (std::uint32_t i = 1; i < iterations; ++i) {
      crypto_auth_hmacsha512_state st2;
      crypto_auth_hmacsha512_init(&st2, password, pass_len);
      crypto_auth_hmacsha512_update(&st2, block, sizeof(block));
      crypto_auth_hmacsha512_final(&st2, block);
      for (std::size_t j = 0; j < sizeof(tmp); ++j) tmp[j] ^= block[j];
    }
    sodium_memzero(block, sizeof(block));

    const std::size_t n = out_len < sizeof(tmp) ? out_len : sizeof(tmp);
    std::memcpy(out, tmp, n);
    out += n;
    out_len -= n;
  }
  sodium_memzero(tmp, sizeof(tmp));
}

}  // namespace

TEST(bip39_official_vectors) {
  const std::string path =
      std::string(TEST_DATA_DIR) + "/bip39_vectors.json";
  const auto vectors = parse_vectors(path);
  CHECK(vectors.size() == 24);

  const bip39::wordlist& wl = bip39::wordlist::load();
  for (const auto& v : vectors) {
    const auto entropy = test_util::from_hex(v[0]);
    const secure_mem::secure_string m =
        bip39::entropy_to_mnemonic(entropy.data(), entropy.size(), wl);
    CHECK(std::string(m.c_str(), m.size()) == v[1]);

    // Derive the seed with PBKDF2-HMAC-SHA512 to validate the full pipeline.
    // The official trezor vectors use the passphrase "TREZOR", so the salt is
    // "mnemonic" + "TREZOR" (BIP-39: salt = "mnemonic" || passphrase).
    const char* kSalt = "mnemonicTREZOR";
    std::uint8_t seed[64];
    pbkdf2_hmac_sha512(seed, sizeof(seed),
                       reinterpret_cast<const std::uint8_t*>(m.c_str()),
                       m.size(), reinterpret_cast<const std::uint8_t*>(kSalt),
                       std::strlen(kSalt), 2048);
    CHECK(test_util::to_hex(seed, sizeof(seed)) == v[2]);
    sodium_memzero(seed, sizeof(seed));
  }
}

TEST(bip39_invalid_entropy_length_rejected) {
  const bip39::wordlist& wl = bip39::wordlist::load();
  const std::uint8_t bad[17] = {0};
  bool threw = false;
  try {
    (void)bip39::entropy_to_mnemonic(bad, sizeof(bad), wl);
  } catch (const std::invalid_argument&) {
    threw = true;
  }
  CHECK(threw);
}
