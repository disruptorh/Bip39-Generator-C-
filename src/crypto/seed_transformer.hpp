#ifndef BIP39_CRYPTO_SEED_TRANSFORMER_HPP_
#define BIP39_CRYPTO_SEED_TRANSFORMER_HPP_

#include <string_view>
#include <vector>

#include "bip39/wordlist.hpp"
#include "crypto/kdf.hpp"
#include "secure_mem/secure_buffer.hpp"

namespace crypto {

struct TransformParams {
  std::string_view seed_phrase;
  std::string_view secret;
  std::vector<std::uint8_t> salt;  // Used only in V2
  KdfVersion kdf_version;
};

// Obfuscates or de-obfuscates a BIP-39 mnemonic by XOR-ing its entropy with a
// key derived from `secret` (the password), then recomputing the BIP-39
// checksum. XOR is involutive, so the same call de-obfuscates what it
// obfuscated. Ported verbatim from BIP-39 Obfuscator.
//
// Throws std::invalid_argument if the phrase is not a valid 12/15/18/21/24-word
// mnemonic or contains a word outside `wl`.
secure_mem::secure_string transform_seed(const TransformParams& params,
                                         const bip39::wordlist& wl);

}  // namespace crypto

#endif  // BIP39_CRYPTO_SEED_TRANSFORMER_HPP_