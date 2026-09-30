#include "crypto/seed_transformer.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace crypto {
namespace {

int find_word_index(std::string_view word, const bip39::wordlist& wl) {
  for (std::size_t i = 0; i < wl.size(); ++i) {
    const std::string& candidate = wl.word(i);
    // Compared by length first so no temporary std::string is built for a
    // secret-bearing token.
    if (candidate.size() == word.size() &&
        candidate.compare(0, candidate.size(), word.data(), word.size()) == 0) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

// Splits on single spaces without copying: the returned views point straight
// into the caller's buffer, so the mnemonic never lands on the heap.
std::vector<std::string_view> split_words(std::string_view phrase) {
  std::vector<std::string_view> words;
  std::size_t i = 0;
  while (i < phrase.size()) {
    while (i < phrase.size() && phrase[i] == ' ') ++i;
    if (i >= phrase.size()) break;
    const std::size_t start = i;
    while (i < phrase.size() && phrase[i] != ' ') ++i;
    words.push_back(phrase.substr(start, i - start));
  }
  return words;
}

bool is_valid_word_count(std::size_t n) {
  return n == 12 || n == 15 || n == 18 || n == 21 || n == 24;
}

}  // namespace

secure_mem::secure_string transform_seed(const TransformParams& params,
                                         const bip39::wordlist& wl) {
  const std::vector<std::string_view> words = split_words(params.seed_phrase);
  if (!is_valid_word_count(words.size())) {
    throw std::invalid_argument(
        "Invalid mnemonic length. Must be 12, 15, 18, 21, or 24 words.");
  }

  const std::size_t total_bits = words.size() * 11;
  const std::size_t ent_bits = (total_bits * 32) / 33;
  const std::size_t cs_bits = total_bits - ent_bits;
  const std::size_t ent_bytes = ent_bits / 8;

  // Decode the mnemonic into its raw entropy bytes. Only the first `ent_bits`
  // bits are entropy: the trailing bits of the last word are the BIP-39
  // checksum and must not be written into `entropy` (which is exactly
  // `ent_bytes` long), or they overflow the buffer.
  secure_mem::byte_buffer entropy(ent_bytes);
  std::size_t bit_pos = 0;
  for (std::size_t i = 0; i < words.size(); ++i) {
    const int idx = find_word_index(words[i], wl);
    if (idx < 0) {
      throw std::invalid_argument("Invalid word in mnemonic: " +
                                  std::string(words[i]));
    }
    for (std::size_t j = 0; j < 11; ++j, ++bit_pos) {
      if (bit_pos >= ent_bits) break;
      if (idx & (1 << (10 - j))) {
        entropy.data()[bit_pos / 8] |= (0x80 >> (bit_pos % 8));
      }
    }
  }

  KdfParams kdf_params;
  kdf_params.version = params.kdf_version;
  kdf_params.secret = params.secret;
  kdf_params.salt = params.salt;
  kdf_params.length = ent_bytes;
  secure_mem::byte_buffer key = derive_key(kdf_params);

  // XOR the entropy with the derived keystream, then re-derive the checksum
  // so the result is a well-formed mnemonic of the same length.
  secure_mem::byte_buffer new_entropy(ent_bytes);
  for (std::size_t i = 0; i < ent_bytes; ++i) {
    new_entropy.data()[i] = entropy.data()[i] ^ key.data()[i];
  }

  std::uint8_t hash[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(hash, new_entropy.data(), ent_bytes);

  // Re-encode: entropy bits followed by the new checksum bits.
  std::vector<std::uint8_t> bitstream((total_bits + 7) / 8, 0);
  for (std::size_t i = 0; i < ent_bits; ++i) {
    if (new_entropy.data()[i / 8] & (0x80 >> (i % 8))) {
      bitstream[i / 8] |= (0x80 >> (i % 8));
    }
  }
  for (std::size_t i = 0; i < cs_bits; ++i) {
    if (hash[0] & (0x80 >> i)) {
      const std::size_t pos = ent_bits + i;
      bitstream[pos / 8] |= (0x80 >> (pos % 8));
    }
  }
  sodium_memzero(hash, sizeof(hash));

  secure_mem::secure_string result;
  std::uint32_t idx = 0;
  for (std::size_t i = 0; i < words.size(); ++i) {
    idx = 0;
    for (std::size_t j = 0; j < 11; ++j) {
      const std::size_t pos = i * 11 + j;
      if (bitstream[pos / 8] & (0x80 >> (pos % 8))) {
        idx |= (1u << (10 - j));
      }
    }
    if (i > 0) result.append(" ", 1);
    const std::string& w = wl.word(idx);
    result.append(w.data(), w.size());
  }

  return result;
}

}  // namespace crypto