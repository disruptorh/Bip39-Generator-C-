#include "bip39/mnemonic.hpp"

#include <cstring>
#include <stdexcept>

#include <sodium.h>

namespace bip39 {

// Convert raw entropy bytes to a BIP-39 mnemonic (space-separated words).
//
// `bytes` must correspond to a valid BIP-39 strength: 16 (12 words), 20
// (15), 24 (18), 28 (21) or 32 (24 words). The returned string lives in
// mlock'ed, auto-zeroed memory. Throws std::invalid_argument on bad length.
secure_mem::secure_string entropy_to_mnemonic(const std::uint8_t* entropy,
                                              std::size_t bytes,
                                              const wordlist& wl) {
  if (bytes != 16 && bytes != 20 && bytes != 24 && bytes != 28 && bytes != 32) {
    throw std::invalid_argument(
        "mnemonic: entropy must be 16, 20, 24, 28 or 32 bytes");
  }
  const std::size_t ent_bits = bytes * 8;        // 128..256
  const std::size_t cs_bits = ent_bits / 32;     // 4..8
  const std::size_t total_bits = ent_bits + cs_bits;
  const std::size_t total_bytes = (total_bits + 7) / 8;

  // Checksum: first cs_bits of SHA-256(entropy).
  std::uint8_t hash[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(hash, entropy, bytes);
  const std::uint8_t cs = static_cast<std::uint8_t>(hash[0] >> (8 - cs_bits));
  sodium_memzero(hash, sizeof(hash));

  // Concatenated bitstream: entropy bytes followed by the checksum bits.
  secure_mem::byte_buffer bits(total_bytes);
  std::memcpy(bits.data(), entropy, bytes);
  bits.data()[bytes] = static_cast<std::uint8_t>(cs << (8 - cs_bits));

  secure_mem::secure_string mnemonic;
  std::size_t word_count = 0;
  for (std::size_t i = 0; i < total_bits; i += 11) {
    std::uint32_t index = 0;
    for (std::size_t j = 0; j < 11; ++j) {
      const std::size_t bit = i + j;
      const std::uint8_t mask = static_cast<std::uint8_t>(0x80 >> (bit % 8));
      const std::uint8_t set = (bits.data()[bit / 8] & mask) != 0 ? 1U : 0U;
      index = (index << 1) | set;
    }
    const std::string& w = wl.word(index);
    if (word_count != 0) mnemonic.append(" ", 1);
    mnemonic.append(w.data(), w.size());
    ++word_count;
  }
  return mnemonic;
}

}  // namespace bip39
