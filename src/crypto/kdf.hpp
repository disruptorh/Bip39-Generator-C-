#ifndef BIP39_CRYPTO_KDF_HPP_
#define BIP39_CRYPTO_KDF_HPP_

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "secure_mem/secure_buffer.hpp"

namespace crypto {

// Key-derivation schemes shared with BIP-39 Obfuscator. V1 is the legacy
// SHA-256 counter mode; V2 is scrypt (salted, slow). Both are ported verbatim
// from the obfuscator app so a batch export is de-obfuscatable there.
enum class KdfVersion {
  V1_SHA256 = 1,
  V2_SCRYPT = 2,
};

constexpr std::size_t kSaltBytes = 16;

struct KdfParams {
  KdfVersion version;
  std::string_view secret;
  std::vector<std::uint8_t> salt;  // Used only in V2
  std::size_t length;              // Target output length
};

// Derives `params.length` key bytes. Returns an mlock'ed, auto-zeroed buffer.
secure_mem::byte_buffer derive_key(const KdfParams& params);

// Random salt for V2. Not needed by the legacy (V1) batch export, exposed for
// parity with the obfuscator app.
std::vector<std::uint8_t> generate_salt();

}  // namespace crypto

#endif  // BIP39_CRYPTO_KDF_HPP_