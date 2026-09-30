#include "crypto/kdf.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace crypto {
namespace {

// Legacy KDF: SHA-256(secret || counter_be32) truncated/extended to `length`.
// Unkeyed by design (no salt), which is exactly why the obfuscator app labels
// it "Legacy" and why it is the fast path used for large batches here.
secure_mem::byte_buffer derive_key_v1(std::string_view secret,
                                      std::size_t length) {
  secure_mem::byte_buffer result(length);
  std::size_t out_pos = 0;
  std::uint32_t counter = 0;

  while (out_pos < length) {
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);

    crypto_hash_sha256_update(
        &state, reinterpret_cast<const std::uint8_t*>(secret.data()),
        secret.size());

    const std::uint8_t counter_bytes[4] = {
        static_cast<std::uint8_t>(counter >> 24),
        static_cast<std::uint8_t>(counter >> 16),
        static_cast<std::uint8_t>(counter >> 8),
        static_cast<std::uint8_t>(counter),
    };
    crypto_hash_sha256_update(&state, counter_bytes, sizeof(counter_bytes));

    std::uint8_t hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256_final(&state, hash);

    const std::size_t copy_len =
        std::min(static_cast<std::size_t>(crypto_hash_sha256_BYTES),
                 length - out_pos);
    std::memcpy(result.data() + out_pos, hash, copy_len);
    out_pos += copy_len;

    sodium_memzero(hash, sizeof(hash));
    ++counter;
  }

  return result;
}

// N=32768, r=8, p=1. Unused by the legacy batch export but kept so the KDF is
// byte-compatible with the obfuscator app if V2 is ever selected.
secure_mem::byte_buffer derive_key_v2(std::string_view secret,
                                      const std::vector<std::uint8_t>& salt,
                                      std::size_t length) {
  if (salt.size() != kSaltBytes) {
    throw std::invalid_argument("V2 salt must be exactly 16 bytes.");
  }

  secure_mem::byte_buffer result(length);
  const int ret = crypto_pwhash_scryptsalsa208sha256_ll(
      reinterpret_cast<const std::uint8_t*>(secret.data()), secret.size(),
      salt.data(), salt.size(), 32768, 8, 1, result.data(), result.size());
  if (ret != 0) {
    throw std::runtime_error("scrypt failed");
  }
  return result;
}

}  // namespace

secure_mem::byte_buffer derive_key(const KdfParams& params) {
  if (params.version == KdfVersion::V1_SHA256) {
    return derive_key_v1(params.secret, params.length);
  }
  if (params.version == KdfVersion::V2_SCRYPT) {
    return derive_key_v2(params.secret, params.salt, params.length);
  }
  throw std::invalid_argument("Unknown KDF version");
}

std::vector<std::uint8_t> generate_salt() {
  std::vector<std::uint8_t> salt(kSaltBytes);
  randombytes_buf(salt.data(), salt.size());
  return salt;
}

}  // namespace crypto