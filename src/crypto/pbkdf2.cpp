#include "crypto/pbkdf2.hpp"

#include <cstring>
#include <stdexcept>

#include <sodium.h>

namespace crypto {
namespace {

// HMAC-SHA512 via libsodium. libsodium implements the full RFC 2104
// (a key longer than the 128-byte block is hashed down first). The streaming
// API is used so an arbitrary-length key is supported. The HMAC state holds
// the expanded key material (the PBKDF2 password / BIP-39 mnemonic) and MUST
// be wiped before returning.
void hmac_sha512(std::uint8_t out[64], const std::uint8_t* key,
                 std::size_t key_len, const std::uint8_t* data,
                 std::size_t data_len) {
  crypto_auth_hmacsha512_state st;
  crypto_auth_hmacsha512_init(&st, key, key_len);
  crypto_auth_hmacsha512_update(&st, data, data_len);
  crypto_auth_hmacsha512_final(&st, out);
  sodium_memzero(&st, sizeof(st));
}

}  // namespace

void pbkdf2_hmac_sha512(const std::uint8_t* password, std::size_t pass_len,
                        const std::uint8_t* salt, std::size_t salt_len,
                        std::uint32_t iterations, std::uint8_t* out,
                        std::size_t dk_len) {
  if (iterations == 0) throw std::invalid_argument("pbkdf2: iterations == 0");
  if (dk_len == 0) throw std::invalid_argument("pbkdf2: dk_len == 0");

  // U1 = PRF(P, S || INT32_BE(i));  T_i = U1 ^ U2 ^ ... ^ Uc.
  std::uint8_t u[crypto_auth_hmacsha512_BYTES];
  std::uint8_t t[crypto_auth_hmacsha512_BYTES];

  const std::size_t blocks = (dk_len + 63) / 64;
  for (std::uint32_t block = 1; block <= blocks; ++block) {
    const std::uint8_t block_be[4] = {
        static_cast<std::uint8_t>(block >> 24),
        static_cast<std::uint8_t>(block >> 16),
        static_cast<std::uint8_t>(block >> 8),
        static_cast<std::uint8_t>(block)};
    // Prepend the block counter to the salt for U1 without extra allocation:
    // HMAC(password, salt || counter).
    crypto_auth_hmacsha512_state state;
    crypto_auth_hmacsha512_init(&state, password, pass_len);
    crypto_auth_hmacsha512_update(&state, salt, salt_len);
    crypto_auth_hmacsha512_update(&state, block_be, 4);
    crypto_auth_hmacsha512_final(&state, u);
    sodium_memzero(&state, sizeof(state));  // state holds the expanded password
    std::memcpy(t, u, sizeof(t));

    for (std::uint32_t i = 1; i < iterations; ++i) {
      hmac_sha512(u, password, pass_len, u, sizeof(u));
      for (std::size_t j = 0; j < sizeof(u); ++j) t[j] ^= u[j];
    }

    const std::size_t copy = (dk_len - (block - 1) * 64 < 64)
                                 ? dk_len - (block - 1) * 64
                                 : 64;
    std::memcpy(out + (block - 1) * 64, t, copy);
  }

  sodium_memzero(u, sizeof(u));
  sodium_memzero(t, sizeof(t));
}

}  // namespace crypto
