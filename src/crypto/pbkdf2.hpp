#ifndef BIP39_CRYPTO_PBKDF2_HPP_
#define BIP39_CRYPTO_PBKDF2_HPP_

#include <cstddef>
#include <cstdint>

namespace crypto {

// PBKDF2-HMAC-SHA512 per RFC 2898, with HMAC-SHA512 per RFC 2104 (including
// the key-longer-than-one-block hash-down case). Fills `out` with `dk_len`
// bytes. `iterations` must be >= 1; `dk_len` must be > 0.
void pbkdf2_hmac_sha512(const std::uint8_t* password, std::size_t pass_len,
                        const std::uint8_t* salt, std::size_t salt_len,
                        std::uint32_t iterations, std::uint8_t* out,
                        std::size_t dk_len);

}  // namespace crypto

#endif  // BIP39_CRYPTO_PBKDF2_HPP_
