#ifndef BIP39_CRYPTO_RIPEMD160_HPP_
#define BIP39_CRYPTO_RIPEMD160_HPP_

#include <cstddef>
#include <cstdint>

namespace crypto {

// RIPEMD-160 (used by Bitcoin P2PKH and P2SH address hashes).
void ripemd160(std::uint8_t out[20], const std::uint8_t* data,
               std::size_t len);

}  // namespace crypto

#endif  // BIP39_CRYPTO_RIPEMD160_HPP_
