#ifndef BIP39_CRYPTO_BASE58_HPP_
#define BIP39_CRYPTO_BASE58_HPP_

#include <cstddef>
#include <cstdint>
#include <string>

namespace crypto {

// Base58Check encoding (Bitcoin): payload + first 4 bytes of double-SHA256,
// then Base58 with leading '1' per leading zero byte.
std::string base58check(const std::uint8_t* payload, std::size_t len);

}  // namespace crypto

#endif  // BIP39_CRYPTO_BASE58_HPP_
