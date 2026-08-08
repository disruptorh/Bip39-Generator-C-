#ifndef BIP39_CRYPTO_KECCAK256_HPP_
#define BIP39_CRYPTO_KECCAK256_HPP_

#include <cstddef>
#include <cstdint>

namespace crypto {

// Keccak-256 (original Keccak padding, NOT the NIST SHA3-256). Ethereum
// addresses use the pre-NIST Keccak variant, whose empty-input digest is
// c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470.
void keccak256(std::uint8_t out[32], const std::uint8_t* data,
               std::size_t len);

}  // namespace crypto

#endif  // BIP39_CRYPTO_KECCAK256_HPP_
