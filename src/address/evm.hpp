#ifndef BIP39_ADDRESS_EVM_HPP_
#define BIP39_ADDRESS_EVM_HPP_

#include <cstdint>
#include <string>

namespace address {

// Ethereum address (20 bytes) from a secp256k1 private key: last 20 bytes of
// keccak256(uncompressed pubkey without the 0x04 prefix).
void evm_address(const std::uint8_t key[32], std::uint8_t out[20]);

// EIP-55 checksummed hex address, including the "0x" prefix.
std::string evm_address_checksummed(const std::uint8_t key[32]);

}  // namespace address

#endif  // BIP39_ADDRESS_EVM_HPP_
