#ifndef BIP39_ADDRESS_BTC_HPP_
#define BIP39_ADDRESS_BTC_HPP_

#include <cstdint>
#include <string>

namespace address {

// Bitcoin P2PKH address (Base58Check, version 0x00) from a secp256k1
// private key using the compressed public key.
std::string btc_p2pkh(const std::uint8_t key[32]);

// Bitcoin native SegWit P2WPKH address (bech32, witness version 0) from a
// secp256k1 private key using the compressed public key.
std::string btc_p2wpkh(const std::uint8_t key[32]);

}  // namespace address

#endif  // BIP39_ADDRESS_BTC_HPP_
