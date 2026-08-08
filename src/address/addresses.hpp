#ifndef BIP39_ADDRESS_ADDRESSES_HPP_
#define BIP39_ADDRESS_ADDRESSES_HPP_

#include <string>

namespace address {

// Addresses derived from a BIP-39 mnemonic at account 0, external chain,
// first index:
//   EVM: m/44'/60'/0'/0/0  (Ethereum, EIP-55 checksummed)
//   BTC: m/84'/0'/0'/0/0   (Bitcoin native SegWit P2WPKH, bech32)
struct addresses {
  std::string evm;
  std::string btc;
};

addresses derive_from_mnemonic(const char* mnemonic,
                               const char* passphrase = "");

}  // namespace address

#endif  // BIP39_ADDRESS_ADDRESSES_HPP_
