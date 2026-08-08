#ifndef BIP39_ADDRESS_BECH32_HPP_
#define BIP39_ADDRESS_BECH32_HPP_

#include <cstdint>
#include <string>
#include <vector>

namespace address {

// BIP-173 bech32 encode. `data5` holds 5-bit values (0..31); returns
// "<hrp>1<data><checksum>". Throws std::invalid_argument for a non-printable
// ASCII HRP or a data value outside [0, 31].
std::string bech32_encode(const std::string& hrp,
                          const std::vector<std::uint8_t>& data5);

// Native SegWit v0 (P2WPKH) bech32 address from a 20-byte HASH160.
// Mainnet HRP is "bc" (testnet would be "tb").
std::string bech32_p2wpkh(const std::uint8_t hash160[20],
                          const std::string& hrp = "bc");

}  // namespace address

#endif  // BIP39_ADDRESS_BECH32_HPP_
