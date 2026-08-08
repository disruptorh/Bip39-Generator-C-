#ifndef BIP39_BIP39_MNEMONIC_HPP_
#define BIP39_BIP39_MNEMONIC_HPP_

#include <cstddef>
#include <cstdint>

#include "bip39/wordlist.hpp"
#include "secure_mem/secure_buffer.hpp"

namespace bip39 {

// Convert raw entropy bytes to a BIP-39 mnemonic (space-separated words).
//
// `bytes` must be 16 (12 words) or 32 (24 words). The returned string lives in
// mlock'ed, auto-zeroed memory. Throws std::invalid_argument on bad length.
secure_mem::secure_string entropy_to_mnemonic(const std::uint8_t* entropy,
                                              std::size_t bytes,
                                              const wordlist& wl);

}  // namespace bip39

#endif  // BIP39_BIP39_MNEMONIC_HPP_
