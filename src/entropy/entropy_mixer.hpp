#ifndef BIP39_ENTROPY_ENTROPY_MIXER_HPP_
#define BIP39_ENTROPY_ENTROPY_MIXER_HPP_

#include <cstddef>
#include <cstdint>

#include "secure_mem/secure_buffer.hpp"

namespace entropy {

// Output length produced by random_bytes() / mix(), in bytes.
constexpr std::size_t kEntropy12Words = 16;  // 128 bits
constexpr std::size_t kEntropy24Words = 32;  // 256 bits

// Application-level, immutable HKDF parameters. Changing these constants
// changes the derived entropy; they are fixed for the lifetime of the app.
//   salt = fixed application identifier (auditable constant)
//   info = domain separation tag for the entropy derivation
constexpr char kHkdfSalt[] = "bip39-app-salt-fixed-0001";
constexpr char kHkdfInfo[] = "bip39-entropy-v1";

// CSPRNG from the operating system via libsodium (getrandom()/dev/urandom).
// Throws std::runtime_error on RNG failure.
secure_mem::byte_buffer random_bytes(std::size_t n);

// Mix OS entropy with optional user-supplied entropy.
//
//   ikm  = os_entropy || user_entropy
//   out  = HKDF-SHA512(ikm, salt=kHkdfSalt, info=kHkdfInfo)[:out_len]
//
// Property: when `user` is empty the output is cryptographically equivalent to
// the OS entropy processed through HKDF. User input can only ADD entropy; it
// can never reduce the output below the OS-guaranteed floor.
secure_mem::byte_buffer mix(const std::uint8_t* os_entropy, std::size_t os_len,
                            const char* user, std::size_t user_len,
                            std::size_t out_len);

}  // namespace entropy

#endif  // BIP39_ENTROPY_ENTROPY_MIXER_HPP_
