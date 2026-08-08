#ifndef BIP39_BIP32_BIP32_HPP_
#define BIP39_BIP32_BIP32_HPP_

#include <cstddef>
#include <cstdint>

#include "secure_mem/secure_buffer.hpp"

namespace bip32 {

// A 256-bit private key plus its BIP-32 chain code.
struct key_pair {
  std::uint8_t key[32];
  std::uint8_t chain_code[32];
};

// BIP-39 mnemonic -> 64-byte seed (PBKDF2-HMAC-SHA512, 2048 iterations,
// salt "mnemonic" + passphrase). The mnemonic is assumed to be ASCII (the
// English wordlist is pure ASCII, so NFKD normalization is the identity).
// Passphrase may be empty. `seed` must point to 64 bytes.
//
// Preferred overload: `mnemonic` must live in mlock'ed secure memory
// (secure_mem::secure_string). Taking the type by reference enforces at the
// API level that a real seed phrase can never be held in a plain std::string.
void mnemonic_to_seed(const secure_mem::secure_string& mnemonic,
                      const char* passphrase, std::uint8_t seed[64]);

// Raw-pointer overload kept for test vectors (compile-time string literals).
// The caller MUST pass a mnemonic that resides in secure memory; do not feed
// it a std::string holding a real seed phrase.
void mnemonic_to_seed(const char* mnemonic, const char* passphrase,
                      std::uint8_t seed[64]);

// BIP-32 master key from a seed. Throws std::runtime_error if the master
// IL is not a valid secp256k1 scalar (astronomically unlikely; per BIP-32
// the seed would need to be retried with different entropy).
key_pair master_from_seed(const std::uint8_t* seed, std::size_t seed_len);

// BIP-32 CKDpriv. Index >= 0x80000000 selects hardened derivation.
// Returns false if the derivation yields an invalid key (IL >= n or
// resulting key == 0), in which case BIP-32 requires retrying with the
// next index. On success fills `out`.
bool child_key(const key_pair& parent, std::uint32_t index, key_pair& out);

// Derive along a path of indexes, retrying each level at the next index if a
// BIP-32 invalid key is produced. `path` has `n` elements; `out` receives the
// final key pair. Throws std::runtime_error if the master is invalid.
void derive_path(const key_pair& master, const std::uint32_t* path,
                 std::size_t n, key_pair& out);

// secp256k1 public key derivation. `out` must hold 33 (compressed) or
// 65 (uncompressed) bytes. Throws std::runtime_error on an invalid key.
void compressed_pubkey(const std::uint8_t key[32], std::uint8_t out[33]);
void uncompressed_pubkey(const std::uint8_t key[32], std::uint8_t out[65]);

// BIP-32 parent fingerprint: first 4 bytes of hash160(pubkey).
void fingerprint(const std::uint8_t key[32], std::uint8_t out[4]);

}  // namespace bip32

#endif  // BIP39_BIP32_BIP32_HPP_
