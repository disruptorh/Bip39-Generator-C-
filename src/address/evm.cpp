#include "address/evm.hpp"

#include <cstring>

#include <sodium.h>

#include "bip32/bip32.hpp"
#include "crypto/keccak256.hpp"

namespace address {
namespace {

constexpr char kHex[] = "0123456789abcdef";

}  // namespace

void evm_address(const std::uint8_t key[32], std::uint8_t out[20]) {
  std::uint8_t pub[65];
  bip32::uncompressed_pubkey(key, pub);

  // Keccak-256 over the public key WITHOUT the leading 0x04 prefix.
  std::uint8_t digest[32];
  crypto::keccak256(digest, pub + 1, 64);
  std::memcpy(out, digest + 12, 20);

  sodium_memzero(pub, sizeof(pub));
  sodium_memzero(digest, sizeof(digest));
}

std::string evm_address_checksummed(const std::uint8_t key[32]) {
  std::uint8_t addr[20];
  evm_address(key, addr);

  // Lowercase hex address (no 0x prefix).
  char lower[40];
  for (int i = 0; i < 20; ++i) {
    lower[2 * i] = kHex[addr[i] >> 4];
    lower[2 * i + 1] = kHex[addr[i] & 0x0f];
  }

  std::uint8_t digest[32];
  crypto::keccak256(digest, reinterpret_cast<const std::uint8_t*>(lower), 40);

  std::string out = "0x";
  out.reserve(42);
  for (int i = 0; i < 40; ++i) {
    const std::uint8_t nibble = (i % 2 == 0) ? (std::uint8_t)(digest[i / 2] >> 4)
                                             : (std::uint8_t)(digest[i / 2] & 0x0f);
    if (nibble >= 8 && lower[i] >= 'a' && lower[i] <= 'f') {
      out.push_back(static_cast<char>(lower[i] - 'a' + 'A'));
    } else {
      out.push_back(lower[i]);
    }
  }

  sodium_memzero(digest, sizeof(digest));
  sodium_memzero(addr, sizeof(addr));
  return out;
}

}  // namespace address
