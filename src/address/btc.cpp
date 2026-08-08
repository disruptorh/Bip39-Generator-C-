#include "address/btc.hpp"

#include <cstring>

#include <sodium.h>

#include "bip32/bip32.hpp"
#include "crypto/base58.hpp"
#include "crypto/ripemd160.hpp"

namespace address {

std::string btc_p2pkh(const std::uint8_t key[32]) {
  std::uint8_t pub[33];
  bip32::compressed_pubkey(key, pub);

  std::uint8_t h1[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(h1, pub, sizeof(pub));

  std::uint8_t h160[20];
  crypto::ripemd160(h160, h1, sizeof(h1));

  std::uint8_t payload[21];
  payload[0] = 0x00;  // P2PKH mainnet version byte
  std::memcpy(payload + 1, h160, 20);

  std::string out = crypto::base58check(payload, sizeof(payload));

  sodium_memzero(pub, sizeof(pub));
  sodium_memzero(h1, sizeof(h1));
  sodium_memzero(h160, sizeof(h160));
  sodium_memzero(payload, sizeof(payload));
  return out;
}

}  // namespace address
