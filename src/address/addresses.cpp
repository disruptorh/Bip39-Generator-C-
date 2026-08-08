#include "address/addresses.hpp"

#include <cstring>

#include <sodium.h>

#include "address/btc.hpp"
#include "address/evm.hpp"
#include "bip32/bip32.hpp"

namespace address {
namespace {

constexpr std::uint32_t kHardened = 0x80000000U;

void derive_account_key_from_seed(const std::uint8_t* seed, std::size_t seed_len,
                                  std::uint32_t purpose, std::uint32_t coin_type,
                                  std::uint8_t key[32]) {
  bip32::key_pair master = bip32::master_from_seed(seed, seed_len);

  const std::uint32_t path[] = {kHardened + purpose, kHardened + coin_type,
                                kHardened, 0, 0};
  bip32::key_pair leaf;
  bip32::derive_path(master, path, sizeof(path) / sizeof(path[0]), leaf);
  sodium_memzero(master.key, sizeof(master.key));
  sodium_memzero(master.chain_code, sizeof(master.chain_code));

  std::memcpy(key, leaf.key, 32);
  sodium_memzero(leaf.key, sizeof(leaf.key));
  sodium_memzero(leaf.chain_code, sizeof(leaf.chain_code));
}

void derive_account_key(const char* mnemonic, const char* passphrase,
                        std::uint32_t purpose, std::uint32_t coin_type,
                        std::uint8_t key[32]) {
  std::uint8_t seed[64];
  bip32::mnemonic_to_seed(mnemonic, passphrase, seed);
  derive_account_key_from_seed(seed, sizeof(seed), purpose, coin_type, key);
  sodium_memzero(seed, sizeof(seed));
}

void derive_account_key(const secure_mem::secure_string& mnemonic,
                        const char* passphrase, std::uint32_t purpose,
                        std::uint32_t coin_type, std::uint8_t key[32]) {
  std::uint8_t seed[64];
  bip32::mnemonic_to_seed(mnemonic, passphrase, seed);
  derive_account_key_from_seed(seed, sizeof(seed), purpose, coin_type, key);
  sodium_memzero(seed, sizeof(seed));
}

}  // namespace

addresses derive_from_mnemonic(const char* mnemonic, const char* passphrase) {
  addresses out;

  std::uint8_t key[32];
  derive_account_key(mnemonic, passphrase, 44, 60, key);
  out.evm = evm_address_checksummed(key);
  sodium_memzero(key, sizeof(key));

  derive_account_key(mnemonic, passphrase, 84, 0, key);
  out.btc = btc_p2wpkh(key);
  sodium_memzero(key, sizeof(key));

  return out;
}

addresses derive_from_mnemonic(const secure_mem::secure_string& mnemonic,
                               const char* passphrase) {
  addresses out;

  std::uint8_t key[32];
  derive_account_key(mnemonic, passphrase, 44, 60, key);
  out.evm = evm_address_checksummed(key);
  sodium_memzero(key, sizeof(key));

  derive_account_key(mnemonic, passphrase, 84, 0, key);
  out.btc = btc_p2wpkh(key);
  sodium_memzero(key, sizeof(key));

  return out;
}

}  // namespace address
