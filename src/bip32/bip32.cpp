#include "bip32/bip32.hpp"

#include <cstring>
#include <stdexcept>

#include <secp256k1.h>
#include <sodium.h>

#include "crypto/pbkdf2.hpp"
#include "crypto/ripemd160.hpp"

namespace bip32 {
namespace {

// BIP-39 KDF parameters.
constexpr char kSaltPrefix[] = "mnemonic";
constexpr std::uint32_t kPbkdf2Iterations = 2048;

const secp256k1_context* context() {
  // C++11 function-local statics guarantee thread-safe one-time
  // initialization, so concurrent first calls cannot race.
  static const secp256k1_context* ctx = [] {
    // Current libsecp256k1 API: SECP256K1_CONTEXT_NONE is the only
    // non-deprecated flag and yields a context sufficient for ALL library
    // functionality (the historical SIGN/VERIFY flags were removed upstream
    // and are treated as equivalent to NONE). secp256k1_context_static is NOT
    // suitable here: it forbids secret-key operations such as
    // secp256k1_ec_pubkey_create used below.
    secp256k1_context* c = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (c == nullptr) {
      throw std::runtime_error("secp256k1: context allocation failed");
    }
    // Randomize the context as recommended by the library docs for secret-key
    // operations (side-channel hardening for the pubkey derivations).
    std::uint8_t seed[32];
    randombytes_buf(seed, sizeof(seed));
    if (secp256k1_context_randomize(c, seed) != 1) {
      sodium_memzero(seed, sizeof(seed));
      secp256k1_context_destroy(c);
      throw std::runtime_error("secp256k1: context randomization failed");
    }
    sodium_memzero(seed, sizeof(seed));
    return c;
  }();
  return ctx;
}

void hmac_sha512(const std::uint8_t* key, std::size_t key_len,
                 const std::uint8_t* data, std::size_t data_len,
                 std::uint8_t out[64]) {
  crypto_auth_hmacsha512_state st;
  crypto_auth_hmacsha512_init(&st, key, key_len);
  crypto_auth_hmacsha512_update(&st, data, data_len);
  crypto_auth_hmacsha512_final(&st, out);
  // The state holds the expanded master/child key material; wipe it before it
  // leaves scope.
  sodium_memzero(&st, sizeof(st));
}
bool is_zero(const std::uint8_t bytes[32]) {
  for (int i = 0; i < 32; ++i) {
    if (bytes[i] != 0) return false;
  }
  return true;
}

}  // namespace

void mnemonic_to_seed(const secure_mem::secure_string& mnemonic,
                      const char* passphrase, std::uint8_t seed[64]) {
  mnemonic_to_seed(mnemonic.c_str(), passphrase, seed);
}

void mnemonic_to_seed(const char* mnemonic, const char* passphrase,
                      std::uint8_t seed[64]) {
  const std::size_t m_len = std::strlen(mnemonic);
  const std::size_t p_len = (passphrase != nullptr) ? std::strlen(passphrase)
                                                     : 0;
  const std::size_t salt_len = sizeof(kSaltPrefix) - 1 + p_len;
  // Salt buffer on the stack. The RAII guard wipes the whole buffer on every
  // exit path, including the case where pbkdf2_hmac_sha512 throws: the BIP-39
  // passphrase must never survive on the stack.
  std::uint8_t salt[sizeof(kSaltPrefix) - 1 + 256];
  struct salt_guard {
    std::uint8_t* ptr;
    std::size_t len;
    ~salt_guard() { sodium_memzero(ptr, len); }
  } guard{salt, sizeof(salt)};
  if (salt_len > sizeof(salt)) {
    throw std::invalid_argument("passphrase too long");
  }
  std::memcpy(salt, kSaltPrefix, sizeof(kSaltPrefix) - 1);
  if (p_len != 0) std::memcpy(salt + sizeof(kSaltPrefix) - 1, passphrase, p_len);

  crypto::pbkdf2_hmac_sha512(
      reinterpret_cast<const std::uint8_t*>(mnemonic), m_len, salt, salt_len,
      kPbkdf2Iterations, seed, 64);
}

key_pair master_from_seed(const std::uint8_t* seed, std::size_t seed_len) {
  const std::uint8_t key_data[] = {'B', 'i', 't', 'c', 'o', 'i', 'n',
                                   ' ', 's', 'e', 'e', 'd'};
  std::uint8_t i[64];
  hmac_sha512(key_data, sizeof(key_data), seed, seed_len, i);

  key_pair master;
  std::memcpy(master.key, i, 32);
  std::memcpy(master.chain_code, i + 32, 32);
  sodium_memzero(i, sizeof(i));

  if (is_zero(master.key) ||
      secp256k1_ec_seckey_verify(context(), master.key) != 1) {
    throw std::runtime_error(
        "BIP-32: master IL is not a valid secp256k1 scalar");
  }
  return master;
}

bool child_key(const key_pair& parent, std::uint32_t index, key_pair& out) {
  std::uint8_t data[37];
  const bool hardened = index >= 0x80000000U;
  if (hardened) {
    data[0] = 0x00;
    std::memcpy(data + 1, parent.key, 32);
  } else {
    std::uint8_t pub[33];
    compressed_pubkey(parent.key, pub);
    std::memcpy(data, pub, 33);
    sodium_memzero(pub, sizeof(pub));
  }
  data[33] = static_cast<std::uint8_t>(index >> 24);
  data[34] = static_cast<std::uint8_t>(index >> 16);
  data[35] = static_cast<std::uint8_t>(index >> 8);
  data[36] = static_cast<std::uint8_t>(index);

  std::uint8_t i[64];
  hmac_sha512(parent.chain_code, sizeof(parent.chain_code), data, sizeof(data),
              i);
  sodium_memzero(data, sizeof(data));

  const std::uint8_t* il = i;
  const std::uint8_t* ir = i + 32;
  std::memcpy(out.chain_code, ir, 32);

  if (is_zero(il)) {
    // IL == 0 is valid per BIP-32: the child key equals the parent key.
    std::memcpy(out.key, parent.key, 32);
    sodium_memzero(i, sizeof(i));
    return true;
  }
  if (secp256k1_ec_seckey_verify(context(), il) != 1) {
    // IL >= n: invalid per BIP-32, caller retries the next index.
    sodium_memzero(i, sizeof(i));
    return false;
  }

  std::memcpy(out.key, parent.key, 32);
  const bool ok = secp256k1_ec_seckey_tweak_add(context(), out.key, il) == 1;
  sodium_memzero(i, sizeof(i));
  if (!ok) {
    // Resulting key is zero: invalid per BIP-32, caller retries.
    sodium_memzero(out.key, sizeof(out.key));
    return false;
  }
  return true;
}

void derive_path(const key_pair& master, const std::uint32_t* path,
                 std::size_t n, key_pair& out) {
  key_pair current = master;
  for (std::size_t level = 0; level < n; ++level) {
    std::uint32_t index = path[level];
    key_pair next;
    while (!child_key(current, index, next)) {
      // BIP-32: proceed with the next value for i at this level.
      ++index;
      if (index == 0) {  // wrapped past 2^32-1
        throw std::runtime_error("BIP-32: no valid child at level");
      }
    }
    sodium_memzero(current.key, sizeof(current.key));
    current = next;
  }
  out = current;
  sodium_memzero(current.key, sizeof(current.key));
}

void compressed_pubkey(const std::uint8_t key[32], std::uint8_t out[33]) {
  secp256k1_pubkey pub;
  if (secp256k1_ec_pubkey_create(context(), &pub, key) != 1) {
    throw std::runtime_error("secp256k1: invalid private key");
  }
  std::size_t out_len = 33;
  if (secp256k1_ec_pubkey_serialize(context(), out, &out_len, &pub,
                                    SECP256K1_EC_COMPRESSED) != 1) {
    throw std::runtime_error("secp256k1: pubkey serialize failed");
  }
}

void uncompressed_pubkey(const std::uint8_t key[32], std::uint8_t out[65]) {
  secp256k1_pubkey pub;
  if (secp256k1_ec_pubkey_create(context(), &pub, key) != 1) {
    throw std::runtime_error("secp256k1: invalid private key");
  }
  std::size_t out_len = 65;
  if (secp256k1_ec_pubkey_serialize(context(), out, &out_len, &pub,
                                    SECP256K1_EC_UNCOMPRESSED) != 1) {
    throw std::runtime_error("secp256k1: pubkey serialize failed");
  }
}

void fingerprint(const std::uint8_t key[32], std::uint8_t out[4]) {
  std::uint8_t pub[33];
  compressed_pubkey(key, pub);
  std::uint8_t h1[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(h1, pub, sizeof(pub));
  std::uint8_t h2[20];
  crypto::ripemd160(h2, h1, sizeof(h1));
  std::memcpy(out, h2, 4);
  sodium_memzero(pub, sizeof(pub));
  sodium_memzero(h1, sizeof(h1));
  sodium_memzero(h2, sizeof(h2));
}

}  // namespace bip32
