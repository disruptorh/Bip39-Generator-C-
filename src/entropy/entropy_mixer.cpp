#include "entropy/entropy_mixer.hpp"

#include <cassert>
#include <cstring>
#include <stdexcept>

namespace entropy {

secure_mem::byte_buffer random_bytes(std::size_t n) {
  secure_mem::byte_buffer out(n);
  randombytes_buf(out.data(), out.size());
  return out;
}

secure_mem::byte_buffer mix(const std::uint8_t* os_entropy, std::size_t os_len,
                            const char* user, std::size_t user_len,
                            std::size_t out_len) {
  assert(os_entropy != nullptr || os_len == 0);
  assert(user != nullptr || user_len == 0);
  secure_mem::byte_buffer ikm(os_len + user_len);
  if (os_len != 0) std::memcpy(ikm.data(), os_entropy, os_len);
  if (user_len != 0) std::memcpy(ikm.data() + os_len, user, user_len);

  std::uint8_t prk[crypto_kdf_hkdf_sha512_KEYBYTES];
  const std::size_t salt_len = sizeof(kHkdfSalt) - 1;
  const std::size_t info_len = sizeof(kHkdfInfo) - 1;

  if (crypto_kdf_hkdf_sha512_extract(
          prk, reinterpret_cast<const std::uint8_t*>(kHkdfSalt), salt_len,
          ikm.data(), ikm.size()) != 0) {
    sodium_memzero(prk, sizeof(prk));
    throw std::runtime_error("HKDF-SHA512 extract failed");
  }

  secure_mem::byte_buffer out(out_len);
  if (crypto_kdf_hkdf_sha512_expand(
          out.data(), out.size(), kHkdfInfo, info_len, prk) != 0) {
    sodium_memzero(prk, sizeof(prk));
    throw std::runtime_error("HKDF-SHA512 expand failed");
  }

  sodium_memzero(prk, sizeof(prk));
  return out;
}

secure_mem::byte_buffer mix(const secure_mem::byte_buffer& os_entropy,
                            const char* user, std::size_t user_len,
                            std::size_t out_len) {
  return mix(os_entropy.data(), os_entropy.size(), user, user_len, out_len);
}

}  // namespace entropy
