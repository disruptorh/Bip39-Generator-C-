#include <cstring>

#include "entropy/entropy_mixer.hpp"
#include "secure_mem/secure_buffer.hpp"
#include "test_util.hpp"

namespace {

// Independently computed reference outputs (Python standard-library HKDF
// implementation), hardcoded to guard the C++ implementation.
//   ikm  = "test-os-entropy-0123456789abcdef"
//   salt = entropy::kHkdfSalt ("bip39-app-salt-fixed-0001")
//   info = entropy::kHkdfInfo ("bip39-entropy-v1")
const char* kIkm = "test-os-entropy-0123456789abcdef";
const std::size_t kIkmLen = 32;

const char* kRefOut16 =
    "f4817badc3dda24098f41f673f4ec9e1";
const char* kRefOut32 =
    "f4817badc3dda24098f41f673f4ec9e17dcfc47f2eb413c112a57b77821018be";
const char* kRefUserPassOut32 =
    "92e315267198dfdfcd974ff63dfb8a5b3b81077c80e9f5d511572f2a4a6a5122";

secure_mem::byte_buffer mix_with_user(const char* user, std::size_t out_len = 32) {
  return entropy::mix(reinterpret_cast<const std::uint8_t*>(kIkm), kIkmLen,
                      user, (user != nullptr) ? std::strlen(user) : 0, out_len);
}

}  // namespace

TEST(hkdf_reference_16_bytes) {
  auto out = mix_with_user(nullptr, 16);
  CHECK(out.size() == 16);
  CHECK(test_util::to_hex(out.data(), out.size()) == kRefOut16);
}

TEST(hkdf_reference_32_bytes) {
  auto out = mix_with_user(nullptr, 32);
  CHECK(out.size() == 32);
  CHECK(test_util::to_hex(out.data(), out.size()) == kRefOut32);
}

TEST(hkdf_user_input_extends_ikm) {
  auto with_user = mix_with_user("pass");
  CHECK(test_util::to_hex(with_user.data(), with_user.size()) ==
        kRefUserPassOut32);
  auto empty = mix_with_user(nullptr);
  CHECK(!std::memcmp(with_user.data(), empty.data(), 32) == 0);
}

TEST(hkdf_is_deterministic) {
  auto a = mix_with_user(nullptr);
  auto b = mix_with_user(nullptr);
  CHECK(std::memcmp(a.data(), b.data(), 32) == 0);
}

TEST(mix_is_avalanche_sensitive_to_os_input) {
  const std::uint8_t os_a[32] = {1};
  const std::uint8_t os_b[32] = {2};
  auto a = entropy::mix(os_a, sizeof(os_a), nullptr, 0, 32);
  auto b = entropy::mix(os_b, sizeof(os_b), nullptr, 0, 32);
  std::size_t differing = 0;
  for (std::size_t i = 0; i < 32; ++i) differing += (a.data()[i] != b.data()[i]);
  CHECK(differing > 8);  // far from identical under any sane hash
}

TEST(random_bytes_differ_and_are_nonzero_distributed) {
  auto a = entropy::random_bytes(32);
  auto b = entropy::random_bytes(32);
  CHECK(a.size() == 32);
  std::size_t differing = 0;
  for (std::size_t i = 0; i < 32; ++i) differing += (a.data()[i] != b.data()[i]);
  CHECK(differing > 8);
}
