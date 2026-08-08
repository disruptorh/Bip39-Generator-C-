#ifndef BIP39_TESTS_TEST_UTIL_HPP_
#define BIP39_TESTS_TEST_UTIL_HPP_

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace test_util {

struct test_case {
  std::string name;
  std::function<void()> fn;
};

inline std::vector<test_case>& registry() {
  static std::vector<test_case> r;
  return r;
}

struct registrar {
  registrar(const char* name, std::function<void()> fn) {
    registry().push_back({name, std::move(fn)});
  }
};

inline std::string to_hex(const std::uint8_t* data, std::size_t len) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (std::size_t i = 0; i < len; ++i) {
    out.push_back(kHex[data[i] >> 4]);
    out.push_back(kHex[data[i] & 0x0f]);
  }
  return out;
}

inline std::uint8_t hex_nibble(char c) {
  if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
  if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
  if (c >= 'A' && c <= 'F') return static_cast<std::uint8_t>(c - 'A' + 10);
  throw std::runtime_error("invalid hex digit");
}

inline std::vector<std::uint8_t> from_hex(const std::string& hex) {
  if (hex.size() % 2 != 0) throw std::runtime_error("odd hex length");
  std::vector<std::uint8_t> out(hex.size() / 2);
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<std::uint8_t>((hex_nibble(hex[2 * i]) << 4) |
                                       hex_nibble(hex[2 * i + 1]));
  }
  return out;
}

}  // namespace test_util

#define TEST(name)                                                     \
  static void test_##name();                                           \
  static ::test_util::registrar reg_##name(                            \
      #name, &test_##name);                                            \
  static void test_##name()

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond))                                                             \
      throw std::runtime_error(std::string("CHECK failed [" #cond "] at ") + \
                               __FILE__ + ":" + std::to_string(__LINE__));  \
  } while (0)

#define CHECK_EQ(a, b)                                                       \
  do {                                                                       \
    const auto va = (a);                                                     \
    const auto vb = (b);                                                     \
    if (!(va == vb))                                                         \
      throw std::runtime_error(std::string("CHECK_EQ failed [") +            \
                               std::to_string(va) + " != " +                 \
                               std::to_string(vb) + "] at " + __FILE__ +     \
                               ":" + std::to_string(__LINE__));              \
  } while (0)

#endif  // BIP39_TESTS_TEST_UTIL_HPP_
