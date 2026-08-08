#include <cstdlib>
#include <cstring>
#include <new>
#include <vector>

#include "secure_mem/secure_buffer.hpp"
#include "test_util.hpp"

namespace {

// Deterministic destructor check: intercept the single heap allocation of a
// secure buffer and verify, at the moment it is freed, that the bytes have
// been zeroed. This avoids reading freed memory.
struct free_zero_check {
  std::size_t watch_bytes = 0;
  bool watching = false;
  bool active = false;
  void* captured = nullptr;
  bool observed = false;
  int nonzero_at_free = -1;
} g_check;

}  // namespace

void* operator new[](std::size_t n) {
  void* p = std::malloc(n);
  if (p == nullptr) throw std::bad_alloc();
  if (g_check.watching && n == g_check.watch_bytes && g_check.captured == nullptr) {
    g_check.captured = p;
  }
  return p;
}

void operator delete[](void* p) noexcept {
  if (g_check.active && p == g_check.captured) {
    int nonzero = 0;
    auto* bytes = static_cast<unsigned char*>(p);
    for (std::size_t i = 0; i < g_check.watch_bytes; ++i) {
      if (bytes[i] != 0) ++nonzero;
    }
    g_check.nonzero_at_free = nonzero;
    g_check.observed = true;
  }
  std::free(p);
}

void operator delete[](void* p, std::size_t) noexcept { operator delete[](p); }

TEST(secure_buffer_zeroizes_on_destroy) {
  constexpr std::size_t kBytes = 512;
  g_check.watch_bytes = kBytes;
  g_check.watching = true;
  g_check.active = true;
  {
    secure_mem::buffer<char> buf(kBytes);
    std::memset(buf.data(), 0xAB, kBytes);
  }
  g_check.watching = false;
  g_check.active = false;
  CHECK(g_check.captured != nullptr);
  CHECK(g_check.observed);
  CHECK(g_check.nonzero_at_free == 0);
  g_check.captured = nullptr;
  g_check.observed = false;
}

TEST(secure_buffer_clear_zeroizes_in_place) {
  secure_mem::buffer<char> buf(64);
  std::memset(buf.data(), 0x5A, 64);
  buf.zero();
  for (std::size_t i = 0; i < 64; ++i) CHECK(buf.data()[i] == 0);
}

TEST(secure_buffer_move_transfers_ownership) {
  secure_mem::buffer<char> a(32);
  std::memset(a.data(), 0x11, 32);
  char* raw = a.data();
  secure_mem::buffer<char> b = std::move(a);
  CHECK(b.data() == raw);
  CHECK(b.size() == 32);
  CHECK(a.empty());
  CHECK(a.data() == nullptr);
}

TEST(secure_buffer_resize_preserve) {
  secure_mem::buffer<std::uint8_t> buf(16);
  for (std::size_t i = 0; i < 16; ++i) buf.data()[i] = static_cast<std::uint8_t>(i);
  buf.resize(32, /*preserve=*/true);
  for (std::size_t i = 0; i < 16; ++i) CHECK(buf.data()[i] == i);
}

TEST(secure_string_roundtrip_and_wipe) {
  {
    secure_mem::secure_string s;
    s.assign("hello world", 11);
    CHECK(std::string(s.c_str()) == "hello world");
    CHECK(s.size() == 11);
    s.append("!", 1);
    CHECK(std::string(s.c_str()) == "hello world!");
    CHECK(s.size() == 12);
    s.clear();
    CHECK(s.empty());
  }
  {
    // Growth must preserve content and remain zeroable on wipe.
    secure_mem::secure_string s;
    for (int i = 0; i < 5000; ++i) s.append("a", 1);
    CHECK(s.size() == 5000);
    const char* p = s.data();
    s.wipe();
    CHECK(s.empty());
    for (int i = 0; i < 5000; ++i) CHECK(p[i] == 0);
  }
}

TEST(secure_string_move_transfers_buffer) {
  secure_mem::secure_string a;
  a.assign("secret", 6);
  const char* raw = a.data();
  secure_mem::secure_string b = std::move(a);
  CHECK(b.data() == raw);
  CHECK(b.size() == 6);
  CHECK(a.empty());
}
