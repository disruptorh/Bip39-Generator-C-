#include <cstdio>
#include <cstdlib>

#include "test_util.hpp"

int main() {
  std::size_t failures = 0;
  for (const auto& tc : test_util::registry()) {
    try {
      tc.fn();
      std::printf("[PASS] %s\n", tc.name.c_str());
    } catch (const std::exception& e) {
      ++failures;
      std::printf("[FAIL] %s: %s\n", tc.name.c_str(), e.what());
    } catch (...) {
      ++failures;
      std::printf("[FAIL] %s: unknown exception\n", tc.name.c_str());
    }
  }
  std::printf("%zu tests, %zu failures\n", test_util::registry().size(),
              failures);
  return failures == 0 ? 0 : 1;
}
