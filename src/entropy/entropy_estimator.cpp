#include "entropy/entropy_estimator.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>

namespace entropy {

double estimate_user_entropy(const char* input, std::size_t len) {
  if (len == 0) return 0.0;

  static constexpr std::size_t kAlphabet = 256;
  std::array<std::uint64_t, kAlphabet> counts{};
  for (std::size_t i = 0; i < len; ++i) {
    counts[static_cast<unsigned char>(input[i])]++;
  }

  double shannon = 0.0;
  for (const std::uint64_t c : counts) {
    if (c == 0) continue;
    const double p = static_cast<double>(c) / static_cast<double>(len);
    shannon -= p * std::log2(p);
  }

  // Total heuristic = Shannon entropy per byte x length, clamped to a sane
  // ceiling: free text can never honestly claim more than ~256 bits.
  const double bits = shannon * static_cast<double>(len);
  return std::min(bits, 256.0);
}

security_level classify(std::size_t guaranteed_bits) {
  if (guaranteed_bits >= 128) return security_level::High;
  if (guaranteed_bits >= 80) return security_level::Medium;
  return security_level::Low;
}

const char* to_string(security_level level) {
  switch (level) {
    case security_level::Low:
      return "Bajo";
    case security_level::Medium:
      return "Medio";
    case security_level::High:
      return "Alto";
  }
  return "?";
}

}  // namespace entropy
