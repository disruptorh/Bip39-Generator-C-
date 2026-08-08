#include "crypto/keccak256.hpp"

#include <cstring>

#include <sodium.h>

namespace crypto {
namespace {

constexpr std::size_t kRateBytes = 136;  // 1600 - 2 * 256 bits

// Rotation offsets rho[x][y] (lane x + 5y) from the Keccak specification.
constexpr int kRho[5][5] = {
    {0, 36, 3, 41, 18},
    {1, 44, 10, 45, 2},
    {62, 6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39, 8, 14}};

constexpr std::uint64_t kRoundConstants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

inline std::uint64_t rotl64(std::uint64_t x, int n) {
  const int m = n & 63;
  if (m == 0) return x;
  return (x << m) | (x >> (64 - m));
}

void keccak_f1600(std::uint64_t state[25]) {
  std::uint64_t c[5];
  std::uint64_t b[25];
  for (int round = 0; round < 24; ++round) {
    // theta
    for (int x = 0; x < 5; ++x) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^
             state[x + 20];
    }
    for (int x = 0; x < 5; ++x) {
      const std::uint64_t d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
      for (int y = 0; y < 5; ++y) state[x + 5 * y] ^= d;
    }
    // rho + pi: B[y][2x + 3y (mod 5)] = rot(A[x][y], rho[x][y])
    for (int x = 0; x < 5; ++x) {
      for (int y = 0; y < 5; ++y) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] =
            rotl64(state[x + 5 * y], kRho[x][y]);
      }
    }
    // chi
    for (int y = 0; y < 5; ++y) {
      for (int x = 0; x < 5; ++x) {
        state[x + 5 * y] =
            b[x + 5 * y] ^
            ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y]);
      }
    }
    // iota
    state[0] ^= kRoundConstants[round];
  }
}

}  // namespace

void keccak256(std::uint8_t out[32], const std::uint8_t* data,
               std::size_t len) {
  std::uint64_t state[25];
  std::memset(state, 0, sizeof(state));

  std::uint8_t block[kRateBytes];
  const std::size_t full = len - (len % kRateBytes);
  for (std::size_t off = 0; off < full; off += kRateBytes) {
    for (std::size_t i = 0; i < kRateBytes; ++i) {
      const std::size_t lane = (off + i) / 8;
      const int shift = static_cast<int>((off + i) % 8) * 8;
      state[lane] ^= static_cast<std::uint64_t>(data[off + i]) << shift;
    }
    keccak_f1600(state);
  }

  const std::size_t rem = len - full;
  std::memset(block, 0, sizeof(block));
  std::memcpy(block, data + full, rem);
  block[rem] ^= 0x01;
  block[kRateBytes - 1] ^= 0x80;
  for (std::size_t i = 0; i < kRateBytes; ++i) {
    const std::size_t lane = i / 8;
    const int shift = static_cast<int>(i % 8) * 8;
    state[lane] ^= static_cast<std::uint64_t>(block[i]) << shift;
  }
  keccak_f1600(state);

  std::uint8_t* s = reinterpret_cast<std::uint8_t*>(state);
  std::memcpy(out, s, 32);
  sodium_memzero(state, sizeof(state));
}

}  // namespace crypto
