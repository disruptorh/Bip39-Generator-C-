#include "crypto/base58.hpp"

#include <cstdlib>
#include <cstring>
#include <new>

#include <sodium.h>

namespace crypto {
namespace {

constexpr char kAlphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

}  // namespace

std::string base58check(const std::uint8_t* payload, std::size_t len) {
  // Digest: payload || first 4 bytes of SHA256(SHA256(payload)).
  std::uint8_t digest[crypto_hash_sha256_BYTES];
  std::uint8_t checksum[4];
  crypto_hash_sha256(digest, payload, len);
  crypto_hash_sha256(digest, digest, crypto_hash_sha256_BYTES);
  std::memcpy(checksum, digest, sizeof(checksum));
  sodium_memzero(digest, sizeof(digest));

  const std::size_t total = len + sizeof(checksum);
  std::uint8_t* buf = static_cast<std::uint8_t*>(std::malloc(total));
  if (buf == nullptr) throw std::bad_alloc();
  std::memcpy(buf, payload, len);
  std::memcpy(buf + len, checksum, sizeof(checksum));
  sodium_memzero(checksum, sizeof(checksum));

  // Count leading zero bytes (they become leading '1's).
  std::size_t zeros = 0;
  while (zeros < total && buf[zeros] == 0) ++zeros;

  // Repeatedly divide the big number by 58, gathering remainders. buf is
  // big-endian, so the significant span is [first, total); after each pass
  // the quotient's leading zero bytes are skipped by advancing `first`.
  std::size_t first = zeros;
  std::string out;
  out.reserve(total * 138 / 100 + 1);
  while (first < total) {
    std::uint32_t rem = 0;
    for (std::size_t i = first; i < total; ++i) {
      const std::uint32_t acc = rem * 256 + buf[i];
      buf[i] = static_cast<std::uint8_t>(acc / 58);
      rem = acc % 58;
    }
    while (first < total && buf[first] == 0) ++first;
    out.push_back(kAlphabet[rem]);
  }
  out.append(zeros, '1');
  for (std::size_t i = 0, n = out.size(); i < n / 2; ++i) {
    std::swap(out[i], out[n - 1 - i]);
  }

  sodium_memzero(buf, total);
  std::free(buf);
  return out;
}

}  // namespace crypto
