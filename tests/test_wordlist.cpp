#include <cstdio>
#include <fstream>
#include <set>
#include <sstream>
#include <string>

#include <sodium.h>

#include "bip39/wordlist.hpp"
#include "test_util.hpp"

namespace {

std::string file_sha256(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  std::ostringstream ss;
  ss << in.rdbuf();
  const std::string raw = ss.str();
  std::uint8_t digest[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(digest, reinterpret_cast<const std::uint8_t*>(raw.data()),
                     raw.size());
  return test_util::to_hex(digest, sizeof(digest));
}

}  // namespace

TEST(wordlist_embedded_is_complete_and_sorted) {
  const bip39::wordlist& wl = bip39::wordlist::load();
  CHECK(wl.size() == 2048);
  CHECK(wl.from_embedded());
  for (std::size_t i = 0; i < wl.size(); ++i) {
    CHECK(!wl.word(i).empty());
    if (i > 0) CHECK(wl.word(i - 1) < wl.word(i));  // strictly sorted
  }
  // Embedded hash must match the canonical bip39.txt shipped in the repo.
  const std::string hash = file_sha256(
      std::string(WORDSLIST_PATH) + "/bip39.txt");
  CHECK(hash == wl.expected_hash_hex());
}

TEST(wordlist_external_file_verified_and_loaded) {
  // Point the loader directly at the repo's bip39.txt: it must pass the
  // embedded SHA-256 verification and load from the file.
  const bip39::wordlist& wl = bip39::wordlist::load(
      (std::string(WORDSLIST_PATH) + "/bip39.txt").c_str());
  CHECK(!wl.from_embedded());
  CHECK(wl.size() == 2048);
  CHECK(wl.word(0) == "abandon");
  CHECK(wl.word(2047) == "zoo");
}

TEST(wordlist_tampered_file_rejected) {
  // A tampered file must fail verification with an exception; the caller
  // decides whether to fall back to the embedded copy.
  const char* path = "/tmp/bip39_tampered_test.txt";
  {
    std::ofstream out(path, std::ios::trunc);
    out << "not-a-real-wordlist\n";
  }
  bool threw = false;
  try {
    (void)bip39::wordlist::load(path);
  } catch (const std::runtime_error&) {
    threw = true;
  }
  CHECK(threw);
  std::remove(path);
}
