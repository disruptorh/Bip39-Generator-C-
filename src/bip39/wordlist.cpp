#include "bip39/wordlist.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>

#include <unistd.h>

#include <sodium.h>

#include "bip39/wordlist_data.generated.hpp"

namespace bip39 {
namespace {

std::string sha256_hex(const std::uint8_t* data, std::size_t len) {
  std::uint8_t digest[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(digest, data, len);
  std::string hex;
  hex.reserve(sizeof(digest) * 2);
  const char* kHex = "0123456789abcdef";
  for (const std::uint8_t b : digest) {
    hex.push_back(kHex[b >> 4]);
    hex.push_back(kHex[b & 0x0f]);
  }
  sodium_memzero(digest, sizeof(digest));
  return hex;
}

std::string wordlist_search_path() {
  const char* env = std::getenv("BIP39_WORDLIST");
  if (env != nullptr && *env != '\0') return std::string(env);

  // Same directory as the running binary (single-binary deployment).
  char self[4096];
  const ssize_t n = ::readlink("/proc/self/exe", self, sizeof(self) - 1);
  if (n > 0) {
    self[n] = '\0';
    std::string exe(self);
    const std::size_t slash = exe.find_last_of('/');
    if (slash != std::string::npos) {
      return exe.substr(0, slash + 1) + "bip39.txt";
    }
  }
  return "bip39.txt";  // fall back to current working directory
}

void validate_words(const std::vector<std::string>& words) {
  if (words.size() != 2048) {
    throw std::runtime_error("wordlist: expected 2048 words, got " +
                             std::to_string(words.size()));
  }
  for (const std::string& w : words) {
    if (w.empty()) throw std::runtime_error("wordlist: empty word entry");
  }
  std::vector<std::string> sorted(words);
  std::sort(sorted.begin(), sorted.end());
  if (sorted != words) {
    throw std::runtime_error("wordlist: entries are not in sorted order");
  }
  if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end()) {
    throw std::runtime_error("wordlist: duplicate entries found");
  }
}

}  // namespace

wordlist wordlist::load(const char* external_path) {
  wordlist wl;
  if (external_path != nullptr && *external_path != '\0') {
    wl.load_file(external_path);
  } else {
    wl.load_embedded();
  }
  return wl;
}

std::string wordlist::default_path() { return wordlist_search_path(); }

void wordlist::load_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw std::runtime_error("wordlist: cannot open " + path);

  std::ostringstream ss;
  ss << in.rdbuf();
  const std::string raw = ss.str();
  if (raw.empty()) throw std::runtime_error("wordlist: empty file " + path);

  const std::string actual_hex = sha256_hex(
      reinterpret_cast<const std::uint8_t*>(raw.data()), raw.size());
  if (actual_hex != detail::kEmbeddedHashHex) {
    throw std::runtime_error("wordlist: SHA-256 mismatch for " + path);
  }

  std::vector<std::string> words;
  std::istringstream lines(raw);
  std::string line;
  while (std::getline(lines, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    words.push_back(line);
  }
  validate_words(words);

  words_ = std::move(words);
  expected_hash_hex_ = detail::kEmbeddedHashHex;
  from_embedded_ = false;
}

void wordlist::load_embedded() {
  words_.clear();
  words_.reserve(detail::kEmbeddedWordCount);
  for (std::size_t i = 0; i < detail::kEmbeddedWordCount; ++i) {
    words_.emplace_back(detail::kEmbeddedWords[i]);
  }
  validate_words(words_);
  expected_hash_hex_ = detail::kEmbeddedHashHex;
  from_embedded_ = true;
}

const std::string& wordlist::word(std::size_t index) const {
  if (index >= words_.size()) {
    throw std::out_of_range("wordlist: index out of range");
  }
  return words_[index];
}

}  // namespace bip39
