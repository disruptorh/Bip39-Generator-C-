#ifndef BIP39_BIP39_WORDLIST_HPP_
#define BIP39_BIP39_WORDLIST_HPP_

#include <cstddef>
#include <string>
#include <vector>

namespace bip39 {

// BIP-39 wordlist: loaded from an optional external file (verified against an
// embedded SHA-256 digest) or from an embedded copy compiled into the binary.
// The class is stateless after construction; it owns a plain (non-secret)
// read-only list of 2048 words.
class wordlist {
 public:
  // Constructs a wordlist from `external_path`. When `external_path` is null
  // the embedded copy is used. When provided, the file MUST verify against the
  // embedded SHA-256 digest or a std::runtime_error is thrown. Never silently
  // falls back: callers decide whether to fall back to the embedded copy.
  static wordlist load(const char* external_path = nullptr);

  // Path the app should try before falling back to the embedded copy.
  static std::string default_path();

  const std::string& word(std::size_t index) const;
  std::size_t size() const { return words_.size(); }

  // SHA-256 (hex, lowercase) of the canonical bip39.txt bytes this build was
  // generated against.
  const std::string& expected_hash_hex() const { return expected_hash_hex_; }

  // True when the active wordlist came from the embedded copy (single-binary
  // operation), false when it was verified from an external file.
  bool from_embedded() const { return from_embedded_; }

 private:
  void load_file(const std::string& path);
  void load_embedded();

  std::vector<std::string> words_;
  std::string expected_hash_hex_;
  bool from_embedded_ = true;
};

}  // namespace bip39

#endif  // BIP39_BIP39_WORDLIST_HPP_
