#ifndef BIP39_EXPORT_BATCH_EXPORT_HPP_
#define BIP39_EXPORT_BATCH_EXPORT_HPP_

#include <cstddef>
#include <string>
#include <vector>

namespace batch_export {

// Upper bound on a single batch. Keeps one frame's work bounded: every seed
// needs a full PBKDF2-HMAC-SHA512 seed derivation for its two addresses.
constexpr int kMinSeeds = 1;
constexpr int kMaxSeeds = 1000;

// One exported record: the obfuscated mnemonic plus the addresses derived from
// the REAL (de-obfuscated) seed (account 0 / index 0), i.e. the addresses the
// user will actually see once the seed is recovered. Only `seed` is obfuscated.
struct entry {
  std::string seed;  // Obfuscated mnemonic, space separated
  std::string evm;
  std::string btc;
};

// Header fields of the exported report.
struct report_meta {
  std::size_t word_count = 12;
  std::size_t entropy_bits = 128;
  std::string kdf_label = "V1 SHA-256 (modo legacy)";
  std::string timestamp_utc;
};

// Default file name for a batch of `seed_count` seeds: "6seeds.txt".
std::string default_filename(int seed_count);

// Checks the destination the user typed. Returns an empty string when the
// export may proceed, otherwise a human-readable Spanish error message.
std::string validate(int seed_count, const std::string& directory,
                     const std::string& filename);

// Joins directory and filename with a single '/'. No normalisation: the
// directory is used exactly as typed so the user can see what was written.
std::string join_path(const std::string& directory,
                      const std::string& filename);

bool file_exists(const std::string& path);

// Renders the full .txt body. Pure: no I/O, so the layout is unit-testable.
std::string render(const std::vector<entry>& entries, const report_meta& meta);

// Writes `content` to `path` atomically: a sibling "<path>.tmp" is written,
// flushed and then renamed over the target, so an interrupted export never
// leaves a half-written report behind. Throws std::runtime_error on failure
// and removes the temporary file.
void write_atomic(const std::string& path, const std::string& content);

// Overwrites a std::string's bytes before releasing them. std::string gives no
// guarantee about where the allocator put the data, so this is best-effort;
// it is still strictly better than letting seed material sit in freed heap.
void wipe(std::string& value);

// Current UTC time as "YYYY-MM-DD HH:MM:SS" (no timezone database needed).
std::string utc_timestamp();

}  // namespace batch_export

#endif  // BIP39_EXPORT_BATCH_EXPORT_HPP_