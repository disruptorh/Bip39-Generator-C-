#ifndef BIP39_UI_APP_HPP_
#define BIP39_UI_APP_HPP_

#include <cstddef>
#include <cstdint>
#include <string>

#include "address/addresses.hpp"
#include "bip39/wordlist.hpp"
#include "clipboard/secure_clipboard.hpp"
#include "secure_mem/secure_buffer.hpp"

namespace ui {

// Global application state. All sensitive material lives in mlock'ed,
// auto-zeroed secure buffers; the destructor and reset() wipe everything.
// All shared state is private and only reachable through the narrow public
// interface (init/shutdown/frame) and the member functions that render the
// screens.
class app {
 public:
  app() = default;
  ~app();

  app(const app&) = delete;
  app& operator=(const app&) = delete;

  // Load the wordlist and initialize the clipboard. Returns false on failure.
  bool init();
  void shutdown();

  // Render one frame of the active screen.
  void frame();

  // Last error message from the most recent operation (empty on success).
  const std::string& last_error() const { return last_error_; }

 private:
  enum class screen { config, reveal };
  screen screen_ = screen::config;

  // Shared state (used by the screen implementations).
  bool word_count_24_ = false;
  secure_mem::buffer<char> user_input_;  // NUL-terminated editing buffer
  std::size_t user_len_ = 0;
  secure_mem::secure_string mnemonic_;
  secure_mem::byte_buffer entropy_final_;
  std::size_t guaranteed_bits_ = 128;
  double user_estimate_bits_ = 0.0;
  std::string last_error_;
  bip39::wordlist wl_;
  clipboard::secure_clipboard clipboard_;

  // Addresses derived from the revealed mnemonic (BIP-44 account 0 / index 0).
  address::addresses addresses_;

  // Per-field copy indicator: only the last copied value is shown as active,
  // matching the single-slot clipboard.
  struct copy_state {
    bool active = false;
    std::uint64_t expires_at_ms = 0;
  };
  copy_state copy_mnemonic_;
  copy_state copy_evm_;
  copy_state copy_btc_;

  static constexpr std::size_t kUserInputCapacity = 4096;
  static constexpr std::uint64_t kClipboardTimeoutMs =
      clipboard::secure_clipboard::kDefaultTimeoutMs;

  void render_config_screen();
  void render_reveal_screen();
  void render_entropy_meter() const;
  void render_copy_status(copy_state& item, std::uint64_t now);
  void render_address_field(const char* label, const std::string& value,
                            copy_state& item, std::uint64_t now);
  void begin_copy(copy_state& target, const char* text, std::size_t len,
                  std::uint64_t now);
  void poll_copies(std::uint64_t now);
  void update_estimate();
  void generate();
  void reset();
};

}  // namespace ui

#endif  // BIP39_UI_APP_HPP_
