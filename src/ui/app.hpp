#ifndef BIP39_UI_APP_HPP_
#define BIP39_UI_APP_HPP_

#include <cstddef>
#include <cstdint>
#include <string>

#include "bip39/wordlist.hpp"
#include "clipboard/secure_clipboard.hpp"
#include "secure_mem/secure_buffer.hpp"

namespace ui {

// Global application state. All sensitive material lives in mlock'ed,
// auto-zeroed secure buffers; the destructor and reset() wipe everything.
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

  // Shared state (used by the screen implementations).
  bool word_count_24_ = false;
  secure_mem::buffer<char> user_input_;  // NUL-terminated editing buffer
  std::size_t user_len_ = 0;
  secure_mem::secure_string mnemonic_;
  secure_mem::byte_buffer entropy_final_;
  std::size_t guaranteed_bits_ = 128;
  double user_estimate_bits_ = 0.0;
  bool copied_ = false;
  std::uint64_t copy_expires_at_ms_ = 0;
  std::string last_error_;
  bip39::wordlist wl_;
  clipboard::secure_clipboard clipboard_;

  static constexpr std::size_t kUserInputCapacity = 4096;
  static constexpr std::uint64_t kClipboardTimeoutMs =
      clipboard::secure_clipboard::kDefaultTimeoutMs;

 private:
  enum class screen { config, reveal };
  screen screen_ = screen::config;

  void render_config_screen();
  void render_reveal_screen();
  void render_entropy_meter() const;
  void update_estimate();
  void generate();
  void reset();
};

}  // namespace ui

#endif  // BIP39_UI_APP_HPP_
