#include "ui/app.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <exception>

#include "bip39/mnemonic.hpp"
#include "entropy/entropy_estimator.hpp"
#include "entropy/entropy_mixer.hpp"

#include <imgui.h>

namespace ui {

namespace {
std::uint64_t now_ms() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}
}  // namespace

app::~app() { shutdown(); }

bool app::init() {
  try {
    // Prefer a verified external bip39.txt (SHA-256 checked against the
    // embedded digest); fall back to the embedded copy for single-binary use.
    wl_ = bip39::wordlist::load(bip39::wordlist::default_path().c_str());
  } catch (const std::exception&) {
    try {
      wl_ = bip39::wordlist::load(nullptr);
    } catch (const std::exception& e) {
      last_error_ = e.what();
      return false;
    }
  }
  user_input_.resize(kUserInputCapacity);
  if (!clipboard_.init()) {
    last_error_ = "No hay servidor X disponible; el portapapeles estará desactivado.";
  } else {
    // Optional auto-clear override (ms), e.g. for testing. Default 30 s.
    if (const char* env = std::getenv("BIP39_CLIPBOARD_TIMEOUT_MS")) {
      const long v = std::strtol(env, nullptr, 10);
      if (v > 0) clipboard_.set_timeout_ms(static_cast<std::uint64_t>(v));
    }
  }
  return true;
}

void app::shutdown() {
  clipboard_.shutdown();
  mnemonic_.wipe();
  entropy_final_.release_and_zero();
  user_input_.release_and_zero();
  user_len_ = 0;
}

void app::frame() {
  clipboard_.poll(now_ms());
  if (screen_ == screen::config) {
    render_config_screen();
  } else {
    render_reveal_screen();
  }
}

void app::update_estimate() {
  user_len_ = 0;
  const char* d = user_input_.data();
  if (d != nullptr) user_len_ = std::strlen(d);
  user_estimate_bits_ = entropy::estimate_user_entropy(d, user_len_);
}

void app::generate() {
  const std::size_t bytes =
      word_count_24_ ? entropy::kEntropy24Words : entropy::kEntropy12Words;
  guaranteed_bits_ = bytes * 8;
  update_estimate();

  try {
    secure_mem::byte_buffer os_entropy = entropy::random_bytes(bytes);

    secure_mem::byte_buffer mixed = entropy::mix(
        os_entropy.data(), os_entropy.size(), user_input_.data(), user_len_, bytes);
    os_entropy.release_and_zero();  // OS entropy consumed by the HKDF extractor

    mnemonic_ = bip39::entropy_to_mnemonic(mixed.data(), mixed.size(), wl_);
    entropy_final_ = std::move(mixed);

    // The user's contribution has been mixed in; wipe it immediately.
    user_input_.zero();
    user_len_ = 0;

    last_error_.clear();
    screen_ = screen::reveal;
  } catch (const std::exception& e) {
    last_error_ = e.what();
  }
}

void app::reset() {
  clipboard_.clear_now();
  mnemonic_.wipe();
  entropy_final_.release_and_zero();
  user_input_.zero();
  user_len_ = 0;
  user_estimate_bits_ = 0.0;
  copied_ = false;
  copy_expires_at_ms_ = 0;
  last_error_.clear();
  screen_ = screen::config;
}

void app::render_entropy_meter() const {
  if (ImGui::BeginChild("entropy_meter", ImVec2(0, 0), ImGuiChildFlags_Border)) {
    ImGui::TextUnformatted("Indicador de entropía");
    ImGui::Separator();

    const entropy::security_level level = entropy::classify(guaranteed_bits_);
    ImGui::TextUnformatted("Seguridad garantizada (CSPRNG del sistema operativo):");
    ImGui::TextColored(ImVec4(0.42f, 0.88f, 0.52f, 1.0f), "  %zu bits  -  Nivel: %s",
                       guaranteed_bits_, entropy::to_string(level));

    if (user_estimate_bits_ > 0.0) {
      ImGui::TextUnformatted("Aporte del usuario (ESTIMACIÓN, no garantizada):");
      ImGui::TextColored(ImVec4(0.92f, 0.72f, 0.25f, 1.0f), "  %.1f bits",
                         user_estimate_bits_);
    } else {
      ImGui::TextDisabled("Aporte del usuario: sin aporte adicional");
    }
  }
  ImGui::EndChild();
}

}  // namespace ui
