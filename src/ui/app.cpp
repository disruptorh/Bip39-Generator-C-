#include "ui/app.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <vector>

#include "address/addresses.hpp"
#include "bip39/mnemonic.hpp"
#include "crypto/seed_transformer.hpp"
#include "entropy/entropy_estimator.hpp"
#include "entropy/entropy_mixer.hpp"
#include "export/batch_export.hpp"

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
  batch_password_.resize(kBatchInputCapacity);
  export_dir_.resize(kExportPathCapacity);
  export_name_.resize(kExportPathCapacity);
  // Default destination: the user's home directory.
  if (const char* home = std::getenv("HOME");
      home != nullptr && home[0] != '\0') {
    std::snprintf(export_dir_.data(), kExportPathCapacity, "%s", home);
  }
  sync_default_export_name();
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
  batch_password_.release_and_zero();
  export_dir_.release_and_zero();
  export_name_.release_and_zero();
  user_len_ = 0;
  addresses_.evm.clear();
  addresses_.btc.clear();
  batch_export::wipe(export_status_);
}

void app::frame() {
  const std::uint64_t now = now_ms();
  clipboard_.poll(now);
  poll_copies(now);
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
        os_entropy, user_input_.data(), user_len_, bytes);
    os_entropy.release_and_zero();  // OS entropy consumed by the HKDF extractor

    mnemonic_ = bip39::entropy_to_mnemonic(mixed.data(), mixed.size(), wl_);
    entropy_final_ = std::move(mixed);

    // Derive the EVM/BTC addresses for the revealed seed right away so the
    // reveal screen never triggers a slow/blocking operation. The secure_string
    // overload enforces that the mnemonic is derived from mlock'ed memory.
    addresses_ = address::derive_from_mnemonic(mnemonic_);

    // The user's contribution has been mixed in; wipe it immediately.
    user_input_.zero();
    user_len_ = 0;

    last_error_.clear();
    screen_ = screen::reveal;
  } catch (const std::exception& e) {
    last_error_ = e.what();
  }
}

void app::sync_default_export_name() {
  if (export_name_custom_) return;
  const std::string name = batch_export::default_filename(batch_count_);
  std::snprintf(export_name_.data(), kExportPathCapacity, "%s", name.c_str());
}

// Batch export: generate `batch_count_` seeds, obfuscate each one with the
// user's password (legacy XOR-with-derived-key, as BIP-39 Obfuscator does) and
// write the obfuscated mnemonic plus its derived addresses to a .txt file.
//
// Memory discipline: the plaintext mnemonic and the raw entropy of each seed
// are wiped as soon as the obfuscated form exists, so at most one plaintext
// seed is ever resident. The obfuscated seeds themselves live in ordinary
// heap strings because they are the payload being written to a plaintext file;
// they are wiped once the file is on disk.
void app::generate_batch() {
  const std::size_t bytes =
      word_count_24_ ? entropy::kEntropy24Words : entropy::kEntropy12Words;
  guaranteed_bits_ = bytes * 8;

  const char* dir_raw = export_dir_.data();
  const char* name_raw = export_name_.data();
  const char* password = batch_password_.data();
  const std::string dir = (dir_raw != nullptr) ? dir_raw : "";
  const std::string name = (name_raw != nullptr) ? name_raw : "";

  if (password == nullptr || password[0] == '\0') {
    last_error_ = "Escribe la contrasena con la que se obfuscaran las semillas.";
    return;
  }
  const std::string invalid =
      batch_export::validate(batch_count_, dir, name);
  if (!invalid.empty()) {
    last_error_ = invalid;
    return;
  }

  const std::string path = batch_export::join_path(dir, name);
  if (batch_export::file_exists(path) && !export_overwrite_pending_) {
    // Never clobber a previous export silently: demand a second, explicit
    // confirmation from the user.
    export_overwrite_pending_ = true;
    last_error_ = "El archivo '" + name +
                  "' ya existe en esa carpeta. Vuelve a pulsar el boton para "
                  "sobrescribirlo.";
    return;
  }
  export_overwrite_pending_ = false;
  export_status_.clear();

  std::vector<batch_export::entry> entries;
  std::string content;
  try {
    entries.reserve(static_cast<std::size_t>(batch_count_));
    for (int i = 0; i < batch_count_; ++i) {
      secure_mem::byte_buffer os_entropy = entropy::random_bytes(bytes);
      secure_mem::byte_buffer mixed = entropy::mix(
          os_entropy, user_input_.data(), user_len_, bytes);
      os_entropy.release_and_zero();

      secure_mem::secure_string plain =
          bip39::entropy_to_mnemonic(mixed.data(), mixed.size(), wl_);
      mixed.release_and_zero();

      // Addresses belong to the REAL seed: the one the user recovers by
      // de-obfuscating with the password. Those are the addresses the wallet
      // will show once the recovered seed is imported. Only the mnemonic that
      // goes into the file is obfuscated.
      const address::addresses addr = address::derive_from_mnemonic(plain);

      crypto::TransformParams params;
      params.seed_phrase = plain.c_str();
      params.secret = password;
      params.kdf_version = crypto::KdfVersion::V1_SHA256;
      secure_mem::secure_string obfuscated =
          crypto::transform_seed(params, wl_);
      plain.wipe();  // Plaintext no longer needed.

      entries.push_back({std::string(obfuscated.c_str()), addr.evm, addr.btc});
      obfuscated.wipe();
    }

    batch_export::report_meta meta;
    meta.word_count = word_count_24_ ? 24U : 12U;
    meta.entropy_bits = bytes * 8;
    meta.timestamp_utc = batch_export::utc_timestamp();
    content = batch_export::render(entries, meta);
    batch_export::write_atomic(path, content);

    export_status_ = std::to_string(batch_count_) +
                     (batch_count_ == 1 ? " semilla exportada a "
                                         : " semillas exportadas a ") +
                     path;
    last_error_.clear();
  } catch (const std::exception& e) {
    last_error_ = std::string("No se pudo exportar: ") + e.what();
  }

  batch_export::wipe(content);
  for (batch_export::entry& item : entries) {
    batch_export::wipe(item.seed);
    item.evm.clear();
    item.btc.clear();
  }
  // The user's contribution has been mixed into every seed of the batch.
  user_input_.zero();
  user_len_ = 0;
}

void app::reset() {
  clipboard_.clear_now();
  mnemonic_.wipe();
  entropy_final_.release_and_zero();
  user_input_.zero();
  user_len_ = 0;
  user_estimate_bits_ = 0.0;
  addresses_.evm.clear();
  addresses_.btc.clear();
  copy_mnemonic_.active = false;
  copy_evm_.active = false;
  copy_btc_.active = false;
  last_error_.clear();
  screen_ = screen::config;
}

void app::begin_copy(copy_state& target, const char* text, std::size_t len,
                     std::uint64_t now) {
  // The secure clipboard holds exactly one value; only the latest copy is
  // shown as active so the indicator never lies about what is stored.
  copy_mnemonic_.active = false;
  copy_evm_.active = false;
  copy_btc_.active = false;
  last_error_.clear();
  clipboard_.set_text(text, len);
  if (clipboard_.is_active()) {
    target.active = true;
    target.expires_at_ms = now + clipboard_.timeout_ms();
  } else {
    last_error_ = "No hay servidor X; no se pudo copiar.";
  }
}

void app::poll_copies(std::uint64_t now) {
  copy_state* items[] = {&copy_mnemonic_, &copy_evm_, &copy_btc_};
  for (copy_state* item : items) {
    if (item->active && now >= item->expires_at_ms) item->active = false;
  }
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

    ImGui::Separator();
    ImGui::TextUnformatted("Wordlist:");
    if (wl_.from_embedded()) {
      ImGui::TextDisabled("  embebida en el binario (SHA-256 verificada)");
    } else {
      ImGui::TextColored(ImVec4(0.55f, 0.85f, 0.55f, 1.0f),
                         "  externa (SHA-256 verificada)");
    }
  }
  ImGui::EndChild();
}

}  // namespace ui
