#include "ui/app.hpp"

#include <chrono>

#include <imgui.h>

#include "entropy/entropy_estimator.hpp"
#include "entropy/entropy_mixer.hpp"

namespace ui {

namespace {
std::uint64_t now_ms_ui() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}
}  // namespace

// Screen 2: revealed mnemonic + copy-with-auto-clear + wipe-and-restart.
void app::render_reveal_screen() {
  const std::uint64_t now = now_ms_ui();
  if (copied_ && now >= copy_expires_at_ms_) {
    clipboard_.clear_now();
    copied_ = false;
  }

  ImGui::SetNextWindowSize(ImVec2(760, 560), ImGuiCond_FirstUseEver);
  ImGui::SetNextWindowPos(ImVec2(40, 40), ImGuiCond_FirstUseEver);

  if (ImGui::Begin("BIP-39 Seedphrase Generator - Semilla generada", nullptr,
                   ImGuiWindowFlags_NoCollapse)) {
    ImGui::TextWrapped(
        "Anota esta semilla en papel. Se limpiara de la memoria al cerrar la "
        "aplicacion o generar una nueva semilla.");
    ImGui::Separator();
    ImGui::Spacing();

    const std::size_t word_count = word_count_24_ ? 24U : 12U;
    ImGui::Text("Tu semilla (%zu palabras):", word_count);
    ImGui::Spacing();

    if (ImGui::BeginChild("mnemonic_box", ImVec2(0, 110),
                          ImGuiChildFlags_Border)) {
      ImGui::TextWrapped("%s", mnemonic_.c_str());
    }
    ImGui::EndChild();

    ImGui::Spacing();
    ImGui::Spacing();

    if (ImGui::Button("Copiar al portapapeles (auto-limpieza)",
                      ImVec2(320, 0))) {
      clipboard_.set_text(mnemonic_.c_str(), mnemonic_.size());
      copied_ = clipboard_.is_active();
      copy_expires_at_ms_ = now + clipboard_.timeout_ms();
      if (!copied_) last_error_ =
                         "No hay servidor X; no se pudo copiar.";
    }
    ImGui::SameLine();
    if (ImGui::Button("Nueva semilla", ImVec2(320, 0))) {
      reset();
    }

    if (copied_) {
      const std::uint64_t remaining =
          (copy_expires_at_ms_ > now) ? (copy_expires_at_ms_ - now) : 0;
      ImGui::TextColored(ImVec4(0.92f, 0.72f, 0.25f, 1.0f),
                         "Copiado. El portapapeles se limpiara en %llu s.",
                         static_cast<unsigned long long>(remaining / 1000 + 1));
    } else if (!last_error_.empty()) {
      ImGui::TextColored(ImVec4(0.95f, 0.35f, 0.35f, 1.0f), "%s",
                         last_error_.c_str());
    }

    ImGui::Spacing();
    ImGui::Spacing();
    if (ImGui::BeginChild("meter_container", ImVec2(0, 0), true)) {
      render_entropy_meter();
    }
    ImGui::EndChild();
  }
  ImGui::End();
}

}  // namespace ui
