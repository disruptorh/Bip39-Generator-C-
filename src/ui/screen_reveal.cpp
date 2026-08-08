#include "ui/app.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

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

void app::render_copy_status(copy_state& item, std::uint64_t now) {
  if (!item.active) return;
  const std::uint64_t remaining =
      (item.expires_at_ms > now) ? (item.expires_at_ms - now) : 0;
  ImGui::TextColored(ImVec4(0.55f, 0.85f, 0.55f, 1.0f),
                     "Copiado. Se limpiara en %llu s.",
                     static_cast<unsigned long long>(remaining / 1000 + 1));
}

void app::render_address_field(const char* label, const std::string& value,
                               copy_state& item, std::uint64_t now) {
  ImGui::TextUnformatted(label);
  char buf[96] = {};
  if (!value.empty()) std::memcpy(buf, value.c_str(), value.size());
  const float avail_x = ImGui::GetContentRegionAvail().x;
  const float btn_w = std::max(96.0f, avail_x * 0.18f);
  ImGui::PushID(label);
  ImGui::SetNextItemWidth(avail_x - btn_w - ImGui::GetStyle().ItemSpacing.x);
  ImGui::InputText("##addr", buf, sizeof(buf),
                   ImGuiInputTextFlags_ReadOnly |
                       ImGuiInputTextFlags_AutoSelectAll);
  ImGui::SameLine();
  if (ImGui::Button("Copiar", ImVec2(btn_w, 0))) {
    begin_copy(item, value.c_str(), value.size(), now);
  }
  ImGui::PopID();
  render_copy_status(item, now);
}

// Screen 2: revealed mnemonic + derived EVM/BTC addresses, each with its own
// copy button (secure auto-clear). The window fills the available viewport so
// the layout adapts to small airgapped containers and fullscreen alike.
void app::render_reveal_screen() {
  const std::uint64_t now = now_ms_ui();

  const ImGuiViewport* vp = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(vp->WorkPos, ImGuiCond_Always);
  ImGui::SetNextWindowSize(vp->WorkSize, ImGuiCond_Always);

  if (ImGui::Begin("BIP-39 Seedphrase Generator - Semilla generada", nullptr,
                   ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                       ImGuiWindowFlags_NoCollapse)) {
    ImGui::TextWrapped(
        "Anota esta semilla en papel. Se limpiara de la memoria al cerrar la "
        "aplicacion o generar una nueva semilla. Las direcciones se derivan en "
        "el momento; nada se escribe a disco.");
    ImGui::Separator();
    ImGui::Spacing();

    const std::size_t word_count = word_count_24_ ? 24U : 12U;
    ImGui::Text("Tu semilla (%zu palabras):", word_count);
    ImGui::Spacing();

    const float avail_h = ImGui::GetContentRegionAvail().y;
    const float box_h = std::clamp(avail_h * 0.30f, 96.0f, 220.0f);
    if (ImGui::BeginChild("mnemonic_box", ImVec2(0, box_h),
                          ImGuiChildFlags_Border)) {
      ImGui::TextWrapped("%s", mnemonic_.c_str());
    }
    ImGui::EndChild();

    ImGui::Spacing();
    const float avail_x = ImGui::GetContentRegionAvail().x;
    const bool side = avail_x >= 560.0f;
    const float btn_w =
        std::max(200.0f, (avail_x - ImGui::GetStyle().ItemSpacing.x) * 0.5f);
    if (ImGui::Button("Copiar semilla (auto-limpieza)",
                      ImVec2(side ? btn_w : 0.0f, 0.0f))) {
      begin_copy(copy_mnemonic_, mnemonic_.c_str(), mnemonic_.size(), now);
    }
    if (side) ImGui::SameLine();
    if (ImGui::Button("Nueva semilla", ImVec2(side ? btn_w : 0.0f, 0.0f))) {
      reset();
    }
    render_copy_status(copy_mnemonic_, now);
    if (!last_error_.empty()) {
      ImGui::TextColored(ImVec4(0.95f, 0.35f, 0.35f, 1.0f), "%s",
                         last_error_.c_str());
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::TextWrapped(
        "Direcciones derivadas de esta semilla (cuenta 0, indice 0):");
    ImGui::Spacing();
    render_address_field("Ethereum (EVM, EIP-55)", addresses_.evm, copy_evm_,
                         now);
    ImGui::Spacing();
    render_address_field("Bitcoin (SegWit nativo, bech32)", addresses_.btc,
                         copy_btc_, now);

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    if (ImGui::BeginChild("meter_container", ImVec2(0, 0), true)) {
      render_entropy_meter();
    }
    ImGui::EndChild();
  }
  ImGui::End();
}

}  // namespace ui
