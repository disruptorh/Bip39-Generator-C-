#include "ui/app.hpp"

#include <imgui.h>

#include "entropy/entropy_estimator.hpp"
#include "entropy/entropy_mixer.hpp"

namespace ui {

// Screen 1: configuration + optional user entropy + always-visible meter.
// The window fills the viewport so it scales to small airgapped containers
// and fullscreen windows. Widget order is kept (radios, input, button) so the
// keyboard-navigation smoke test stays valid.
void app::render_config_screen() {
  guaranteed_bits_ =
      (word_count_24_ ? entropy::kEntropy24Words : entropy::kEntropy12Words) * 8;
  update_estimate();

  const ImGuiViewport* vp = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(vp->WorkPos, ImGuiCond_Always);
  ImGui::SetNextWindowSize(vp->WorkSize, ImGuiCond_Always);

  if (ImGui::Begin("BIP-39 Seedphrase Generator", nullptr,
                   ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                       ImGuiWindowFlags_NoCollapse)) {
    ImGui::TextWrapped(
        "Aplicacion 100%% offline y airgapped. Se genera UNA semilla por "
        "ejecucion del flujo. Nada se escribe a disco.");
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::TextUnformatted("Longitud de la semilla:");
    const bool w12 = !word_count_24_;
    const bool w24 = word_count_24_;
    if (ImGui::RadioButton("12 palabras (128 bits)", w12)) word_count_24_ = false;
    const bool side = ImGui::GetContentRegionAvail().x >= 420.0f;
    if (side) ImGui::SameLine();
    if (ImGui::RadioButton("24 palabras (256 bits)", w24)) word_count_24_ = true;

    ImGui::Spacing();
    ImGui::TextUnformatted(
        "Entropia adicional (opcional): si la dejas vacia no penalizas nada; la "
        "base del sistema operativo es siempre obligatoria y suficiente.");
    if (ImGui::InputText(
            "Entropia adicional (opcional)", user_input_.data(),
            static_cast<int>(user_input_.size()),
            ImGuiInputTextFlags_AutoSelectAll)) {
      update_estimate();
    }
    ImGui::TextDisabled("La estimacion del aporte se muestra abajo.");

    ImGui::Spacing();
    ImGui::Spacing();
    if (ImGui::Button("Generar semilla", ImVec2(-1, 0))) {
      generate();
    }

    if (!last_error_.empty()) {
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
