#include "ui/app.hpp"

#include <cstring>

#include <imgui.h>

#include "export/batch_export.hpp"

namespace ui {

// Screen 1, batch variant: how many seeds, the password used to obfuscate
// them, and where the .txt goes. The user names both the directory and the
// file; the file name tracks the seed count ("6seeds.txt") until they edit it.
void app::render_batch_panel() {
  ImGui::Separator();
  ImGui::Spacing();

  ImGui::TextUnformatted(
      "Genera varias semillas, obfuscada cada una con la contrasena que "
      "indiques, y exporta el resultado a un archivo .txt.");

  ImGui::Spacing();
  ImGui::TextUnformatted("Numero de semillas:");
  ImGui::SetNextItemWidth(160.0f);
  const int previous_count = batch_count_;
  if (ImGui::InputInt("##count", &batch_count_, 1, 10)) {
    if (batch_count_ < batch_export::kMinSeeds) {
      batch_count_ = batch_export::kMinSeeds;
    } else if (batch_count_ > batch_export::kMaxSeeds) {
      batch_count_ = batch_export::kMaxSeeds;
    }
    // Keep the default file name in step with the count, but never overwrite a
    // name the user typed themselves.
    if (batch_count_ != previous_count) {
      export_overwrite_pending_ = false;
      sync_default_export_name();
    }
  }
  ImGui::SameLine();
  ImGui::TextDisabled("entre %d y %d", batch_export::kMinSeeds,
                      batch_export::kMaxSeeds);

  const std::size_t word_count = word_count_24_ ? 24U : 12U;
  if (batch_count_ >= 50) {
    ImGui::TextColored(ImVec4(0.92f, 0.72f, 0.25f, 1.0f),
                       "A partir de ~50 semillas la derivacion de direcciones "
                       "puede tardar varios segundos.");
  }

  ImGui::Spacing();
  ImGui::TextUnformatted("Contrasena para ofuscar:");
  ImGui::SetNextItemWidth(420.0f);
  if (ImGui::InputText("##batch_password", batch_password_.data(),
                       static_cast<int>(batch_password_.size()),
                       ImGuiInputTextFlags_Password |
                           ImGuiInputTextFlags_AutoSelectAll)) {
    // A new password invalidates any pending overwrite confirmation.
    export_overwrite_pending_ = false;
  }
  ImGui::TextDisabled(
      "Se usa como clave XOR derivada (KDF V1 SHA-256, modo legacy), el mismo "
      "del BIP-39 Obfuscator.");

  ImGui::Spacing();
  ImGui::TextUnformatted("Carpeta de destino:");
  if (ImGui::InputText("##export_dir", export_dir_.data(),
                       static_cast<int>(export_dir_.size()),
                       ImGuiInputTextFlags_AutoSelectAll)) {
    export_overwrite_pending_ = false;
  }

  ImGui::TextUnformatted("Nombre del archivo:");
  if (ImGui::InputText("##export_name", export_name_.data(),
                       static_cast<int>(export_name_.size()),
                       ImGuiInputTextFlags_AutoSelectAll)) {
    // From here on the name is the user's, so stop mirroring the seed count.
    export_name_custom_ = true;
    export_overwrite_pending_ = false;
  }
  const std::string default_name = batch_export::default_filename(batch_count_);
  ImGui::TextDisabled("Por defecto: %s", default_name.c_str());

  ImGui::Spacing();
  const bool has_dir = export_dir_.data() != nullptr &&
                       std::strlen(export_dir_.data()) != 0;
  const bool has_name = export_name_.data() != nullptr &&
                        std::strlen(export_name_.data()) != 0;
  const bool exists =
      has_dir && has_name && batch_export::file_exists(
                                  batch_export::join_path(export_dir_.data(),
                                                          export_name_.data()));
  if (exists && !export_overwrite_pending_) {
    ImGui::TextColored(ImVec4(0.92f, 0.72f, 0.25f, 1.0f),
                       "Ese archivo ya existe. El boton de abajo lo "
                       "sobrescribira.");
  }
  const char* label = export_overwrite_pending_ ? "Sobrescribir y exportar"
                                                : "Generar y exportar .txt";
  if (ImGui::Button(label, ImVec2(-1, 0))) {
    generate_batch();
  }

  if (!last_error_.empty()) {
    ImGui::TextColored(ImVec4(0.95f, 0.35f, 0.35f, 1.0f), "%s",
                       last_error_.c_str());
  }
  if (!export_status_.empty()) {
    ImGui::TextColored(ImVec4(0.42f, 0.88f, 0.52f, 1.0f), "%s",
                       export_status_.c_str());
  }
  ImGui::TextDisabled(
      "El archivo contendra, por cada semilla, la frase obfuscada y sus "
      "direcciones EVM y BTC (%zu palabras por semilla).",
      word_count);
}

}  // namespace ui
