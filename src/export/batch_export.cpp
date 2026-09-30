#include "export/batch_export.hpp"

#include <sodium.h>

#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace batch_export {
namespace {

constexpr char kRule[] =
    "================================================================";
// One indent level inside the rules, shared by the header fields, the entries
// and the prose, so every colon in the file lands in the same column.
constexpr char kInset[] = " ";
constexpr int kLabelWidth = 17;

void append_labeled(std::string& out, const char* label, int width,
                    const std::string& value) {
  // Size the buffer to the exact formatted length first. A 24-word mnemonic
  // line can exceed any small fixed stack buffer, and writing past it would
  // print adjacent stack memory as mojibake (or crash).
  const int needed =
      std::snprintf(nullptr, 0, "%-*s: %s", width, label, value.c_str());
  if (needed <= 0) return;
  const std::size_t start = out.size();
  const std::size_t size = static_cast<std::size_t>(needed);
  out.resize(start + size + 1);
  std::snprintf(&out[start], size + 1, "%-*s: %s", width, label,
                value.c_str());
  out.resize(start + size);
  out.push_back('\n');
}

}  // namespace

std::string default_filename(int seed_count) {
  return std::to_string(seed_count) + "seeds.txt";
}

std::string validate(int seed_count, const std::string& directory,
                     const std::string& filename) {
  if (seed_count < kMinSeeds || seed_count > kMaxSeeds) {
    return "El numero de semillas debe estar entre 1 y " +
           std::to_string(kMaxSeeds) + ".";
  }
  if (directory.empty()) {
    return "Indica la carpeta de destino del archivo .txt";
  }
  if (filename.empty()) {
    return "Indica el nombre del archivo .txt";
  }
  if (filename.find('/') != std::string::npos) {
    return "El nombre del archivo no puede contener '/'; elige la carpeta "
           "en el campo de arriba.";
  }
  if (filename == "." || filename == "..") {
    return "Nombre de archivo no valido.";
  }
  if (filename.size() > 200) {
    return "Nombre de archivo demasiado largo.";
  }

  std::error_code ec;
  const std::filesystem::path dir(directory);
  if (!std::filesystem::is_directory(dir, ec) || ec) {
    return "La carpeta '" + directory + "' no existe o no es un directorio.";
  }
  return {};
}

std::string join_path(const std::string& directory,
                      const std::string& filename) {
  if (directory.empty() || filename.empty()) {
    throw std::invalid_argument("batch_export: path component is empty");
  }
  if (directory.back() == '/') return directory + filename;
  return directory + "/" + filename;
}

bool file_exists(const std::string& path) {
  std::error_code ec;
  return std::filesystem::is_regular_file(std::filesystem::path(path), ec);
}

std::string render(const std::vector<entry>& entries, const report_meta& meta) {
  const std::size_t total = entries.size();
  std::string out;
  out.reserve(256 + total * 320);

  // UTF-8 byte order mark. The report is plain ASCII/UTF-8, but some text
  // editors default to UTF-16; without a BOM they decode the bytes as UTF-16
  // and show Chinese-looking mojibake. The BOM pins the encoding to UTF-8.
  out += "\xEF\xBB\xBF";
  out += kRule;
  out += "\n BIP-39 Seedphrase Generator - exporte de lote (semillas "
         "obfuscadas)\n";
  out += kRule;
  out += "\n";

  append_labeled(out, " Semillas", kLabelWidth, std::to_string(total));
  append_labeled(out, " Longitud", kLabelWidth,
                 std::to_string(meta.word_count) + " palabras (" +
                     std::to_string(meta.entropy_bits) + " bits)");
  append_labeled(out, " KDF", kLabelWidth, meta.kdf_label);
  append_labeled(out, " Generado (UTC)", kLabelWidth, meta.timestamp_utc);
  append_labeled(out, " Direcciones", kLabelWidth,
                 "EVM m/44'/60'/0'/0/0   BTC m/84'/0'/0'/0/0");
  out += "\n En este archivo la SEMILLA de cada entrada esta OBFUSCADA; solo se\n";
  out += " recupera en claro con la contrasena correcta en BIP-39 Obfuscator.\n";
  out += "\n Las direcciones EVM/BTC son las de la semilla REAL (la ya de-ofuscada),\n";
  out += " es decir, las que mostrara tu cartera al importar la semilla recuperada.\n";
  out += "\n Para recuperar las semillas: abre BIP-39 Obfuscator, selecciona el\n";
  out += " modo \"V1 SHA-256 (Legacy)\" y usa la MISMA contrasena con la que\n";
  out += " se exporto este archivo. Sin ella no se pueden recuperar.\n";
  out += kRule;
  out += "\n\n";

  // The seed never shares a line with anything: the label sits alone, the
  // obfuscated mnemonic starts two blank lines below it, and the addresses
  // start two blank lines below the mnemonic. This keeps a 24-word seed from
  // running into its addresses when read.
  for (std::size_t i = 0; i < total; ++i) {
    out += kInset;
    out += "[" + std::to_string(i + 1) + "/" + std::to_string(total) + "]\n";
    out += "   SEMILLA:\n";
    out += "\n\n";
    out += "   " + entries[i].seed + "\n";
    out += "\n\n";
    out += "   EVM: " + entries[i].evm + "\n";
    out += "   BTC: " + entries[i].btc + "\n";
    out += "\n";
  }

  out += kRule;
  out += "\n Fin del archivo: " + std::to_string(total) + " ";
  out += (total == 1) ? "semilla obfuscada.\n" : "semillas obfuscadas.\n";
  out += kRule;
  out += "\n";

  return out;
}

void write_atomic(const std::string& path, const std::string& content) {
  const std::string tmp_path = path + ".tmp";
  std::error_code ec;
  std::filesystem::remove(std::filesystem::path(tmp_path), ec);

  {
    std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
    if (!out) {
      throw std::runtime_error("No se pudo crear el archivo: " + tmp_path);
    }
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    out.flush();
    if (!out) {
      out.close();
      std::filesystem::remove(std::filesystem::path(tmp_path), ec);
      throw std::runtime_error("No se pudo escribir el archivo: " + path);
    }
  }

  std::filesystem::rename(std::filesystem::path(tmp_path),
                          std::filesystem::path(path), ec);
  if (ec) {
    std::filesystem::remove(std::filesystem::path(tmp_path), ec);
    throw std::runtime_error("No se pudo finalizar el archivo '" + path +
                             "': " + ec.message());
  }
}

void wipe(std::string& value) {
  if (!value.empty()) {
    sodium_memzero(value.data(), value.size());
    value.clear();
  }
}

std::string utc_timestamp() {
  const std::time_t now = std::time(nullptr);
  std::tm tm_utc{};
  if (gmtime_r(&now, &tm_utc) == nullptr) return "desconocido";
  char buf[32];
  const std::size_t len =
      std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_utc);
  return std::string(buf, len);
}

}  // namespace batch_export