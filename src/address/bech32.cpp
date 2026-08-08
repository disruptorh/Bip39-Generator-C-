#include "address/bech32.hpp"

#include <array>
#include <stdexcept>

namespace address {
namespace {

constexpr const char* kCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
constexpr std::size_t kChecksumLen = 6;

std::uint32_t polymod(const std::vector<std::uint8_t>& values) {
  static constexpr std::uint32_t kGen[5] = {0x3b6a57b2U, 0x26508e6dU,
                                            0x1ea119faU, 0x3d4233ddU,
                                            0x2a1462b3U};
  std::uint32_t chk = 1;
  for (std::uint8_t v : values) {
    const std::uint32_t top = chk >> 25;
    chk = ((chk & 0x1ffffffU) << 5) ^ v;
    for (int i = 0; i < 5; ++i) {
      if ((top >> i) & 1) chk ^= kGen[i];
    }
  }
  return chk;
}

std::vector<std::uint8_t> hrp_expand(const std::string& hrp) {
  std::vector<std::uint8_t> out;
  out.reserve(hrp.size() * 2 + 1);
  for (char c : hrp) {
    out.push_back(static_cast<std::uint8_t>(
        static_cast<unsigned char>(c) >> 5));
  }
  out.push_back(0);
  for (char c : hrp) {
    out.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(c) & 31));
  }
  return out;
}

std::vector<std::uint8_t> create_checksum(
    const std::string& hrp, const std::vector<std::uint8_t>& data) {
  std::vector<std::uint8_t> values = hrp_expand(hrp);
  values.insert(values.end(), data.begin(), data.end());
  values.insert(values.end(), kChecksumLen, 0);
  const std::uint32_t mod = polymod(values) ^ 1;
  std::vector<std::uint8_t> out(kChecksumLen);
  for (std::size_t i = 0; i < kChecksumLen; ++i) {
    out[i] = static_cast<std::uint8_t>((mod >> (5 * (5 - i))) & 31);
  }
  return out;
}

std::vector<std::uint8_t> to_5bits(const std::uint8_t* data, std::size_t n) {
  std::vector<std::uint8_t> out;
  out.reserve((n * 8 + 4) / 5);
  std::uint32_t acc = 0;
  int bits = 0;
  for (std::size_t i = 0; i < n; ++i) {
    acc = (acc << 8) | data[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out.push_back(static_cast<std::uint8_t>((acc >> bits) & 31));
    }
  }
  if (bits > 0) {
    out.push_back(static_cast<std::uint8_t>((acc << (5 - bits)) & 31));
  }
  return out;
}

}  // namespace

std::string bech32_encode(const std::string& hrp,
                          const std::vector<std::uint8_t>& data5) {
  for (std::uint8_t v : data5) {
    if (v >= 32) throw std::invalid_argument("bech32: data value out of range");
  }
  for (char c : hrp) {
    const unsigned char uc = static_cast<unsigned char>(c);
    if (uc < 33 || uc > 126) {
      throw std::invalid_argument("bech32: HRP contains non-printable ASCII");
    }
  }
  std::vector<std::uint8_t> values = data5;
  const std::vector<std::uint8_t> checksum = create_checksum(hrp, data5);
  values.insert(values.end(), checksum.begin(), checksum.end());
  std::string out;
  out.reserve(hrp.size() + 1 + values.size());
  out.append(hrp);
  out.push_back('1');
  for (std::uint8_t v : values) out.push_back(kCharset[v]);
  return out;
}

std::string bech32_p2wpkh(const std::uint8_t hash160[20],
                          const std::string& hrp) {
  std::vector<std::uint8_t> data;
  data.push_back(0);  // witness version 0
  const std::vector<std::uint8_t> program = to_5bits(hash160, 20);
  data.insert(data.end(), program.begin(), program.end());
  return bech32_encode(hrp, data);
}

}  // namespace address
