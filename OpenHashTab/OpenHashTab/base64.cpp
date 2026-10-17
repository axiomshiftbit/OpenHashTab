//    Copyright 2019-2025 namazso <admin@namazso.eu>
//    This file is part of OpenHashTab.
//
//    OpenHashTab is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    OpenHashTab is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with OpenHashTab.  If not, see <https://www.gnu.org/licenses/>.
#include "base64.h"
#include <stdexcept>

// clang-format off
static const char encode_table[64]{
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
  'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
  'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

// clang-format on

std::string b64::encode(const uint8_t* src, size_t len) {
  if (len == 0) return {};
  if (len > (std::string{}.max_size() / 4) * 3)
    throw std::length_error("Base64 input is too large");
  const auto olen = 4 * ((len + 2) / 3);

  std::string str;
  str.resize(olen);

  const auto begin = src;
  const auto end = begin + len;
  auto it = begin;
  auto out = str.begin();
  while (end - it >= 3) {
    *out++ = encode_table[it[0] >> 2];
    *out++ = encode_table[((it[0] & 0x03) << 4) | (it[1] >> 4)];
    *out++ = encode_table[((it[1] & 0x0f) << 2) | (it[2] >> 6)];
    *out++ = encode_table[it[2] & 0x3f];
    it += 3;
  }

  if (end - it) {
    *out++ = encode_table[it[0] >> 2];
    if (end - it == 1) {
      *out++ = encode_table[(it[0] & 0x03) << 4];
      *out++ = '=';
    } else {
      *out++ = encode_table[((it[0] & 0x03) << 4) | (it[1] >> 4)];
      *out++ = encode_table[(it[1] & 0x0f) << 2];
    }
    *out = '=';
  }

  return str;
}

// Accept standard, URL-safe and the historical comma alphabet.
static int decode_digit(unsigned char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+' || c == '-') return 62;
  if (c == '/' || c == '_' || c == ',') return 63;
  return -1;
}

std::vector<uint8_t> b64::decode(const char* str, const size_t len) {
  if (len == 0) return {};
  size_t digits = len;
  while (digits && str[digits - 1] == '=') --digits;
  const auto padding = len - digits;
  const auto remainder = digits % 4;
  if (digits == 0 || remainder == 1 || padding > 2 ||
      (padding && (len % 4 != 0 || padding != 4 - remainder)))
    return {};

  std::vector<uint8_t> out;
  out.reserve(digits / 4 * 3 + remainder * 3 / 4);
  uint32_t bits = 0;
  unsigned count = 0;
  for (size_t i = 0; i < digits; ++i) {
    const auto digit = decode_digit(static_cast<unsigned char>(str[i]));
    if (digit < 0) return {};
    bits = (bits << 6) | static_cast<uint32_t>(digit);
    count += 6;
    if (count >= 8) {
      count -= 8;
      out.push_back(static_cast<uint8_t>(bits >> count));
    }
  }
  if ((bits & ((1u << count) - 1u)) != 0) return {};
  return out;
}
