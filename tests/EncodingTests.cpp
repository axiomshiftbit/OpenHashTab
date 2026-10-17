// SPDX-License-Identifier: GPL-3.0-or-later
#include "base64.h"
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string_view>

static void check(bool ok, const char* message) {
  if (!ok) { std::fprintf(stderr, "FAIL: %s\n", message); std::exit(1); }
}
int main() {
  // Use an exact-size allocation so sanitizers catch reads past the input.
  auto one = std::make_unique<char[]>(1);
  one[0] = 'A';
  check(b64::decode(one.get(), 1).empty(), "one base64 character is invalid");
  for (auto bad : {"AAAAA", "=AAA", "AA=A", "A===", "AAAA====", "AA!A", "AB=="})
    check(b64::decode(bad, std::string_view(bad).size()).empty(), bad);
  const char* text[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
  const char* encoded[] = {"", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"};
  for (size_t i = 0; i < 7; ++i) {
    std::string_view input(text[i]);
    const auto actual = b64::encode(reinterpret_cast<const uint8_t*>(input.data()), input.size());
    check(actual == encoded[i], "RFC 4648 encoding vector");
    for (auto value : {actual, actual.substr(0, actual.find('='))}) {
      const auto decoded = b64::decode(value.data(), value.size());
      check(std::string(decoded.begin(), decoded.end()) == input, "padded/unpadded decoding vector");
    }
  }
  check(b64::decode("-_8=", 4) == std::vector<uint8_t>({251, 255}), "URL alphabet");
  for (size_t length = 0; length < 4096; ++length) {
    std::vector<uint8_t> input(length);
    for (size_t i = 0; i < length; ++i) input[i] = static_cast<uint8_t>(i * 71 + length);
    const auto encoded_value = b64::encode(input.data(), input.size());
    check(b64::decode(encoded_value.data(), encoded_value.size()) == input, "binary round trip");
  }
  std::puts("PASS: base64 vectors, malformed input and 4096 binary round trips");
}
