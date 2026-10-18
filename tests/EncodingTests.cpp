// SPDX-License-Identifier: GPL-3.0-or-later
#include "base64.h"
#include "crc64.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string_view>
#if !defined(_WIN32) && SIZE_MAX > UINT32_MAX
#include <sys/mman.h>
#endif

static void check(bool ok, const char* message) {
  if (!ok) { std::fprintf(stderr, "FAIL: %s\n", message); std::exit(1); }
}
// Bit-by-bit reference using the polynomial and complements in XZ format §6.
// https://tukaani.org/xz/xz-file-format.txt
static uint64_t reference_crc64(uint64_t crc, const uint8_t* data, size_t size) {
  crc = ~crc;
  for (size_t i = 0; i < size; ++i) {
    crc ^= data[i];
    for (unsigned bit = 0; bit < 8; ++bit)
      crc = (crc >> 1) ^ ((crc & 1) ? UINT64_C(0xC96C5795D7870F42) : 0);
  }
  return ~crc;
}
static void crc64_tests() {
  check(crc64(0, "123456789", 9) == UINT64_C(0x995dc9bbdf1939fa), "CRC64/XZ check value");
  for (const uint64_t initial : {UINT64_C(0), UINT64_C(0x123456789abcdef0)}) {
    check(crc64(initial, nullptr, 0) == initial, "empty CRC64 update");
    for (size_t offset = 0; offset < 8; ++offset) {
      for (size_t length = 0; length <= 257; ++length) {
        // Exact-size allocation also detects a word load past the last byte.
        auto storage = std::make_unique<uint8_t[]>(offset + length + 1);
        auto input = storage.get() + offset + 1;
        for (size_t i = 0; i < length; ++i) input[i] = static_cast<uint8_t>(i * 71 + length);
        const auto expected = reference_crc64(initial, input, length);
        check(crc64(initial, input, length) == expected, "CRC64 unaligned input and tail");
        for (const size_t chunk : {size_t(1), size_t(7), size_t(8), size_t(31)}) {
          auto actual = initial;
          for (size_t i = 0; i < length; i += chunk)
            actual = crc64(actual, input + i, std::min(chunk, length - i));
          check(actual == expected, "CRC64 streaming reference");
        }
      }
    }
  }
  std::puts("PASS: CRC64/XZ check value and 20640 aligned/unaligned streaming comparisons");
#if !defined(_WIN32) && SIZE_MAX > UINT32_MAX
  // Private anonymous zero pages avoid allocating 4 GiB of physical memory.
  // The independent liblzma value and reproduction are in HashVectors.md.
  const size_t size = (size_t(1) << 32) + 17;
  void* input = mmap(nullptr, size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  check(input != MAP_FAILED, "map CRC64 input over 4 GiB");
  const auto actual = crc64(0, input, size);
  check(munmap(input, size) == 0, "unmap CRC64 input");
  check(actual == UINT64_C(0x9247c1bf2ab39629), "CRC64 single update over 4 GiB");
  std::puts("PASS: CRC64 single 4 GiB + 17 byte update");
#endif
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
  crc64_tests();
}
