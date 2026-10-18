// SPDX-License-Identifier: GPL-3.0-or-later
#include "ExtendedHash.h"
#include "ExtendedHashVectors.h"
extern "C" {
#include "KeccakHash.h"
}
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

static size_t checks;
// One update crossing 2^32 input bits used to wrap Kupyna's size_t arithmetic
// on x86. Compare it with smaller updates and exercise carry into bit 64.
static void CheckKupynaLength() {
  std::vector<uint8_t> input((size_t{1} << 29) + 17, 0x5a);
  const auto run = [&](auto context, auto initialize, auto update, auto finish, size_t bytes) {
    initialize(&context);
    update(&context, input.data(), input.size());
    if (context.total != uint64_t{input.size()} * 8 || context.total_high != 0)
      throw std::runtime_error("Kupyna length truncated at 2^32 bits");
    uint8_t once[64]{}, streamed[64]{};
    finish(&context, once);
    initialize(&context);
    for (size_t offset = 0; offset < input.size(); offset += 1024 * 1024)
      update(&context, input.data() + offset, std::min(size_t{1024 * 1024}, input.size() - offset));
    finish(&context, streamed);
    if (std::memcmp(once, streamed, bytes)) throw std::runtime_error("Kupyna large-update partition mismatch");
    initialize(&context);
    context.total = UINT64_MAX - 7;
    context.total_high = 17;
    update(&context, input.data(), 1);
    if (context.total != 0 || context.total_high != 18)
      throw std::runtime_error("Kupyna lost carry into the high length word");
    ++checks;
  };
  run(kupyna256_ctx_t{}, kupyna256_init, kupyna256_update, kupyna256_final, 32);
  run(kupyna512_ctx_t{}, kupyna512_init, kupyna512_update, kupyna512_final, 64);
}
static std::string Unhex(std::string_view hex) {
  std::string result;
  for (size_t i = 0; i < hex.size(); i += 2)
    result += static_cast<char>(std::stoul(std::string(hex.substr(i, 2)), nullptr, 16));
  return result;
}
static void Check(const std::string& name, const std::string& input, const std::string& expected, size_t chunk) {
  const auto run = [&](auto context) {
    const auto size = context.GetOutputSize();
    std::vector<uint8_t> output(size + 32, 0xa5);
    // Offset input and output deliberately: callers do not promise alignment.
    const std::string unaligned = "x" + input;
    context.Update(nullptr, 0);
    for (size_t i = 0; i < input.size(); i += chunk)
      context.Update(unaligned.data() + 1 + i, std::min(chunk, input.size() - i));
    context.Update(nullptr, 0);
    context.Finish(output.data() + 15);
    for (size_t i = 0; i < output.size(); ++i)
      if ((i < 15 || i >= 15 + size) && output[i] != 0xa5) throw std::runtime_error(name + " output overrun");
    std::string actual;
    for (size_t i = 0; i < size; ++i) {
      char pair[3];
      std::snprintf(pair, sizeof(pair), "%02x", output[i + 15]);
      actual += pair;
    }
    if (actual != expected) throw std::runtime_error(name + " mismatch: length=" + std::to_string(input.size()) + " chunk=" + std::to_string(chunk));
    ++checks;
  };
  if (name == "BLAKE2b-256") { run(oht::Blake2b<32>{}); return; }
  if (name == "BLAKE2b-512") { run(oht::Blake2b<64>{}); return; }
  if (name == "BLAKE2s-256") { run(oht::Blake2s{}); return; }
  if (name == "Ascon-Hash256") { run(oht::Ascon<oht::AsconMode::Hash>{}); return; }
  if (name == "Ascon-XOF128-256") { run(oht::Ascon<oht::AsconMode::Xof>{}); return; }
  if (name == "Ascon-CXOF128-256") { run(oht::Ascon<oht::AsconMode::Cxof>{}); return; }
  if (name == "KT256-512") { run(oht::Kt256{}); return; }
  if (name == "TurboSHAKE128-256") { run(oht::TurboShake<128, 32>{}); return; }
  if (name == "TurboSHAKE256-512") { run(oht::TurboShake<256, 64>{}); return; }
  if (name == "Kupyna-256") { run(oht::Kupyna256{}); return; }
  if (name == "Kupyna-384") { run(oht::Kupyna384{}); return; }
  if (name == "Kupyna-512") { run(oht::Kupyna512{}); return; }
  if (name == "Skein-256-256") { run(oht::Skein256_256{}); return; }
  if (name == "Skein-512-256") { run(oht::Skein512_256{}); return; }
  if (name == "Skein-512-512") { run(oht::Skein512_512{}); return; }
  if (name == "Skein-1024-1024") { run(oht::Skein1024_1024{}); return; }
  if (name == "Groestl-224") { run(oht::Groestl224{}); return; }
  if (name == "Groestl-256") { run(oht::Groestl256{}); return; }
  if (name == "Groestl-384") { run(oht::Groestl384{}); return; }
  if (name == "Groestl-512") { run(oht::Groestl512{}); return; }
  if (name == "JH-224") { run(oht::Jh224{}); return; }
  if (name == "JH-256") { run(oht::Jh256{}); return; }
  if (name == "JH-384") { run(oht::Jh384{}); return; }
  if (name == "JH-512") { run(oht::Jh512{}); return; }
  if (name == "Whirlpool") { run(oht::Whirlpool{}); return; }
  throw std::runtime_error("Missing portable test algorithm: " + name);
}
// Independently generated with Python hashlib (FIPS 202). This also covers
// the existing 24-round backend, not only the new 12-round TurboSHAKE callers.
static void CheckFips202Alignment() {
  struct Vector { unsigned rate, capacity, fixed_bits, suffix; const char* expected; };
  const Vector vectors[] = {
    {1088, 512, 256, 6, "ba7f1834cddbba9f82cd4dcf7a106bb2e615fec90020f5a5de8efff8d49198b6"},
    {1344, 256, 0, 31, "b4347102639420d3f094d275cc1311e91cab7e047cf624679f20b81f5c9e2a9c"},
    {1088, 512, 0, 31, "9d780b699069ff9c378acd8857081da4efe44787ead6b5c92d8213445d4b1ebaf8f18ee78ae5c80640470731ab70162961625d053467abafe60dcb7950fc84bd"},
  };
  std::vector<uint8_t> input(1025);
  for (size_t i = 0; i < 1024; ++i) input[i + 1] = static_cast<uint8_t>(i % 251);
  for (const auto& vector : vectors) for (const size_t chunk : {1u, 7u, 127u, 1024u}) {
    Keccak_HashInstance context{};
    Keccak_HashInitialize(&context, vector.rate, vector.capacity, vector.fixed_bits, static_cast<unsigned char>(vector.suffix));
    for (size_t i = 0; i < 1024; i += chunk)
      Keccak_HashUpdate(&context, input.data() + 1 + i, std::min(chunk, size_t{1024} - i) * 8);
    const auto expected = Unhex(vector.expected);
    std::vector<uint8_t> output(expected.size() + 2, 0xa5);
    Keccak_HashFinal(&context, output.data() + 1);
    if (!vector.fixed_bits) Keccak_HashSqueeze(&context, output.data() + 1, expected.size() * 8);
    if (output.front() != 0xa5 || output.back() != 0xa5 ||
        std::memcmp(output.data() + 1, expected.data(), expected.size())) throw std::runtime_error("FIPS 202 unaligned input/output mismatch");
    ++checks;
  }
}
int main() {
  try {
    CheckKupynaLength();
    CheckFips202Alignment();
    for (const auto& vector : extended_vectors) {
      const auto input = Unhex(vector.input_hex);
      for (const size_t chunk : {1u, 7u, 31u, 127u, 8192u}) Check(vector.name, input, vector.expected, chunk);
    }
    for (const auto& vector : extended_long_vectors) {
      std::string input(vector.size, 0);
      for (size_t i = 0; i < input.size(); ++i) input[i] = static_cast<char>(i % 251);
      for (const auto chunk : {size_t{127}, size_t{8192}, size_t{8193}, input.size()}) Check(vector.name, input, vector.expected, chunk);
    }
    std::printf("PASS: %zu hash checks: independent answers, unaligned buffers, guards and large Kupyna updates\n", checks);
    return 0;
  } catch (const std::exception& error) {
    std::fprintf(stderr, "FAIL: %s\n", error.what());
    return 1;
  }
}
