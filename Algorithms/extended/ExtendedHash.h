// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
extern "C" {
#include "blake2/blake2.h"
#include "sphlib/sph_groestl.h"
#include "sphlib/sph_jh.h"
#include "sphlib/sph_whirlpool.h"
#include "skein/skein.h"
#include "kupyna/kupyna256.h"
#include "kupyna/kupyna512.h"
#include "ascon/permutations.h"
#include "ascon/word.h"
#include "TurboSHAKE.h"
}

namespace oht {

template <class Context, size_t Bytes, auto Init, auto UpdateFn, auto Final>
class StreamingHash {
  Context ctx{};
public:
  StreamingHash() { Init(&ctx); }
  void Update(const void* input, size_t size) {
    auto data = static_cast<const uint8_t*>(input);
    while (size) {
      const auto count = std::min(size, size_t{1} << 29);
      UpdateFn(&ctx, data, count);
      data += count;
      size -= count;
    }
  }
  void Finish(uint8_t* output) { Final(&ctx, output); }
  size_t GetOutputSize() const { return Bytes; }
};

template <size_t Bytes>
class Blake2b {
  blake2b_state ctx{};
public:
  Blake2b() { static_assert(Bytes == 32 || Bytes == 64); blake2b_init(&ctx, Bytes); }
  void Update(const void* data, size_t size) { if (size) blake2b_update(&ctx, data, size); }
  void Finish(uint8_t* output) { blake2b_final(&ctx, output, Bytes); }
  size_t GetOutputSize() const { return Bytes; }
};

class Blake2s {
  blake2s_state ctx{};
public:
  Blake2s() { blake2s_init(&ctx, 32); }
  void Update(const void* data, size_t size) { if (size) blake2s_update(&ctx, data, size); }
  void Finish(uint8_t* output) { blake2s_final(&ctx, output, 32); }
  size_t GetOutputSize() const { return 32; }
};

template <size_t Bits> inline int Skein256Init(Skein_256_Ctxt_t* ctx) { return Skein_256_Init(ctx, Bits); }
template <size_t Bits> inline int Skein512Init(Skein_512_Ctxt_t* ctx) { return Skein_512_Init(ctx, Bits); }
inline int Skein1024Init(Skein1024_Ctxt_t* ctx) { return Skein1024_Init(ctx, 1024); }
using Skein256_256 = StreamingHash<Skein_256_Ctxt_t, 32, Skein256Init<256>, Skein_256_Update, Skein_256_Final>;
using Skein512_256 = StreamingHash<Skein_512_Ctxt_t, 32, Skein512Init<256>, Skein_512_Update, Skein_512_Final>;
using Skein512_512 = StreamingHash<Skein_512_Ctxt_t, 64, Skein512Init<512>, Skein_512_Update, Skein_512_Final>;
using Skein1024_1024 = StreamingHash<Skein1024_Ctxt_t, 128, Skein1024Init, Skein1024_Update, Skein1024_Final>;
using Kupyna256 = StreamingHash<kupyna256_ctx_t, 32, kupyna256_init, kupyna256_update, kupyna256_final>;
using Kupyna384 = StreamingHash<kupyna512_ctx_t, 48, kupyna384_init, kupyna384_update, kupyna384_final>;
using Kupyna512 = StreamingHash<kupyna512_ctx_t, 64, kupyna512_init, kupyna512_update, kupyna512_final>;
using Whirlpool = StreamingHash<sph_whirlpool_context, 64, sph_whirlpool_init, sph_whirlpool, sph_whirlpool_close>;

#define OHT_SPH_STATE(Name, prefix, bits) \
  using Name##bits = StreamingHash<sph_##prefix##bits##_context, bits / 8, \
      sph_##prefix##bits##_init, sph_##prefix##bits, sph_##prefix##bits##_close>
OHT_SPH_STATE(Groestl, groestl, 224);
OHT_SPH_STATE(Groestl, groestl, 256);
OHT_SPH_STATE(Groestl, groestl, 384);
OHT_SPH_STATE(Groestl, groestl, 512);
OHT_SPH_STATE(Jh, jh, 224);
OHT_SPH_STATE(Jh, jh, 256);
OHT_SPH_STATE(Jh, jh, 384);
OHT_SPH_STATE(Jh, jh, 512);
#undef OHT_SPH_STATE

// NIST SP 800-232, Algorithms 5-7. All exposed variants produce 256 bits.
// CXOF absorbs the empty customization string, including its length and padding.
enum class AsconMode { Hash, Xof, Cxof };
template <AsconMode Mode>
class Ascon {
  ascon_state_t ctx{};
  unsigned position{};
public:
  Ascon() {
    ctx.x[0] = Mode == AsconMode::Hash ? ASCON_HASH_IV :
        Mode == AsconMode::Xof ? ASCON_XOF_IV : ASCON_CXOF_IV;
    P12(&ctx);
    if constexpr (Mode == AsconMode::Cxof) {
      P12(&ctx); // Absorb the 64-bit zero customization length.
      ctx.x[0] ^= 1;
      P12(&ctx); // Pad the empty customization string.
    }
  }
  void Update(const void* input, size_t size) {
    auto data = static_cast<const uint8_t*>(input);
    while (size) {
      const auto count = std::min(size, size_t{8 - position});
      ctx.x[0] ^= LOADBYTES(data, static_cast<int>(count)) << (8 * position);
      data += count;
      size -= count;
      position += static_cast<unsigned>(count);
      if (position == 8) { P12(&ctx); position = 0; }
    }
  }
  void Finish(uint8_t* output) {
    ctx.x[0] ^= uint64_t{1} << (8 * position);
    for (unsigned i = 0; i < 4; ++i) {
      P12(&ctx);
      STOREBYTES(output + 8 * i, ctx.x[0], 8);
    }
  }
  size_t GetOutputSize() const { return 32; }
};

template <unsigned Strength, size_t Bytes>
class TurboShake {
  TurboSHAKE_Instance ctx{};
public:
  TurboShake() { static_assert(Strength == 128 || Strength == 256); TurboSHAKE_Initialize(&ctx, 2 * Strength); }
  void Update(const void* input, size_t size) {
    if (size) TurboSHAKE_Absorb(&ctx, static_cast<const uint8_t*>(input), size);
  }
  void Finish(uint8_t* output) {
    TurboSHAKE_AbsorbDomainSeparationByte(&ctx, 0x1f);
    TurboSHAKE_Squeeze(&ctx, output, Bytes);
  }
  size_t GetOutputSize() const { return Bytes; }
};

// RFC 9861, KT256 with empty customization and a 512-bit output.
// The first 8192 bytes feed the final node directly; later chunks produce
// 64-byte chaining values. The final customization-length byte is message data.
class Kt256 {
  TurboSHAKE_Instance root{}, leaf{};
  size_t first_size{}, leaf_size{};
  uint64_t leaves{};
  bool tree{};
  void FinishLeaf() {
    uint8_t cv[64];
    TurboSHAKE_AbsorbDomainSeparationByte(&leaf, 0x0b);
    TurboSHAKE_Squeeze(&leaf, cv, sizeof(cv));
    TurboSHAKE_Absorb(&root, cv, sizeof(cv));
    ++leaves;
    leaf_size = 0;
    TurboSHAKE256_Initialize(&leaf);
  }
public:
  Kt256() { TurboSHAKE256_Initialize(&root); TurboSHAKE256_Initialize(&leaf); }
  void Update(const void* input, size_t size) {
    auto data = static_cast<const uint8_t*>(input);
    if (first_size < 8192) {
      const auto count = std::min(size, 8192 - first_size);
      if (count) { TurboSHAKE_Absorb(&root, data, count); data += count; }
      first_size += count;
      size -= count;
    }
    if (size && !tree) {
      const uint8_t divider[8] = {3, 0, 0, 0, 0, 0, 0, 0};
      TurboSHAKE_Absorb(&root, divider, sizeof(divider));
      tree = true;
    }
    while (size) {
      const auto count = std::min(size, 8192 - leaf_size);
      TurboSHAKE_Absorb(&leaf, data, count);
      data += count;
      size -= count;
      leaf_size += count;
      if (leaf_size == 8192) FinishLeaf();
    }
  }
  void Finish(uint8_t* output) {
    const uint8_t empty_customization_length = 0;
    Update(&empty_customization_length, 1);
    if (tree) {
      if (leaf_size) FinishLeaf();
      uint8_t encoded[11]{};
      unsigned bytes = 0;
      for (auto value = leaves; value; value >>= 8) ++bytes;
      for (unsigned i = 0; i < bytes; ++i)
        encoded[i] = static_cast<uint8_t>(leaves >> (8 * (bytes - i - 1)));
      encoded[bytes] = static_cast<uint8_t>(bytes);
      encoded[bytes + 1] = encoded[bytes + 2] = 0xff;
      TurboSHAKE_Absorb(&root, encoded, bytes + 3);
    }
    TurboSHAKE_AbsorbDomainSeparationByte(&root, tree ? 6 : 7);
    TurboSHAKE_Squeeze(&root, output, 64);
  }
  size_t GetOutputSize() const { return 64; }
};

} // namespace oht
