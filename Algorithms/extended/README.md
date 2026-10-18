# Additional hash implementations

Only hashing sources are built. Network, command-line programs, benchmarks and
upstream build scripts are not included. The wrappers use unkeyed hashing.

| Implementation | Pinned source | License / specification |
| --- | --- | --- |
| BLAKE2b / BLAKE2s | [BLAKE2](https://github.com/BLAKE2/BLAKE2/tree/ed1974ea83433eba7b2d95c5dcd9ac33cb847913), `ref/` | CC0; [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html) |
| Ascon permutation | [ascon-c](https://github.com/ascon/ascon-c/tree/446347f21b209f3921c65ece70027c366cbe1693), `crypto_hash/asconhash256/ref/` | CC0; final [NIST SP 800-232](https://csrc.nist.gov/pubs/sp/800/232/final) |
| Grøstl, JH, Whirlpool | [sphlib](https://github.com/pornin/sphlib/tree/15b6b8d8f3e4a43c58ba102d712fa6b8a3317035), selected `c/` files | MIT; final tweaked [Grøstl](https://www.groestl.info/specification.html), 42-round [JH](https://www3.ntu.edu.sg/home/wuhj/research/jh/), final 2003 Whirlpool |
| Skein | [Skein 1.3 package](https://www.schneier.com/wp-content/uploads/2015/01/skein.zip), `NIST/CD/Optimized_64bit/` | Public domain algorithm sources; Brian Gladman's notices retained in portability headers; [specification 1.3](https://www.schneier.com/academic/skein/) |
| Kupyna | [kupyna-c](https://github.com/sjinks/kupyna-c/tree/be73541d9694c04faa01dc0ad4a951d5d3056b52) | MIT; [designers' translated DSTU 7564:2014 specification](https://eprint.iacr.org/2015/885) |

Local changes to Kupyna: include `stddef.h` in public headers; avoid addition
overflow when checking buffered input; widen input length before converting
bytes to bits; retain and explicitly encode all 96 message-length bits.
The ordinary update API copies input into aligned internal storage.

sphlib is compiled with `SPH_UNALIGNED=0` so input need not have native word
alignment. Unused historical Whirlpool variants are not exposed by OpenHashTab.

Skein uses its documented `SKEIN_NEED_SWAP=0` override and portable byte access.
Its 2010 platform detector predates MSVC ARM64; all supported Windows targets
use little-endian encoding ([Microsoft ARM64 ABI](https://learn.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions#endianness)).

The Ascon streaming adapter uses the final standard's little-endian encoding,
12-round permutation, 8-byte rate and `0x01` padding. The displayed XOF variants
produce 32 bytes; CXOF uses an empty customization string.

KT256 and TurboSHAKE use the existing pinned XKCP permutation implementation,
following [RFC 9861](https://www.rfc-editor.org/rfc/rfc9861.html). TurboSHAKE uses
domain separation byte `0x1f`. KT256 uses empty customization and 64-byte output;
it is distinct from the historical `K12-512` option.

The streaming adapters handle arbitrary input/output alignment. A checked
build-time copy of XKCP's portable 64-bit backend fixes native unaligned loads
in both its 24-round and 12-round fast absorption loops. The existing
`NO_MISALIGNED_ACCESSES` option did not cover those loops. The patch stages
only unaligned rate blocks, leaving aligned input on the original fast path;
it also protects existing SHA-3/SHAKE/KangarooTwelve/ParallelHash callers of
that backend. The pinned submodule remains unchanged. `ExtendedHashTests`
covers input/output alignment under ASan/UBSan with alignment checks enabled.
