# SPDX-License-Identifier: GPL-3.0-or-later
add_library(extended_hashes STATIC
    blake2/blake2b-ref.c blake2/blake2s-ref.c
    sphlib/groestl.c sphlib/jh.c sphlib/whirlpool.c
    skein/skein.c skein/skein_block.c
    kupyna/kupyna256.c kupyna/kupyna512.c kupyna/kupyna_tables.c)
target_include_directories(extended_hashes PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(extended_hashes PROPERTIES C_STANDARD 11)
# Use portable loads: callers may pass any byte alignment.
target_compile_definitions(extended_hashes PUBLIC SPH_UNALIGNED=0)
# All supported Windows targets (x86/x64/ARM64) use little-endian encoding.
# Skein 1.3 predates MSVC ARM64 detection; its documented override also selects
# portable byte copies instead of relying on the host's alignment rules.
target_compile_definitions(extended_hashes PUBLIC SKEIN_NEED_SWAP=0)
