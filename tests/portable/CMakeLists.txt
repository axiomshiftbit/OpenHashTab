# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.19)
project(OpenHashTabPortableTests LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(EXT "${ROOT}/Algorithms/extended")
set(XKCP "${ROOT}/Algorithms/XKCP/XKCP/lib")
include("${ROOT}/Algorithms/XKCP/PatchAlignment.cmake")
add_executable(ExtendedHashTests ../ExtendedHashTests.cpp
    ${EXT}/blake2/blake2b-ref.c ${EXT}/blake2/blake2s-ref.c
    ${EXT}/sphlib/groestl.c ${EXT}/sphlib/jh.c ${EXT}/sphlib/whirlpool.c
    ${EXT}/skein/skein.c ${EXT}/skein/skein_block.c
    ${EXT}/kupyna/kupyna256.c ${EXT}/kupyna/kupyna512.c ${EXT}/kupyna/kupyna_tables.c
    ${XKCP}/high/TurboSHAKE/TurboSHAKE.c
    ${KECCAK_ALIGNMENT_SOURCE}
    ${XKCP}/high/Keccak/FIPS202/KeccakHash.c ${XKCP}/high/Keccak/KeccakSponge.c)
target_include_directories(ExtendedHashTests PRIVATE ${EXT}
    ${ROOT}/Algorithms/XKCP ${XKCP}/low/common ${XKCP}/common
    ${XKCP}/low/KeccakP-1600/common ${XKCP}/low/KeccakP-1600/plain-64bits/u6
    ${XKCP}/low/KeccakP-1600/plain-64bits ${XKCP}/high/TurboSHAKE ${XKCP}/high/Keccak ${XKCP}/high/Keccak/FIPS202)
target_compile_definitions(ExtendedHashTests PRIVATE SPH_UNALIGNED=0 SKEIN_NEED_SWAP=0
    XKCP_has_KeccakP1600 NO_MISALIGNED_ACCESSES)
if(MSVC)
    target_compile_options(ExtendedHashTests PRIVATE /EHsc)
else()
    target_compile_options(ExtendedHashTests PRIVATE -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all)
    target_link_options(ExtendedHashTests PRIVATE -fsanitize=address,undefined)
endif()
set_target_properties(ExtendedHashTests PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Tests")
enable_testing()
add_test(NAME extended-hashes COMMAND ExtendedHashTests)
set_tests_properties(extended-hashes PROPERTIES TIMEOUT 300)
