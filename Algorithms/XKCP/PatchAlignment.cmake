# Keep the pinned source intact; compile a checked copy with safe byte input.
set(KECCAK_ALIGNMENT_SOURCE "${CMAKE_CURRENT_LIST_DIR}/XKCP/lib/low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c")
if(NOT DEFINED KECCAK_ALIGNMENT_OUTPUT_DIR)
    set(KECCAK_ALIGNMENT_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/keccak-alignment")
endif()
file(READ "${KECCAK_ALIGNMENT_SOURCE}" content)
string(REPLACE "\r\n" "\n" content "${content}")
string(SHA256 actual "${content}")
if(NOT actual STREQUAL "b66afacd81e5d1128722f616c690d3b68e16dd72203b248ede940eec563eaa6e")
    message(FATAL_ERROR "XKCP KeccakP-1600-opt64.c changed: review the input alignment patch")
endif()
# Both 24-round and 12-round fast loops bypass NO_MISALIGNED_ACCESSES.
# Their rate is at most 25 lanes. Keep aligned input on the original fast path.
string(REPLACE "uint64_t *inDataAsLanes = (uint64_t*)data;"
    "const unsigned char *input = data;\n    uint64_t aligned[25];" content "${content}")
string(REPLACE "        addInput(A, inDataAsLanes, laneCount)"
    "        const uint64_t *inDataAsLanes;\n        if ((uintptr_t)input % sizeof(uint64_t)) {\n            memcpy(aligned, input, laneCount*8);\n            inDataAsLanes = aligned;\n        } else inDataAsLanes = (const uint64_t*)input;\n        addInput(A, inDataAsLanes, laneCount)" content "${content}")
string(REPLACE "inDataAsLanes += laneCount;" "input += laneCount*8;" content "${content}")
file(MAKE_DIRECTORY "${KECCAK_ALIGNMENT_OUTPUT_DIR}")
set(KECCAK_ALIGNMENT_SOURCE "${KECCAK_ALIGNMENT_OUTPUT_DIR}/KeccakP-1600-opt64.c")
file(WRITE "${KECCAK_ALIGNMENT_SOURCE}" "${content}")
