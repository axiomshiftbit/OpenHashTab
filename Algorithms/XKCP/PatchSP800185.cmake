# The pinned XKCP counts ParallelHash input bits in size_t, which wraps at
# 512 MiB on x86. Keep the submodule intact and build a checked local copy
# with a 64-bit total and right_encode argument (NIST SP 800-185, section 6).
set(SP800185_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/XKCP/lib/high/Keccak/SP800-185")
if(NOT DEFINED SP800185_OUTPUT_DIR)
    set(SP800185_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/sp800-185")
endif()
file(MAKE_DIRECTORY "${SP800185_OUTPUT_DIR}")
set(expected_c "df328c8704260f2b4f87c7752019319e6a1119f48a208e0efd2f84be6858515a")
set(expected_h "9679a718030d5fc5bbb9adc7df10a3e18f371927e18c1fe73c3fa1621b4c5d06")
set(expected_inc "e7b5206cee0e3ae5fa7e2fc7488773e455a8053491abefcd01b54976193e1042")
foreach(extension c h inc)
    set(source "${SP800185_SOURCE_DIR}/SP800-185.${extension}")
    file(READ "${source}" content)
    # Windows Git checkouts may use CRLF. Verify the canonical source text
    # and patch the same text so line-based replacements work on every host.
    string(REPLACE "\r\n" "\n" content "${content}")
    string(SHA256 actual "${content}")
    if(NOT actual STREQUAL expected_${extension})
        message(FATAL_ERROR "XKCP SP800-185.${extension} changed: review the 64-bit length patch")
    endif()
    if(extension STREQUAL "h")
        string(REPLACE "size_t totalInputSize;" "uint64_t totalInputSize;" content "${content}")
    elseif(extension STREQUAL "inc")
        string(REPLACE "unsigned char encbuf[sizeof(size_t)+1];\n    size_t nBlocks;"
                       "unsigned char encbuf[sizeof(uint64_t)+1];\n    uint64_t nBlocks;" content "${content}")
    else()
        # right_encode is the final function in the .c file; leave left_encode
        # and its size_t-sized input buffers unchanged.
        string(FIND "${content}" "static unsigned int right_encode" position)
        string(SUBSTRING "${content}" 0 ${position} prefix)
        string(SUBSTRING "${content}" ${position} -1 suffix)
        string(REPLACE "size_t" "uint64_t" suffix "${suffix}")
        set(content "${prefix}${suffix}")
    endif()
    file(WRITE "${SP800185_OUTPUT_DIR}/SP800-185.${extension}" "${content}")
endforeach()
