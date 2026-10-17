add_library(bee2_hash STATIC
        BeltHash.c
        BeltHashLength.c
        bee2/src/crypto/belt/belt_compr.c
        bee2/src/crypto/belt/belt_block.c
        bee2/src/core/blob.c
        bee2/src/core/mem.c
        bee2/src/core/u32.c
)
target_include_directories(bee2_hash PUBLIC . bee2/include)
target_compile_definitions(bee2_hash PRIVATE NDEBUG)
set_property(TARGET bee2_hash PROPERTY C_STANDARD 11)
