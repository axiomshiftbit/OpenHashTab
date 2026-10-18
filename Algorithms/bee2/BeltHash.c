// SPDX-License-Identifier: GPL-3.0-or-later
#include "BeltHashState.h"
#include "bee2/src/crypto/belt/belt_hash.c"

// beltCompr_deep() in the pinned belt_compr.c is 12 * sizeof(u32).
// Check the actual private type, including its flexible-array alignment.
// Negative array bounds also enforce these checks in CodeQL's MSVC C frontend,
// which does not recognize _Static_assert even when cl.exe uses /std:c11.
typedef char OhtBeltHashSizeCheck[
    sizeof(belt_hash_st) + 12 * sizeof(u32) <= sizeof(OhtBeltHashState) ? 1 : -1];
typedef char OhtBeltHashAlignmentCheck[
    _Alignof(belt_hash_st) <= _Alignof(OhtBeltHashState) ? 1 : -1];
