// SPDX-License-Identifier: GPL-3.0-or-later
#include "BeltHashState.h"
#include "bee2/src/crypto/belt/belt_hash.c"

// beltCompr_deep() in the pinned belt_compr.c is 12 * sizeof(u32).
// Check the actual private type, including its flexible-array alignment.
_Static_assert(sizeof(belt_hash_st) + 12 * sizeof(u32) <= sizeof(OhtBeltHashState),
               "Bee2 hash state exceeds the inline buffer");
_Static_assert(_Alignof(belt_hash_st) <= _Alignof(OhtBeltHashState),
               "Bee2 hash state requires stronger alignment");
