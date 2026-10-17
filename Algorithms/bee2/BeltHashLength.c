/*
 * Copyright The Bee2 authors.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hash-only subset of bee2/src/crypto/belt/belt_lcl.c, copied unchanged from
 * e7e7c5ad073d7006c9ebde58ea596f37564d9e7c. Other functions in that translation
 * unit require polynomial arithmetic unrelated to belt-hash.
 */
#include "bee2/core/util.h"
#include "bee2/src/crypto/belt/belt_lcl.h"

void beltBlockAddBitSizeU32(u32 block[4], size_t count)
{
	register u32 carry = (u32)count << 3;
#if (B_PER_S < 32)
	carry = (block[0] += carry) < carry;
	carry = (block[1] += carry) < carry;
	carry = (block[2] += carry) < carry;
	block[3] += carry;
#else
	register size_t t = count >> 29;
	carry = (block[0] += carry) < carry;
	if ((block[1] += carry) < carry)
		block[1] = (u32)t;
	else
		carry = (block[1] += (u32)t) < (u32)t;
	t >>= 16, t >>= 16;
	if ((block[2] += carry) < carry)
		block[2] = (u32)t;
	else
		carry = (block[2] += (u32)t) < (u32)t;
	t >>= 16, t >>= 16;
	block[3] += carry;
	block[3] += (u32)t;
	CLEAN(t);
#endif
	CLEAN(carry);
}
