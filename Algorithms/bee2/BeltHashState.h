// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <bee2/core/mem.h>

// The pinned Bee2 implementation needs 200 bytes on 64-bit Windows.
// BeltHash.c checks the private state layout without duplicating it here.
typedef union {
  mem_align_t alignment;
  unsigned char bytes[256];
} OhtBeltHashState;
