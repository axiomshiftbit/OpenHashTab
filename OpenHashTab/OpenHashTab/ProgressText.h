// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "Progress.h"
#include <string>

std::wstring ProgressText(oht::ProgressSnapshot progress, uint64_t elapsed_ms, bool finished);
