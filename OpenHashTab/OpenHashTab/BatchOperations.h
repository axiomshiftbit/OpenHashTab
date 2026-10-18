// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "Progress.h"
#include "Report.h"
#include <atomic>
#include <functional>
#include <string>
#include <vector>

class LegacyHashAlgorithm;
namespace oht {
using ProgressCallback = std::function<void(ProgressSnapshot)>;
std::vector<ResultRow> HashPaths(const std::vector<std::wstring>& paths, const LegacyHashAlgorithm& algorithm,
    const std::atomic<bool>& cancelled, ProgressCallback progress = {});
std::vector<ResultRow> ComparePaths(const std::wstring& left, const std::wstring& right, const LegacyHashAlgorithm& algorithm,
    const std::atomic<bool>& cancelled, ProgressCallback progress = {});
std::vector<ResultRow> VerifySumfile(const std::wstring& path, const LegacyHashAlgorithm& algorithm,
    const std::atomic<bool>& cancelled, ProgressCallback progress = {});
} // namespace oht
