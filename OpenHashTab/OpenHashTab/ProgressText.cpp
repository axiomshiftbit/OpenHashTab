// SPDX-License-Identifier: GPL-3.0-or-later
#include "ProgressText.h"
#include "utl.h"

static std::wstring FormatBytes(double bytes) {
  const wchar_t* units[] = {L"B", L"KiB", L"MiB", L"GiB", L"TiB", L"PiB", L"EiB"};
  size_t unit = 0;
  while (bytes >= 1024 && unit + 1 < std::size(units)) { bytes /= 1024; ++unit; }
  return utl::FormatString(unit ? L"%.1f %s" : L"%.0f %s", bytes, units[unit]);
}

std::wstring ProgressText(oht::ProgressSnapshot progress, uint64_t elapsed_ms, bool finished) {
  auto result = FormatBytes(static_cast<double>(progress.processed)) + L" / " + FormatBytes(static_cast<double>(progress.total));
  const auto estimate = oht::EstimateProgress(progress, elapsed_ms, finished);
  if (estimate.bytes_per_second > 0) {
    result += L"\n" + utl::FormatString(utl::GetString(IDS_PROGRESS_SPEED).c_str(), FormatBytes(estimate.bytes_per_second).c_str());
    if (estimate.available) {
      constexpr double limit = 9999.0 * 3600;
      const auto seconds = static_cast<uint64_t>(std::min(std::ceil(estimate.seconds_remaining), limit));
      const auto remaining = std::wstring(estimate.seconds_remaining > limit ? L"> " : L"") +
          utl::FormatString(L"%llu:%02u:%02u", seconds / 3600,
          static_cast<unsigned>(seconds / 60 % 60), static_cast<unsigned>(seconds % 60));
      result += L" · " + utl::FormatString(utl::GetString(IDS_PROGRESS_ETA).c_str(), remaining.c_str());
    }
  }
  return result;
}
