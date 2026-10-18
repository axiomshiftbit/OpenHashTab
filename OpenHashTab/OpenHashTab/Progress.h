// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <algorithm>
#include <cmath>
#include <cstdint>

namespace oht {
struct ProgressSnapshot {
  uint64_t processed{};
  uint64_t total{};
};
struct ProgressEstimate {
  double bytes_per_second{};
  double seconds_remaining{};
  bool available{};
};
inline ProgressEstimate EstimateProgress(ProgressSnapshot value, uint64_t elapsed_ms, bool finished) {
  // Avoid displaying an unstable estimate at startup or an ETA after errors/cancellation.
  if (elapsed_ms < 500 || value.processed == 0) return {};
  const auto speed = static_cast<double>(value.processed) * 1000.0 / static_cast<double>(elapsed_ms);
  const auto remaining = value.total - std::min(value.processed, value.total);
  return {speed, static_cast<double>(remaining) / speed, !finished && remaining != 0};
}
inline unsigned ProgressFraction(ProgressSnapshot value, unsigned resolution) {
  if (!value.total) return 0;
  return static_cast<unsigned>(static_cast<double>(std::min(value.processed, value.total)) /
      static_cast<double>(value.total) * resolution);
}
} // namespace oht
