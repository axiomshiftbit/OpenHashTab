// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <string>
#include <string_view>
#include <vector>

namespace oht {
enum class ResultStatus { Computed, Match, Mismatch, MissingLeft, MissingRight, Error, Cancelled };
struct ResultRow {
  std::string path;
  std::string algorithm;
  std::string expected;
  std::string actual;
  ResultStatus status{ResultStatus::Computed};
  std::string error;
};
enum class ReportFormat { Json, Csv };
const char* StatusName(ResultStatus status);
std::string WriteReport(const std::vector<ResultRow>& rows, ReportFormat format);
// 0: success, 1: differences, 3: read/operation error, 4: cancelled.
// Invalid CLI usage is handled separately with exit code 2.
int ResultExitCode(const std::vector<ResultRow>& rows);
} // namespace oht
