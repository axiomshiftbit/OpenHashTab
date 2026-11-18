// SPDX-License-Identifier: GPL-3.0-or-later
#include "ReportUI.h"
#include "Coordinator.h"
#include "FileHashTask.h"
#include "utl.h"
#include <tuple>

std::wstring ResultStatusText(oht::ResultStatus status) {
  switch (status) {
  case oht::ResultStatus::Computed: return utl::GetString(IDS_RESULT_COMPUTED);
  case oht::ResultStatus::Match: return utl::GetString(IDS_MATCH_GROUP);
  case oht::ResultStatus::Mismatch: return utl::GetString(IDS_MISMATCH_GROUP);
  case oht::ResultStatus::MissingLeft: return utl::GetString(IDS_RESULT_MISSING_LEFT);
  case oht::ResultStatus::MissingRight: return utl::GetString(IDS_RESULT_MISSING_RIGHT);
  case oht::ResultStatus::Cancelled: return utl::GetString(IDS_CANCELLED);
  default: return utl::GetString(IDS_ERROR);
  }
}

void SaveReport(HWND owner, const std::vector<oht::ResultRow>& rows, oht::ReportFormat format) {
  const auto filename = format == oht::ReportFormat::Json ? L"verification-report.json" : L"verification-report.csv";
  const auto path = utl::SaveDialog(owner, nullptr, filename);
  if (path.empty()) return;
  const auto content = oht::WriteReport(rows, format);
  if (const auto error = utl::SaveMemoryAsFile(path.c_str(), content.data(), content.size())) {
    MessageBoxW(owner, utl::ErrorToString(error).c_str(), utl::GetString(IDS_ERROR).c_str(), MB_OK | MB_ICONERROR);
  }
}

static std::string HexString(const std::vector<uint8_t>& bytes) {
  std::string result(bytes.size() * 2, '\0');
  for (size_t i = 0; i < bytes.size(); ++i) {
    result[2 * i] = utl::hex<char>(bytes[i] >> 4, false);
    result[2 * i + 1] = utl::hex<char>(bytes[i] & 15, false);
  }
  return result;
}

std::vector<oht::ResultRow> VerificationReport(const Coordinator& coordinator, const std::vector<uint8_t>& check_against) {
  std::vector<oht::ResultRow> rows;
  for (const auto& file : coordinator.GetFiles()) {
    const auto path = utl::WideToUTF8(file->GetDisplayName().c_str());
    if (const auto error = file->GetError()) {
      const auto status = error == ERROR_CANCELLED || error == ERROR_OPERATION_ABORTED ?
          oht::ResultStatus::Cancelled : oht::ResultStatus::Error;
      const auto message = std::to_string(error) + ": " + utl::WideToUTF8(utl::ErrorToString(error).c_str());
      const auto index = coordinator.GetSumfileAlgorithm();
      const std::string name = index >= 0 && check_against.empty() ? LegacyHashAlgorithm::Algorithms()[index].GetName() : "";
      if (!check_against.empty()) rows.push_back({path, {}, HexString(check_against), {}, status, message});
      else if (!file->GetExpectedHashes().empty()) {
        for (const auto& expected : file->GetExpectedHashes()) {
          const auto algorithm = expected.algorithm >= 0 ? LegacyHashAlgorithm::Algorithms()[expected.algorithm].GetName() : "";
          rows.push_back({path, algorithm, HexString(expected.value), {}, status, message});
        }
      } else rows.push_back({path, name, {}, {}, status, message});
      continue;
    }
    for (const auto& algorithm : LegacyHashAlgorithm::Algorithms()) {
      const auto& actual = file->GetHashResult()[algorithm.Idx()];
      if (actual.empty()) continue;
      std::vector<const std::vector<uint8_t>*> expected;
      if (!check_against.empty()) {
        if (check_against.size() == actual.size()) expected.push_back(&check_against);
      } else {
        for (const auto& entry : file->GetExpectedHashes()) if (entry.AppliesTo(algorithm)) expected.push_back(&entry.value);
      }
      if (expected.empty()) rows.push_back({path, algorithm.GetName(), {}, HexString(actual), oht::ResultStatus::Computed, {}});
      for (const auto value : expected) {
        rows.push_back({path, algorithm.GetName(), HexString(*value), HexString(actual),
            *value == actual ? oht::ResultStatus::Match : oht::ResultStatus::Mismatch, {}});
      }
    }
    if (check_against.empty()) {
      const auto& algorithms = LegacyHashAlgorithm::Algorithms();
      for (const auto& entry : file->GetExpectedHashes()) {
        const bool reported = std::any_of(std::begin(algorithms), std::end(algorithms), [&](const auto& algorithm) {
          return entry.AppliesTo(algorithm) && !file->GetHashResult()[algorithm.Idx()].empty();
        });
        if (!reported) {
          const auto name = entry.algorithm >= 0 ? algorithms[entry.algorithm].GetName() : "";
          rows.push_back({path, name, HexString(entry.value), {}, oht::ResultStatus::Mismatch, {}});
        }
      }
    }
  }
  std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
    return std::tie(a.path, a.algorithm, a.expected, a.actual) < std::tie(b.path, b.algorithm, b.expected, b.actual);
  });
  return rows;
}
