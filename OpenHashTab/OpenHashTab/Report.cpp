// SPDX-License-Identifier: GPL-3.0-or-later
#include "Report.h"
#include <array>

namespace oht {
const char* StatusName(ResultStatus status) {
  switch (status) {
  case ResultStatus::Computed: return "computed";
  case ResultStatus::Match: return "match";
  case ResultStatus::Mismatch: return "mismatch";
  case ResultStatus::MissingLeft: return "missing_left";
  case ResultStatus::MissingRight: return "missing_right";
  case ResultStatus::Error: return "error";
  case ResultStatus::Cancelled: return "cancelled";
  }
  return "error";
}

static std::string JsonString(std::string_view value) {
  constexpr char hex[] = "0123456789abcdef";
  std::string result = "\"";
  for (const unsigned char c : value) {
    if (c == '"' || c == '\\') { result += '\\'; result += static_cast<char>(c); }
    else if (c < 0x20) {
      result += "\\u00";
      result += hex[c >> 4];
      result += hex[c & 15];
    } else result += static_cast<char>(c);
  }
  result += '"';
  return result;
}

static std::string CsvString(std::string_view value) {
  std::string result = "\"";
  // Quotes alone do not prevent spreadsheets from evaluating file names as
  // formulas. JSON retains the exact original string for machine consumers.
  const auto first = value.find_first_not_of(" \t\r\n");
  if ((!value.empty() && (value.front() == '\t' || value.front() == '\r' || value.front() == '\n')) ||
      (first != value.npos && std::string_view("=+-@").find(value[first]) != value.npos)) result += '\'';
  for (const auto c : value) {
    if (c == '"') result += '"';
    result += c;
  }
  result += '"';
  return result;
}

std::string WriteReport(const std::vector<ResultRow>& rows, ReportFormat format) {
  constexpr std::array<const char*, 6> fields{"path", "algorithm", "expected", "actual", "status", "error"};
  std::string result = format == ReportFormat::Csv ?
      "path,algorithm,expected,actual,status,error\r\n" : "{\"schema_version\":1,\"results\":[";
  bool first_row = true;
  for (const auto& row : rows) {
    const std::array<std::string_view, 6> values{row.path, row.algorithm, row.expected, row.actual, StatusName(row.status), row.error};
    if (format == ReportFormat::Json) result += first_row ? "\n  {" : ",\n  {";
    for (size_t i = 0; i < values.size(); ++i) {
      if (i) result += ',';
      if (format == ReportFormat::Json) result += JsonString(fields[i]) + ":" + JsonString(values[i]);
      else result += CsvString(values[i]);
    }
    result += format == ReportFormat::Json ? "}" : "\r\n";
    first_row = false;
  }
  if (format == ReportFormat::Json) result += "\n]}\n";
  return result;
}

int ResultExitCode(const std::vector<ResultRow>& rows) {
  int result = 0;
  for (const auto& row : rows) {
    if (row.status == ResultStatus::Cancelled) return 4;
    if (row.status == ResultStatus::Error) result = 3;
    else if (result == 0 && (row.status == ResultStatus::Mismatch ||
        row.status == ResultStatus::MissingLeft || row.status == ResultStatus::MissingRight)) result = 1;
  }
  return result;
}
} // namespace oht
