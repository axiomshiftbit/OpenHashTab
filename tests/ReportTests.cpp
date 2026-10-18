// SPDX-License-Identifier: GPL-3.0-or-later
#include "Report.h"
#include "Progress.h"
#include <cstdio>
#include <limits>
#include <stdexcept>

static void Check(bool condition, const char* name) {
  if (!condition) throw std::runtime_error(name);
}
int main() {
  try {
    using namespace oht;
    std::vector<ResultRow> rows{{"a,\"b\"\r\nc", "SHA-256", "AB", "CD", ResultStatus::Mismatch, "read\tfailed\\path"}};
    const auto json = WriteReport(rows, ReportFormat::Json);
    Check(json.find("\"path\":\"a,\\\"b\\\"\\u000d\\u000ac\"") != std::string::npos, "JSON escapes quotes and line endings");
    Check(json.find("read\\u0009failed\\\\path") != std::string::npos, "JSON escapes tabs and backslashes");
    const auto csv = WriteReport(rows, ReportFormat::Csv);
    Check(csv == "path,algorithm,expected,actual,status,error\r\n\"a,\"\"b\"\"\r\nc\",\"SHA-256\",\"AB\",\"CD\",\"mismatch\",\"read\tfailed\\path\"\r\n", "RFC 4180 multiline CSV");
    for (const auto path : {"=1+2", "@SUM(A1)", "+1", "-1", "  =1", "\tname", "\rname", "\nname"}) {
      rows[0].path = path;
      Check(WriteReport(rows, ReportFormat::Csv).find(std::string("\"'") + path + "\"") != std::string::npos, "CSV formula neutralization");
      Check(WriteReport(rows, ReportFormat::Json).find("\"path\":\"'") == std::string::npos, "JSON preserves original path");
    }
    rows[0].path = "\xd1\x84\xd0\xb0\xd0\xb9\xd0\xbb \xf0\x9f\x93\x84";
    Check(WriteReport(rows, ReportFormat::Json).find(rows[0].path) != std::string::npos, "UTF-8 path preserved");
    rows[0].path = std::string("a\0b", 3);
    Check(WriteReport(rows, ReportFormat::Json).find("a\\u0000b") != std::string::npos, "JSON preserves embedded NUL as escape");
    Check(WriteReport({}, ReportFormat::Json) == "{\"schema_version\":1,\"results\":[\n]}\n", "empty report valid JSON");
    Check(ResultExitCode({}) == 0, "empty successful operation");
    for (const auto status : {ResultStatus::Computed, ResultStatus::Match, ResultStatus::Mismatch,
        ResultStatus::MissingLeft, ResultStatus::MissingRight, ResultStatus::Error, ResultStatus::Cancelled}) {
      rows[0].status = status;
      const auto expected = status == ResultStatus::Error ? 3 : status == ResultStatus::Cancelled ? 4 :
          status == ResultStatus::Computed || status == ResultStatus::Match ? 0 : 1;
      Check(ResultExitCode(rows) == expected, "distinct exit codes");
    }
    rows = {{"", "", "", "", ResultStatus::Mismatch, ""}, {"", "", "", "", ResultStatus::Error, ""}};
    Check(ResultExitCode(rows) == 3, "error outranks mismatch");
    std::reverse(rows.begin(), rows.end());
    Check(ResultExitCode(rows) == 3, "exit code independent of result order");
    rows.push_back({"", "", "", "", ResultStatus::Cancelled, ""});
    Check(ResultExitCode(rows) == 4, "cancellation outranks incomplete results");
    Check(!EstimateProgress({}, 0, false).available, "no startup ETA");
    Check(!EstimateProgress({1, 100}, 499, false).available, "no unstable initial ETA");
    const auto progress = EstimateProgress({250, 1000}, 2000, false);
    Check(progress.available && progress.bytes_per_second == 125 && progress.seconds_remaining == 6, "rate and ETA use bytes and elapsed time");
    Check(!EstimateProgress({250, 1000}, 2000, true).available, "no ETA after errors/cancellation");
    Check(!EstimateProgress({1001, 1000}, 2000, false).available, "progress above total cannot underflow");
    const auto maximum = std::numeric_limits<uint64_t>::max();
    Check(ProgressFraction({maximum, maximum}, 256) == 256, "fraction avoids integer multiplication overflow");
    Check(ProgressFraction({maximum, 1}, 256) == 256 && ProgressFraction({}, 256) == 0, "fraction clamped and empty safe");
    Check(std::isfinite(EstimateProgress({1, maximum}, maximum, false).seconds_remaining), "extreme ETA stays finite");
    std::puts("PASS: reports, escaping, formula handling, exit codes, progress and ETA");
    return 0;
  } catch (const std::exception& error) {
    std::fprintf(stderr, "FAIL: %s\n", error.what());
    return 1;
  }
}
