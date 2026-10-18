// SPDX-License-Identifier: GPL-3.0-or-later
#include "BatchOperations.h"
#include "utl.h"
#include <Hasher.h>
#include <filesystem>
#include <fstream>
#include <cstdio>

namespace fs = std::filesystem;
static void Check(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}
static void Write(const fs::path& path, std::string_view content) {
  fs::create_directories(path.parent_path());
  std::ofstream stream(path, std::ios::binary);
  stream.write(content.data(), static_cast<std::streamsize>(content.size()));
  Check(static_cast<bool>(stream), "write batch fixture");
}
static const oht::ResultRow& Find(const std::vector<oht::ResultRow>& rows, const std::string& path) {
  const auto found = std::find_if(rows.begin(), rows.end(), [&](const auto& row) { return row.path == path; });
  if (found == rows.end()) throw std::runtime_error("missing comparison row: " + path);
  return *found;
}
int wmain() {
  fs::path root;
  try {
    wchar_t temporary[32768]{};
    Check(GetTempPathW(32768, temporary) != 0, "temporary path");
    root = fs::path(temporary) / (L"OpenHashTab-batch-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    Check(fs::create_directory(root), "isolated fixture directory");
    const auto algorithm = LegacyHashAlgorithm::ByName("SHA-256");
    Check(algorithm != nullptr, "SHA-256 registered");
    constexpr auto abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    std::atomic<bool> cancelled{};
    const auto left = root / L"left", right = root / L"right";
    for (const auto& directory : {left, right}) {
      Write(directory / L"same.bin", "abc");
      Write(directory / L"\u0444\u0430\u0439\u043b \U0001f4c4.bin", "abc");
      fs::create_directory(directory / L"empty");
    }
    Write(left / L"Case.bin", "abc"); Write(right / L"case.bin", "abc");
    Write(left / L"different.bin", "abc"); Write(right / L"different.bin", "abcd");
    Write(left / L"only-left.bin", "abc"); Write(right / L"only-right.bin", "abc");
    fs::create_directory(left / L"empty-left");
    auto rows = oht::ComparePaths(left.wstring(), right.wstring(), *algorithm, cancelled);
    Check(oht::ResultExitCode(rows) == 1, "folder differences exit code");
    Check(Find(rows, "same.bin").status == oht::ResultStatus::Match && Find(rows, "same.bin").actual == abc, "matching file hashes");
    Check(Find(rows, "different.bin").status == oht::ResultStatus::Mismatch, "different bytes");
    Check(Find(rows, "only-left.bin").status == oht::ResultStatus::MissingRight, "missing right file");
    Check(Find(rows, "only-right.bin").status == oht::ResultStatus::MissingLeft, "missing left file");
    Check(Find(rows, "empty/").status == oht::ResultStatus::Match, "empty directories compared");
    Check(Find(rows, "empty-left/").status == oht::ResultStatus::MissingRight, "missing empty directory");
    Check(Find(rows, "Case.bin").status == oht::ResultStatus::Match, "Windows case-insensitive path pairing");
    Check(Find(rows, utl::WideToUTF8(L"\u0444\u0430\u0439\u043b \U0001f4c4.bin")).actual == abc, "Unicode relative paths");
    Check(oht::ResultExitCode(oht::ComparePaths(left.wstring(), left.wstring(), *algorithm, cancelled)) == 0, "self comparison");
    rows = oht::ComparePaths((left / L"same.bin").wstring(), (right / L"same.bin").wstring(), *algorithm, cancelled);
    Check(rows.size() == 1 && rows[0].status == oht::ResultStatus::Match, "compare two files");
    rows = oht::ComparePaths((left / L"same.bin").wstring(), (right / L"empty").wstring(), *algorithm, cancelled);
    Check(rows.size() == 1 && rows[0].status == oht::ResultStatus::Mismatch && rows[0].actual.empty(), "file-directory type mismatch is not a hash");

    const auto checksum = left / L"checks.sha256";
    Write(checksum, std::string(abc) + " *same.bin\n");
    rows = oht::VerifySumfile(checksum.wstring(), *algorithm, cancelled);
    Check(rows.size() == 1 && rows[0].status == oht::ResultStatus::Match && rows[0].expected == abc, "verify expected and actual hash");
    Write(checksum, std::string(64, '0') + " *same.bin\n");
    Check(oht::ResultExitCode(oht::VerifySumfile(checksum.wstring(), *algorithm, cancelled)) == 1, "verification mismatch");
    Write(checksum, std::string(abc) + " *missing.bin\n");
    Check(oht::ResultExitCode(oht::VerifySumfile(checksum.wstring(), *algorithm, cancelled)) == 3, "unreadable expected file is an error");
    for (const auto path : {"../right/same.bin", "C:\\Windows\\win.ini", "\\\\server\\share\\file"}) {
      Write(checksum, std::string(abc) + " *" + path + "\n");
      Check(oht::ResultExitCode(oht::VerifySumfile(checksum.wstring(), *algorithm, cancelled)) == 3, "external manifest path rejected");
    }
    Write(checksum, std::string(abc) + " *\xff-invalid.bin\n");
    rows = oht::VerifySumfile(checksum.wstring(), *algorithm, cancelled);
    Check(oht::ResultExitCode(rows) == 3 && rows.size() == 1 &&
        rows[0].path == utl::WideToUTF8(checksum.c_str()) &&
        oht::WriteReport(rows, oht::ReportFormat::Json).find('\xff') == std::string::npos,
        "invalid UTF-8 rejects the manifest without corrupting JSON output");
    for (const auto content : {"", "garbage\n", "352441c2 *same.bin\n"}) {
      Write(checksum, content);
      Check(oht::ResultExitCode(oht::VerifySumfile(checksum.wstring(), *algorithm, cancelled)) == 3, "invalid manifest or algorithm-length mismatch");
    }
    Write(checksum, std::string(abc) + " *same.bin\n");
    rows = oht::HashPaths({checksum.wstring()}, *algorithm, cancelled);
    Check(rows.size() == 1 && rows[0].status == oht::ResultStatus::Computed && rows[0].actual != abc, "hash command hashes checksum file literally");

    const auto locked = CreateFileW((left / L"same.bin").c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    Check(locked != INVALID_HANDLE_VALUE, "lock fixture");
    rows = oht::HashPaths({(left / L"same.bin").wstring()}, *algorithm, cancelled);
    CloseHandle(locked);
    Check(oht::ResultExitCode(rows) == 3 && rows[0].actual.empty() && !rows[0].error.empty(), "sharing errors are not empty-file digests");

    const auto large = root / L"large.bin";
    Write(large, std::string(3 * 1024 * 1024 + 17, 'x'));
    uint64_t processed = 0;
    bool tried_write = false, write_denied = false;
    rows = oht::HashPaths({large.wstring()}, *algorithm, cancelled, [&](oht::ProgressSnapshot progress) {
      Check(progress.processed >= processed && progress.processed <= progress.total, "monotonic bounded progress");
      processed = progress.processed;
      if (processed && !tried_write) {
        tried_write = true;
        const auto writer = CreateFileW(large.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        write_denied = writer == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION;
        if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
      }
    });
    Check(oht::ResultExitCode(rows) == 0 && processed == 3 * 1024 * 1024 + 17 && write_denied, "full byte accounting and concurrent writer protection");
    bool changed = false;
    rows = oht::HashPaths({large.wstring()}, *algorithm, cancelled, [&](oht::ProgressSnapshot progress) {
      if (!changed && !progress.processed) { changed = true; Write(large, "changed before opening"); }
    });
    Check(oht::ResultExitCode(rows) == 3 && rows[0].actual.empty(), "file changes after enumeration fail visibly");
    Write(large, std::string(3 * 1024 * 1024, 'x'));
    rows = oht::HashPaths({large.wstring()}, *algorithm, cancelled, [&](oht::ProgressSnapshot progress) {
      if (progress.processed) cancelled = true;
    });
    Check(oht::ResultExitCode(rows) == 4 && rows[0].actual.empty(), "cancellation cannot publish a partial digest");
    Check(oht::ResultExitCode(oht::ComparePaths(left.wstring(), right.wstring(), *algorithm, cancelled)) == 4, "cancel before folder enumeration");
    cancelled = false;

    Check(CreateSymbolicLinkW((left / L"cycle").c_str(), left.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY) != FALSE, "create cycle fixture");
    rows = oht::ComparePaths(left.wstring(), right.wstring(), *algorithm, cancelled);
    Check(Find(rows, "cycle/").status == oht::ResultStatus::Error, "directory link not traversed or silently ignored");
    Check(CreateSymbolicLinkW((left / L"file-link.bin").c_str(), (left / L"same.bin").c_str(), 0) != FALSE, "create file link fixture");
    rows = oht::HashPaths({(left / L"file-link.bin").wstring()}, *algorithm, cancelled);
    Check(oht::ResultExitCode(rows) == 0 && rows[0].actual == abc, "file link read normally");
    Check(CreateSymbolicLinkW((right / L"file-link.bin").c_str(), (right / L"same.bin").c_str(), 0) != FALSE, "create matching file link fixture");
    rows = oht::ComparePaths(left.wstring(), right.wstring(), *algorithm, cancelled);
    Check(Find(rows, "file-link.bin").status == oht::ResultStatus::Match && Find(rows, "file-link.bin").actual == abc,
        "enumerated file links use target metadata");
    Check(CreateSymbolicLinkW((left / L"broken-link.bin").c_str(), (left / L"absent-target.bin").c_str(), 0) != FALSE, "create broken file link fixture");
    rows = oht::HashPaths({(left / L"broken-link.bin").wstring()}, *algorithm, cancelled);
    Check(oht::ResultExitCode(rows) == 3 && rows[0].actual.empty(), "broken link fails without a digest");
    const auto report = root / L"report.json";
    const std::string payload(2 * 1024 * 1024 + 7, 'z');
    Check(utl::SaveMemoryAsFile(report.c_str(), payload.data(), payload.size()) == 0 && fs::file_size(report) == payload.size(), "multi-chunk report write");
    Check(utl::SaveMemoryAsFile(report.c_str(), nullptr, 0) == 0 && fs::file_size(report) == 0, "empty report write");
    fs::remove_all(root);
    std::puts("PASS: batch hashing, comparison, verification, paths, errors, cancellation, progress and report I/O");
    return 0;
  } catch (const std::exception& error) {
    std::fprintf(stderr, "FAIL: %s\n", error.what());
    std::error_code ignored;
    if (!root.empty()) fs::remove_all(root, ignored);
    return 1;
  }
}
