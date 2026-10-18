// SPDX-License-Identifier: GPL-3.0-or-later
#include "BatchOperations.h"
#include "utl.h"
#include <Hasher.h>
#include <cstdio>

static std::atomic<bool> cancelled{};
static BOOL WINAPI ConsoleControl(DWORD type) {
  if (type != CTRL_C_EVENT && type != CTRL_BREAK_EVENT) return FALSE;
  cancelled.store(true);
  return TRUE;
}

static bool Output(DWORD stream, const std::string& text) {
  const auto handle = GetStdHandle(stream);
  DWORD mode{};
  if (GetConsoleMode(handle, &mode)) {
    const auto wide = utl::UTF8ToWide(text.c_str());
    for (size_t offset = 0; offset < wide.size();) {
      const auto count = static_cast<DWORD>(std::min<size_t>(wide.size() - offset, 16384));
      DWORD written{};
      if (!WriteConsoleW(handle, wide.data() + offset, count, &written, nullptr) || !written) return false;
      offset += written;
    }
  } else {
    for (size_t offset = 0; offset < text.size();) {
      const auto count = static_cast<DWORD>(std::min<size_t>(text.size() - offset, 1024 * 1024));
      DWORD written{};
      if (!WriteFile(handle, text.data() + offset, count, &written, nullptr) || !written) return false;
      offset += written;
    }
  }
  return true;
}

static const char help[] =
    "OpenHashTab CLI " CI_VERSION "\n"
    "Usage:\n"
    "  OpenHashTabCLI hash [options] <file-or-folder>...\n"
    "  OpenHashTabCLI verify [options] <checksum-file>\n"
    "  OpenHashTabCLI compare [options] <left-file-or-folder> <right-file-or-folder>\n"
    "  OpenHashTabCLI algorithms\n"
    "Options:\n"
    "  --algorithm NAME   Hash algorithm (default: SHA-256; see algorithms).\n"
    "  --format json|csv  Report format on stdout (default: json, UTF-8).\n"
    "  --progress         Byte progress on stderr, at most twice per second.\n"
    "  --                 End of options; subsequent arguments are paths.\n"
    "  --help             Show this help.\n"
    "  --version          Show version.\n"
    "Verification accepts GNU hex/base64 checksums or SFV, with named files.\n"
    "Paths in a checksum file must be relative, without '..', and are resolved\n"
    "from its directory. Select the algorithm explicitly for non-SHA-256 files.\n"
    "Folder comparison uses relative paths and case-insensitive ordinal names.\n"
    "Directory reparse points and ambiguous case aliases are reported as errors.\n"
    "File reparse points are read normally. Empty directories are compared.\n"
    "For comparison, expected is the left hash and actual is the right hash.\n"
    "CSV prefixes formula-like values with an apostrophe; JSON preserves them.\n"
    "Exit codes: 0 success, 1 mismatch/missing entry, 2 invalid arguments,\n"
    "            3 read/operation/output error, 4 cancelled (Ctrl+C/Ctrl+Break).\n";

int wmain(int argc, wchar_t** argv) {
  try {
    if (argc == 2 && !wcscmp(argv[1], L"--version")) return Output(STD_OUTPUT_HANDLE, CI_VERSION "\n") ? 0 : 3;
    if (argc < 2 || !wcscmp(argv[1], L"--help")) {
      return Output(STD_OUTPUT_HANDLE, help) ? (argc < 2 ? 2 : 0) : 3;
    }
    const std::wstring command = argv[1];
    if (command == L"algorithms" && argc == 2) {
      std::string names;
      for (const auto& algorithm : LegacyHashAlgorithm::Algorithms()) {
        names += std::string(algorithm.GetName()) + "\t" + std::to_string(algorithm.GetSize() * 8u) + " bits\n";
      }
      return Output(STD_OUTPUT_HANDLE, names) ? 0 : 3;
    }
    const auto usage = [](const char* error) {
      Output(STD_ERROR_HANDLE, std::string(error) + "\nUse OpenHashTabCLI --help.\n");
      return 2;
    };
    if (command != L"hash" && command != L"verify" && command != L"compare") return usage("Unknown command.");
    const LegacyHashAlgorithm* algorithm = LegacyHashAlgorithm::ByName("SHA-256");
    auto format = oht::ReportFormat::Json;
    bool options = true, show_progress = false;
    std::vector<std::wstring> paths;
    for (int i = 2; i < argc; ++i) {
      const std::wstring argument = argv[i];
      if (options && argument == L"--") { options = false; continue; }
      if (options && argument == L"--help") return Output(STD_OUTPUT_HANDLE, help) ? 0 : 3;
      if (options && argument == L"--progress") { show_progress = true; continue; }
      if (options && argument == L"--algorithm") {
        if (++i >= argc) return usage("Missing algorithm name.");
        const auto name = utl::WideToUTF8(argv[i]);
        algorithm = nullptr;
        for (const auto& candidate : LegacyHashAlgorithm::Algorithms()) {
          if (!_stricmp(candidate.GetName(), name.c_str())) { algorithm = &candidate; break; }
        }
        if (!algorithm) return usage("Unknown algorithm; run OpenHashTabCLI algorithms.");
        continue;
      }
      if (options && argument == L"--format") {
        if (++i >= argc) return usage("Missing report format.");
        if (!wcscmp(argv[i], L"json")) format = oht::ReportFormat::Json;
        else if (!wcscmp(argv[i], L"csv")) format = oht::ReportFormat::Csv;
        else return usage("Report format must be json or csv.");
        continue;
      }
      if (options && argument.starts_with(L"-")) return usage("Unknown option; use -- before a path starting with '-'.");
      if (argument.empty()) return usage("Empty path.");
      paths.push_back(argument);
    }
    if (paths.empty() || (command == L"verify" && paths.size() != 1) || (command == L"compare" && paths.size() != 2)) {
      return usage("Wrong number of paths.");
    }
    if (!SetConsoleCtrlHandler(ConsoleControl, TRUE)) {
      Output(STD_ERROR_HANDLE, "Cannot install cancellation handler.\n");
      return 3;
    }
    uint64_t last_progress{};
    const auto progress = [&](oht::ProgressSnapshot value) {
      const auto now = GetTickCount64();
      if (show_progress && now - last_progress >= 500) {
        Output(STD_ERROR_HANDLE, std::to_string(value.processed) + "/" + std::to_string(value.total) + " bytes\n");
        last_progress = now;
      }
    };
    const auto rows = command == L"hash" ? oht::HashPaths(paths, *algorithm, cancelled, progress) :
        command == L"verify" ? oht::VerifySumfile(paths[0], *algorithm, cancelled, progress) :
        oht::ComparePaths(paths[0], paths[1], *algorithm, cancelled, progress);
    SetConsoleCtrlHandler(ConsoleControl, FALSE);
    if (!Output(STD_OUTPUT_HANDLE, oht::WriteReport(rows, format))) {
      Output(STD_ERROR_HANDLE, "Cannot write report to stdout.\n");
      return 3;
    }
    return oht::ResultExitCode(rows);
  } catch (const std::exception& error) {
    Output(STD_ERROR_HANDLE, std::string("OpenHashTab: ") + error.what() + "\n");
    return 3;
  }
}
