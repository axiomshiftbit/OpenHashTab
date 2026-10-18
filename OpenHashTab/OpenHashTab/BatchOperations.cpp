// SPDX-License-Identifier: GPL-3.0-or-later
#include "BatchOperations.h"
#include "SumFileParser.h"
#include "utl.h"
#include <Hasher.h>
#include <filesystem>
#include <limits>
#include <map>

namespace oht {
namespace {
namespace fs = std::filesystem;
struct Entry {
  std::wstring path;
  bool directory{};
  uint64_t size{};
  FILETIME modified{};
  DWORD error{};
};
struct PathLess {
  bool operator()(const std::wstring& left, const std::wstring& right) const {
    return CompareStringOrdinal(left.c_str(), -1, right.c_str(), -1, TRUE) == CSTR_LESS_THAN;
  }
};
using Inventory = std::map<std::wstring, Entry, PathLess>;
struct FileHandle {
  HANDLE value{INVALID_HANDLE_VALUE};
  ~FileHandle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
  FileHandle(const FileHandle&) = delete;
  FileHandle& operator=(const FileHandle&) = delete;
  explicit FileHandle(HANDLE handle) : value(handle) {}
};
struct FindHandle {
  HANDLE value{INVALID_HANDLE_VALUE};
  ~FindHandle() { if (value != INVALID_HANDLE_VALUE) FindClose(value); }
};

static Entry Inspect(const std::wstring& path) {
  Entry result;
  result.path = utl::MakePathLongCompatible(path);
  WIN32_FILE_ATTRIBUTE_DATA data{};
  if (!GetFileAttributesExW(result.path.c_str(), GetFileExInfoStandard, &data)) result.error = GetLastError();
  else {
    result.directory = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    result.size = result.directory ? 0 : (uint64_t{data.nFileSizeHigh} << 32) | data.nFileSizeLow;
    result.modified = data.ftLastWriteTime;
    if (result.directory && (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) result.error = ERROR_NOT_SUPPORTED;
    else if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
      // GetFileAttributesEx describes the link itself. Read target metadata from
      // a normal handle so the later consistency check compares the same file.
      FileHandle target(CreateFileW(result.path.c_str(), FILE_READ_ATTRIBUTES,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
      BY_HANDLE_FILE_INFORMATION info{};
      if (target.value == INVALID_HANDLE_VALUE) result.error = GetLastError();
      else if (GetFileType(target.value) != FILE_TYPE_DISK) result.error = ERROR_NOT_SUPPORTED;
      else if (!GetFileInformationByHandle(target.value, &info)) result.error = GetLastError();
      else if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) result.error = ERROR_DIRECTORY;
      else {
        result.size = (uint64_t{info.nFileSizeHigh} << 32) | info.nFileSizeLow;
        result.modified = info.ftLastWriteTime;
      }
    }
  }
  return result;
}

static Inventory Collect(const std::wstring& root, const std::atomic<bool>& cancelled) {
  Inventory entries;
  entries.emplace(L".", Inspect(root));
  std::vector<std::wstring> pending{L"."};
  while (!pending.empty() && !cancelled.load()) {
    const auto relative = std::move(pending.back());
    pending.pop_back();
    auto& parent = entries.at(relative);
    if (!parent.directory || parent.error) continue;
    WIN32_FIND_DATAW data{};
    const auto pattern = (fs::path(parent.path) / L"*").wstring();
    FindHandle find{FindFirstFileW(pattern.c_str(), &data)};
    if (find.value == INVALID_HANDLE_VALUE) {
      const auto error = GetLastError();
      if (error != ERROR_FILE_NOT_FOUND) parent.error = error;
      continue;
    }
    do {
      if (cancelled.load()) break;
      if (!wcscmp(data.cFileName, L".") || !wcscmp(data.cFileName, L"..")) continue;
      const auto child_relative = relative == L"." ? std::wstring(data.cFileName) : relative + L"/" + data.cFileName;
      Entry child;
      child.path = (fs::path(parent.path) / data.cFileName).wstring();
      child.directory = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
      child.size = child.directory ? 0 : (uint64_t{data.nFileSizeHigh} << 32) | data.nFileSizeLow;
      child.modified = data.ftLastWriteTime;
      if (child.directory && (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) child.error = ERROR_NOT_SUPPORTED;
      else if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) child = Inspect(child.path);
      const auto [position, added] = entries.emplace(child_relative, std::move(child));
      // Case-sensitive NTFS directories can contain names which would otherwise
      // alias in Windows-style comparison. Never silently discard that ambiguity.
      if (!added) { position->second.error = ERROR_DUP_NAME; parent.error = ERROR_DUP_NAME; }
      else if (position->second.directory && !position->second.error) pending.push_back(child_relative);
    } while (FindNextFileW(find.value, &data));
    if (!cancelled.load()) {
      const auto error = GetLastError();
      if (error != ERROR_NO_MORE_FILES) parent.error = error;
    }
  }
  return entries;
}

static std::string Hex(const std::vector<uint8_t>& bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(bytes.size() * 2);
  for (const auto byte : bytes) { result += digits[byte >> 4]; result += digits[byte & 15]; }
  return result;
}

static void SetError(ResultRow& row, DWORD error) {
  row.status = error == ERROR_CANCELLED ? ResultStatus::Cancelled : ResultStatus::Error;
  row.error = std::to_string(error) + ": " + utl::WideToUTF8(utl::ErrorToString(error).c_str());
}

class Runner {
  const LegacyHashAlgorithm& algorithm;
  const std::atomic<bool>& cancelled;
  ProgressCallback callback;
  ProgressSnapshot progress;
public:
  Runner(const LegacyHashAlgorithm& hash, const std::atomic<bool>& cancel, ProgressCallback cb)
      : algorithm(hash), cancelled(cancel), callback(std::move(cb)) {}
  void AddSize(const Entry& entry) {
    if (!entry.directory && !entry.error) {
      progress.total += std::min(entry.size, std::numeric_limits<uint64_t>::max() - progress.total);
    }
  }
  void Notify() const { if (callback) callback(progress); }
  ResultRow Row(const std::wstring& path) const {
    return {utl::WideToUTF8(path.c_str()), algorithm.GetName(), {}, {}, ResultStatus::Computed, {}};
  }
  bool Cancel(ResultRow& row) const {
    if (!cancelled.load()) return false;
    SetError(row, ERROR_CANCELLED);
    return true;
  }
  DWORD Digest(const Entry& entry, std::string& result) {
    if (cancelled.load()) return ERROR_CANCELLED;
    if (entry.error) return entry.error;
    if (entry.directory) return ERROR_DIRECTORY;
    // Deny new writers/deletion while reading. Existing writers yield a sharing
    // error instead of a misleading digest of a changing stream.
    FileHandle file(CreateFileW(entry.path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) return GetLastError();
    if (GetFileType(file.value) != FILE_TYPE_DISK) return ERROR_NOT_SUPPORTED;
    BY_HANDLE_FILE_INFORMATION before{};
    if (!GetFileInformationByHandle(file.value, &before)) return GetLastError();
    const auto size = (uint64_t{before.nFileSizeHigh} << 32) | before.nFileSizeLow;
    if ((before.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || size != entry.size ||
        CompareFileTime(&before.ftLastWriteTime, &entry.modified)) return ERROR_FILE_INVALID;
    auto hash = algorithm.MakeContext();
    std::vector<uint8_t> buffer(1024 * 1024);
    uint64_t read_total = 0;
    while (true) {
      if (cancelled.load()) return ERROR_CANCELLED;
      DWORD count{};
      if (!ReadFile(file.value, buffer.data(), static_cast<DWORD>(buffer.size()), &count, nullptr)) {
        return cancelled.load() ? ERROR_CANCELLED : GetLastError();
      }
      if (!count) break;
      hash.Update(buffer.data(), count);
      read_total += count;
      progress.processed += count;
      Notify();
    }
    BY_HANDLE_FILE_INFORMATION after{};
    if (!GetFileInformationByHandle(file.value, &after)) return GetLastError();
    if (read_total != size || before.nFileSizeHigh != after.nFileSizeHigh || before.nFileSizeLow != after.nFileSizeLow ||
        CompareFileTime(&before.ftLastWriteTime, &after.ftLastWriteTime)) return ERROR_FILE_INVALID;
    if (cancelled.load()) return ERROR_CANCELLED;
    std::vector<uint8_t> digest(algorithm.GetSize());
    hash.Finish(digest.data());
    result = Hex(digest);
    return ERROR_SUCCESS;
  }
};
} // namespace

std::vector<ResultRow> HashPaths(const std::vector<std::wstring>& paths, const LegacyHashAlgorithm& algorithm,
    const std::atomic<bool>& cancelled, ProgressCallback progress) {
  Runner runner(algorithm, cancelled, std::move(progress));
  std::vector<Inventory> inventories;
  for (const auto& path : paths) {
    inventories.push_back(Collect(path, cancelled));
    for (const auto& [name, entry] : inventories.back()) runner.AddSize(entry);
    if (cancelled.load()) break;
  }
  runner.Notify();
  std::vector<ResultRow> result;
  for (size_t i = 0; i < inventories.size(); ++i) {
    for (const auto& [name, entry] : inventories[i]) {
      if (entry.directory && !entry.error && !cancelled.load()) continue;
      auto row = runner.Row(name == L"." ? paths[i] : (fs::path(paths[i]) / name).wstring());
      if (runner.Cancel(row)) { result.push_back(std::move(row)); return result; }
      if (const auto error = runner.Digest(entry, row.actual)) SetError(row, error);
      result.push_back(std::move(row));
    }
  }
  return result;
}

std::vector<ResultRow> ComparePaths(const std::wstring& left, const std::wstring& right, const LegacyHashAlgorithm& algorithm,
    const std::atomic<bool>& cancelled, ProgressCallback progress) {
  Runner runner(algorithm, cancelled, std::move(progress));
  const auto lhs = Collect(left, cancelled);
  const auto rhs = Collect(right, cancelled);
  std::map<std::wstring, std::pair<const Entry*, const Entry*>, PathLess> pairs;
  for (const auto& [name, entry] : lhs) { pairs[name].first = &entry; runner.AddSize(entry); }
  for (const auto& [name, entry] : rhs) { pairs[name].second = &entry; runner.AddSize(entry); }
  runner.Notify();
  std::vector<ResultRow> result;
  for (const auto& [name, pair] : pairs) {
    const auto [a, b] = pair;
    auto row = runner.Row(name);
    if (runner.Cancel(row)) { result.push_back(std::move(row)); break; }
    if ((a && a->error) || (b && b->error)) {
      SetError(row, a && a->error ? a->error : b->error);
    } else if (!a || !b) {
      row.status = a ? ResultStatus::MissingRight : ResultStatus::MissingLeft;
      const auto& present = a ? *a : *b;
      if (!present.directory) {
        if (const auto error = runner.Digest(present, a ? row.expected : row.actual)) SetError(row, error);
      } else row.algorithm.clear();
    } else if (a->directory != b->directory) {
      row.status = ResultStatus::Mismatch;
      row.error = a->directory ? "Entry types differ: left directory, right file." : "Entry types differ: left file, right directory.";
      row.algorithm.clear();
    } else if (a->directory) {
      row.status = ResultStatus::Match;
      row.algorithm.clear();
    } else {
      const auto error_left = runner.Digest(*a, row.expected);
      const auto error_right = error_left == ERROR_CANCELLED ? ERROR_CANCELLED : runner.Digest(*b, row.actual);
      if (error_left || error_right) SetError(row, error_left == ERROR_CANCELLED || error_right == ERROR_CANCELLED ?
          ERROR_CANCELLED : error_left ? error_left : error_right);
      else row.status = row.expected == row.actual ? ResultStatus::Match : ResultStatus::Mismatch;
    }
    if ((a && a->directory) || (b && b->directory)) row.path += '/';
    result.push_back(std::move(row));
    if (result.back().status == ResultStatus::Cancelled) break;
  }
  return result;
}

std::vector<ResultRow> VerifySumfile(const std::wstring& path, const LegacyHashAlgorithm& algorithm,
    const std::atomic<bool>& cancelled, ProgressCallback progress) {
  Runner runner(algorithm, cancelled, std::move(progress));
  auto failure = runner.Row(path);
  if (runner.Cancel(failure)) return {failure};
  FileHandle file(CreateFileW(utl::MakePathLongCompatible(path).c_str(), GENERIC_READ, FILE_SHARE_READ,
      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (file.value == INVALID_HANDLE_VALUE) { SetError(failure, GetLastError()); return {failure}; }
  FileSumList sums;
  const auto error = TryParseSumFile(file.value, sums);
  if (error || sums.empty()) { SetError(failure, error ? error : ERROR_INVALID_DATA); return {failure}; }
  const auto base = fs::path(utl::MakePathLongCompatible(path)).parent_path();
  std::vector<Entry> entries;
  for (const auto& [name, expected] : sums) {
    const auto wide = utl::UTF8ToWide(name.c_str());
    const fs::path relative(wide);
    const auto unsafe = wide.empty() || relative.has_root_path() ||
        std::find(relative.begin(), relative.end(), fs::path(L"..")) != relative.end();
    auto entry = unsafe ? Entry{} : Inspect((base / relative).wstring());
    if (unsafe || expected.size() != algorithm.GetSize()) entry.error = ERROR_INVALID_DATA;
    runner.AddSize(entry);
    entries.push_back(std::move(entry));
  }
  runner.Notify();
  std::vector<ResultRow> result;
  size_t index = 0;
  for (const auto& [name, expected] : sums) {
    ResultRow row{name, algorithm.GetName(), Hex(expected), {}, ResultStatus::Computed, {}};
    if (runner.Cancel(row)) { result.push_back(std::move(row)); break; }
    const auto error = runner.Digest(entries[index++], row.actual);
    if (error) SetError(row, error);
    else row.status = row.expected == row.actual ? ResultStatus::Match : ResultStatus::Mismatch;
    result.push_back(std::move(row));
  }
  return result;
}
} // namespace oht
