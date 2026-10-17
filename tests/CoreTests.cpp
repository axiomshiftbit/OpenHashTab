// SPDX-License-Identifier: GPL-3.0-or-later
#include "Coordinator.h"
#include "FileHashTask.h"
#include "SumFileParser.h"
#include "Exporter.h"
#include "utl.h"
#include "json.h"
#include <filesystem>
#include <fstream>
#include <cstdio>

static void check(bool ok, const char* message) {
  if (!ok) throw std::runtime_error(message);
}
static int destroyed_contexts = 0;
static size_t ALGORITHMS_CC test_parameters(const uint64_t*) { return 1; }
static HashContext* ALGORITHMS_CC test_factory(void* buffer, const uint64_t*) { return static_cast<HashContext*>(buffer); }
static void ALGORITHMS_CC test_update(HashContext*, const void*, size_t) {}
static void ALGORITHMS_CC test_finish(HashContext*, uint8_t* out) { *out = 0; }
static size_t ALGORITHMS_CC test_size(HashContext*) { return 1; }
static void ALGORITHMS_CC test_destroy(HashContext*) { ++destroyed_contexts; }
static void ownership() {
  const HashAlgorithm algorithm(test_parameters, 16, 16, test_factory, test_update,
      test_finish, test_size, test_destroy, "test context lifetime", false, nullptr, 0);
  {
    auto first = algorithm.MakeContext(nullptr);
    auto second = algorithm.MakeContext(nullptr);
    first = std::move(second);
    check(destroyed_contexts == 1, "move assignment releases previous context");
    auto& same = first;
    first = std::move(same);
    check(first.IsInitialized() && destroyed_contexts == 1, "self move preserves context");
  }
  check(destroyed_contexts == 2, "each context destroyed once");
}

static std::filesystem::path root;
static void write(const std::filesystem::path& file, const std::string& contents) {
  std::filesystem::create_directories(file.parent_path());
  std::ofstream out(file, std::ios::binary);
  out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
  check(static_cast<bool>(out), "write test fixture");
}
static FileSumList parse(const std::string& text) {
  const auto file = root / L"checksums.txt";
  write(file, text);
  auto handle = utl::OpenForRead(file.wstring());
  check(handle != INVALID_HANDLE_VALUE, "open sumfile");
  FileSumList result;
  const auto error = TryParseSumFile(handle, result);
  CloseHandle(handle);
  check(error == ERROR_SUCCESS, "parse sumfile");
  return result;
}
static std::vector<uint8_t> digest(const LegacyHashAlgorithm& algorithm, std::string_view input, size_t chunk) {
  auto context = algorithm.MakeContext();
  check(context.IsInitialized(), "initialize algorithm");
  for (size_t offset = 0; offset < input.size(); offset += chunk)
    context.Update(input.data() + offset, std::min(chunk, input.size() - offset));
  std::vector<uint8_t> out(algorithm.GetSize() + 16, 0xA5);
  context.Finish(out.data());
  check(context.GetOutputSize() == algorithm.GetSize(), "digest size");
  check(std::all_of(out.begin() + algorithm.GetSize(), out.end(), [](auto v) { return v == 0xA5; }), "digest buffer guard");
  out.resize(algorithm.GetSize());
  return out;
}
static void hashing() {
  check(!LegacyHashAlgorithm::ByName("SHA-1")->IsSecure(), "SHA-1 is not collision resistant");
  struct Vector { const char* name; const char* input; const char* expected; };
  const Vector vectors[] = {
    {"CRC32", "123456789", "cbf43926"},
    {"MD4", "abc", "a448017aaf21d8525fc10ae87aa6729d"},
    {"MD5", "abc", "900150983cd24fb0d6963f7d28e17f72"},
    {"SHA-1", "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
    {"SHA-224", "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
    {"SHA-256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    {"SHA-384", "abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
    {"SHA-512", "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
    {"SHA3-256", "abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
    {"BLAKE3", "", "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"}
  };
  for (const auto& v : vectors) {
    const auto algorithm = LegacyHashAlgorithm::ByName(v.name);
    check(algorithm != nullptr, v.name);
    check(digest(*algorithm, v.input, 1) == utl::HashStringToBytes(std::string_view(v.expected)), v.name);
  }
  std::string data(2 * 1024 * 1024 + 17, '\0');
  for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<char>((i * 71 + 19) & 255);
  for (const auto& algorithm : LegacyHashAlgorithm::Algorithms()) {
    for (size_t size : {size_t(0), size_t(1), size_t(63), size_t(64), size_t(65), size_t(8191), size_t(8192), size_t(8193), data.size()}) {
      const auto input = std::string_view(data).substr(0, size);
      check(digest(algorithm, input, data.size()) == digest(algorithm, input, 127), algorithm.GetName());
    }
    std::printf("PASS: %s digest boundaries\n", algorithm.GetName());
  }
}
static void parsers() {
  const std::string filename = "folder\\file\"\n\t.bin";
  const auto serialized = "{\"name\":\"" + json_escape(filename) + "\"}";
  json_parser json(serialized.c_str());
  check(json.root() != nullptr, "escaped JSON parses");
  check(filename == json_getValue(json_getProperty(json.root(), "name")), "JSON path round trip");

  for (auto invalid : {"", "A", "AAA", "AA Z", "GG", "  A "})
    check(utl::HashStringToBytes(std::string_view(invalid)).empty(), "invalid hex rejected");
  check(utl::HashStringToBytes(std::string_view(" AA bb 00 ")) == std::vector<uint8_t>({170, 187, 0}), "spaced hex");
  check(utl::HashStringToBytes(std::string_view(std::string(132, 'a'))).size() == 66, "maximum hash length");
  check(utl::HashStringToBytes(std::string_view(std::string(134, 'a'))).empty(), "oversize hash rejected");
  check(utl::FindHashInString(std::wstring(1000, L'A')).empty(), "long clipboard hash rejected");
  check(utl::UTF8ToWide("\xff").empty(), "invalid UTF-8 rejected");
  check(utl::UTF8ToWide("\xd0\xa4\xd0\xb0\xd0\xb9\xd0\xbb") == L"\u0424\u0430\u0439\u043b", "Unicode conversion");
  auto sfv = parse("; comment\r\nfile with spaces.bin 352441c2\r\n");
  check(sfv.size() == 1 && sfv.front().first == "file with spaces.bin", "SFV filenames with spaces");
  check(parse("\xef\xbb\xbf" "352441c2 *file.bin\n").size() == 1, "UTF-8 BOM");
  check(parse("NSRBwg== *file.bin\n").size() == 1, "base64 sumfile");
  check(parse("NSRBw== *file.bin\n").empty(), "malformed base64 sumfile");
  check(parse("352441c2\n").size() == 1, "single hash");
  const std::string nul("352441c2 *file\0hidden.bin\n", 26);
  check(parse(nul).empty(), "embedded NUL filename rejected");
  DWORD before{}, after{};
  GetProcessHandleCount(GetCurrentProcess(), &before);
  for (int i = 0; i < 128; ++i) check(parse("352441c2\n").size() == 1, "repeat single hash parse");
  GetProcessHandleCount(GetCurrentProcess(), &after);
  check(after <= before + 2, "single-hash mapping handle leak");
  Settings settings;
  check(ProcessEverything({}, &settings).files.empty(), "empty selection");
  check(utl::MakePathLongCompatible(L"\\\\server\\share\\file") == L"\\\\?\\UNC\\server\\share\\file", "long UNC prefix");
}
static void file_hashing() {
  const auto tree = root / L"reparse";
  write(tree / L"target.txt", "abc");
  check(CreateSymbolicLinkW((tree / L"alias.txt").c_str(), (tree / L"target.txt").c_str(), 0) != FALSE, "create file symlink fixture");
  check(CreateSymbolicLinkW((tree / L"cycle").c_str(), tree.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY) != FALSE, "create directory cycle fixture");
  Settings tree_settings;
  check(ProcessEverything({tree.wstring()}, &tree_settings).files.size() == 2, "include file reparse points and skip directory cycles");

  auto file = root / L"\u0442\u0435\u0441\u0442 with spaces.bin";
  write(file, "abc");
  Coordinator coordinator({file.wstring()});
  for (auto& enabled : coordinator.settings.algorithms) enabled.SetNoSave(true);
  coordinator.AddFiles();
  coordinator.ProcessFiles();
  coordinator.WaitForCompletion();
  for (const auto& task : coordinator.GetFiles()) {
    check(task->GetError() == ERROR_SUCCESS, "async Unicode file hash");
    for (const auto& algorithm : LegacyHashAlgorithm::Algorithms())
      check(task->GetHashResult()[algorithm.Idx()] == digest(algorithm, "abc", 1), "async hash matches algorithm");
    std::list<FileHashTask*> tasks{task.get()};
    coordinator.settings.sumfile_banner.SetNoSave(false);
    const auto exported = Exporter::k_exporters.back()->GetExportString(&coordinator.settings, false, tasks);
    check(parse(exported).size() == 1, "SFV export/import round trip");
  }
  // Capture the original size, then truncate before submitting asynchronous I/O.
  Coordinator truncated({file.wstring()});
  truncated.AddFiles();
  write(file, "a");
  truncated.ProcessFiles();
  truncated.WaitForCompletion();
  check(truncated.GetFiles().front()->GetError() == ERROR_HANDLE_EOF, "short read must not produce a digest");
  for (const auto& hash : truncated.GetFiles().front()->GetHashResult()) check(hash.empty(), "failed read has no hash");
  auto long_file = root;
  for (int i = 0; i < 12; ++i) long_file /= L"long directory with spaces";
  long_file /= L"unicode-\u0424.bin";
  long_file = utl::MakePathLongCompatible(long_file.wstring());
  write(long_file, "abc");
  Coordinator long_path({long_file.wstring()});
  long_path.AddFiles();
  long_path.ProcessFiles();
  long_path.WaitForCompletion();
  check(long_path.GetFiles().front()->GetError() == ERROR_SUCCESS, "file path longer than MAX_PATH");
  auto empty = root / L"empty";
  write(empty, "");
  Coordinator empty_file({empty.wstring()});
  empty_file.AddFiles();
  empty_file.ProcessFiles();
  empty_file.WaitForCompletion();
  check(empty_file.GetFiles().front()->GetError() == ERROR_SUCCESS, "empty file hash");
  Coordinator missing({(root / L"missing").wstring()});
  missing.AddFiles();
  missing.ProcessFiles();
  missing.WaitForCompletion();
  check(missing.GetFiles().front()->GetError() != ERROR_SUCCESS, "missing file reports failure");
}
int main() {
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
  try {
    root = std::filesystem::temp_directory_path() / (L"OpenHashTabTests-" + std::to_wstring(GetCurrentProcessId()));
    std::filesystem::create_directories(root);
    ownership();
    hashing();
    parsers();
    file_hashing();
    std::filesystem::remove_all(root);
    std::puts("PASS: hashing, parsing, resource lifetime, asynchronous I/O and export tests");
    return 0;
  } catch (const std::exception& error) {
    std::fprintf(stderr, "FAIL: %s\n", error.what());
    return 1;
  }
}
