// SPDX-License-Identifier: GPL-3.0-or-later
#include "Coordinator.h"
#include "ReportUI.h"
#include "FileHashTask.h"
#include "SumFileParser.h"
#include "Exporter.h"
#include "utl.h"
#include "json.h"
#include "wnd.h"
#include "https.h"
#include "virustotal.h"
#include <filesystem>
#include <fstream>
#include <cstdio>
#include <winioctl.h>
#include "AdditionalHashVectors.h"
#include "OfficialHashVectors.h"
#include "StreamingHashVectors.h"
#include "ExtendedHashVectors.h"

static void check(bool ok, const char* message) {
  if (!ok) throw std::runtime_error(message);
}
// Exercise the production response handlers without credentials or network I/O.
static HTTPResult http_reply{};
static std::string http_request_body;
HTTPResult DoHTTPS(const HTTPRequest& request) {
  http_request_body = request.body ? std::string(static_cast<const char*>(request.body), request.body_size) : std::string{};
  return http_reply;
}

static void network_responses() {
  const auto winhttp = LoadLibraryExW(L"winhttp.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  check(winhttp != nullptr, "load localized WinHTTP error messages");
  for (const auto error : {ERROR_WINHTTP_TIMEOUT, ERROR_WINHTTP_NAME_NOT_RESOLVED, ERROR_WINHTTP_CANNOT_CONNECT}) {
    http_reply = {};
    http_reply.error_code = error;
    http_reply.error_location = 5;
    const auto message = utl::ErrorToString(error);
    check(!message.empty(), "localized WinHTTP error text exists");
    for (bool update : {false, true}) {
      bool caught = false;
      try {
        if (update) (void)utl::GetLatestVersion();
        else (void)vt::Query({}, 0);
      } catch (const std::runtime_error& e) {
        const auto text = utl::UTF8ToWide(e.what());
        check(text.find(message) != std::wstring::npos, "network error retains its localized text as UTF-8");
        caught = true;
      }
      check(caught, "network failure becomes a displayable runtime error");
    }
  }
  FreeLibrary(winhttp);
  http_reply = {};
  http_reply.http_code = 200;
  http_reply.body = R"({"tag_name":"v3.1.2"})";
  check(utl::GetLatestVersion() == utl::Version{3, 1, 2}, "parse a valid update response");
  http_reply.body = R"({"data":[]})";
  check(vt::Query({}, 0).empty(), "empty VirusTotal request has no file reports");
  for (const auto body : {"", "{", "[]", R"({"data":false})", R"({"tag_name":false})"}) {
    http_reply.body = body;
    for (bool update : {false, true}) {
      bool caught = false;
      try {
        if (update) (void)utl::GetLatestVersion();
        else (void)vt::Query({}, 0);
      } catch (const std::runtime_error&) { caught = true; }
      check(caught, "malformed service response becomes a displayable runtime error");
    }
  }
  std::puts("PASS: localized network errors and service response validation");
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
  context.Update(nullptr, 0);
  for (size_t offset = 0; offset < input.size(); offset += chunk)
    context.Update(input.data() + offset, std::min(chunk, input.size() - offset));
  context.Update(nullptr, 0);
  std::vector<uint8_t> out(algorithm.GetSize() + 32, 0xA5);
  context.Finish(out.data() + 16);
  check(context.GetOutputSize() == algorithm.GetSize(), "digest size");
  check(std::all_of(out.begin(), out.begin() + 16, [](auto v) { return v == 0xA5; }) &&
      std::all_of(out.begin() + 16 + algorithm.GetSize(), out.end(), [](auto v) { return v == 0xA5; }), "digest buffer guards");
  return {out.begin() + 16, out.end() - 16};
}
static void hashing() {
  check(!LegacyHashAlgorithm::ByName("SHA-1")->IsSecure(), "SHA-1 is not collision resistant");
  check(!LegacyHashAlgorithm::ByName("RipeMD160")->IsSecure(), "RIPEMD-160 provides only 80-bit generic collision resistance");
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
    {"BLAKE3", "", "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"},
    // Published upstream vectors and independent reference values; see HashVectors.md.
    {"CRC64", "123456789", "995dc9bbdf1939fa"},
    {"XXH32", "", "02cc5d05"},
    {"XXH64", "", "ef46db3751d8e999"},
    {"XXH3-64", "", "2d06800538d394c2"},
    {"XXH3-128", "", "99aa06d3014798d86001c324468d497f"},
    {"RipeMD160", "abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
    {"Blake2sp", "", "dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f"},
    {"SHA3-224", "", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"},
    {"SHA3-384", "", "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"},
    {"SHA3-512", "", "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"},
    {"K12-264", "", "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e542"},
    {"K12-256", "", "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5"},
    {"K12-512", "", "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e54269c056b8c82e48276038b6d292966cc07a3d4645272e31ff38508139eb0a71"},
    {"BLAKE3-512", "", "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a"},
    {"eD2k", "abc", "a448017aaf21d8525fc10ae87aa6729d"},
    {"eD2k (Old)", "abc", "a448017aaf21d8525fc10ae87aa6729d"},
    {"QuickXorHash", "", "0000000000000000000000000000000000000000"},
    // Independently composed from SHAKE/cSHAKE per NIST SP 800-185, B=8192.
    {"PH128-264", "", "922fa19859b2c701f0d9d8e3eed3cb7fb8910af6220bff0f6b8f062dbfa3bd3331"},
    {"PH128-264", "abc", "493a6004492b1b7b14be32fe0bbb4f780183cb8311c17f9ac2ab0454d8940b1f33"},
    {"PH256-528", "", "7c432b8652dc77d082097f80d1fa29b22e3e061d284c9574cdf80750a91bcf135db4930ee8cef82b46751f6347f3262732b0bb91cf38835a2c61d17af6510d203de6"},
    {"PH256-528", "abc", "44d4ea7d0c3dc171711d98bfce531a1bec23c160c6d6ed9379a1b671f025e66083264e7bcd825d497eda24b88220897e2dbfd86b24c915f03a91addd75f13275511d"}
  };
  for (const auto& v : vectors) {
    const auto algorithm = LegacyHashAlgorithm::ByName(v.name);
    check(algorithm != nullptr, v.name);
    check(digest(*algorithm, v.input, 1) == utl::HashStringToBytes(std::string_view(v.expected)), v.name);
  }
  std::string data(2 * 1024 * 1024 + 17, '\0');
  for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<char>((i * 71 + 19) & 255);
  for (const auto& vector : additional_vectors) {
    const auto algorithm = LegacyHashAlgorithm::ByName(vector.name);
    check(algorithm != nullptr, vector.name);
    const auto expected = utl::HashStringToBytes(std::string_view(vector.expected));
    const auto input = std::string_view(data).substr(0, vector.size);
    check(digest(*algorithm, input, data.size()) == expected, vector.name);
    check(digest(*algorithm, input, 127) == expected, vector.name);
  }
  for (const auto& algorithm : LegacyHashAlgorithm::Algorithms()) {
    const auto name = std::string_view(algorithm.GetName());
    check(std::any_of(std::begin(vectors), std::end(vectors), [&](const auto& v) { return name == v.name; }) ||
        std::any_of(std::begin(official_vectors), std::end(official_vectors), [&](const auto& v) { return name == v.name; }) ||
        std::any_of(std::begin(extended_vectors), std::end(extended_vectors), [&](const auto& v) { return name == v.name; }),
        "every registered algorithm needs a known-answer vector");
    for (size_t size : {size_t(0), size_t(1), size_t(63), size_t(64), size_t(65), size_t(8191), size_t(8192), size_t(8193), data.size()}) {
      const auto input = std::string_view(data).substr(0, size);
      check(digest(algorithm, input, data.size()) == digest(algorithm, input, 127), algorithm.GetName());
    }
    std::printf("PASS: %s digest boundaries\n", algorithm.GetName());
  }
}
static void official_hash_vectors() {
  for (const auto& vector : official_vectors) {
    const auto algorithm = LegacyHashAlgorithm::ByName(vector.name);
    check(algorithm != nullptr, vector.name);
    // Fixture messages can be longer than the production digest-parser limit.
    const std::string hex(vector.input_hex);
    std::string input;
    for (size_t i = 0; i < hex.size(); i += 2)
      input.push_back(static_cast<char>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    const auto expected = utl::HashStringToBytes(std::string_view(vector.expected));
    for (const size_t chunk : {size_t(1), size_t(31), size_t(127), size_t(8192)})
      check(digest(*algorithm, input, chunk) == expected, vector.name);
  }
  std::printf("PASS: %zu official SHA-512/t, SHAKE, Streebog and BelT vectors, four streaming patterns each\n", std::size(official_vectors));
}
static void streaming_hash_vectors() {
  for (const auto& vector : streaming_vectors) {
    const auto algorithm = LegacyHashAlgorithm::ByName(vector.name);
    check(algorithm != nullptr, vector.name);
    std::string input(vector.size, '\0');
    uint64_t generator = 2654435761U;
    for (size_t i = 0; i < input.size(); ++i) {
      input[i] = static_cast<char>(vector.pattern == 2 ? generator >> 56 : i % (vector.pattern == 0 ? 251 : 256));
      generator *= 11400714785074694797ULL;
    }
    const auto expected = utl::HashStringToBytes(std::string_view(vector.expected));
    for (const size_t chunk : {size_t(1), size_t(127), size_t(8192)})
      check(digest(*algorithm, input, chunk) == expected, vector.name);
  }
  std::printf("PASS: %zu published xxHash, BLAKE2sp, BLAKE3 and K12 vectors, three streaming patterns each\n", std::size(streaming_vectors));
}
static void extended_hash_vectors() {
  for (const auto& vector : extended_vectors) {
    const auto algorithm = LegacyHashAlgorithm::ByName(vector.name);
    check(algorithm != nullptr, vector.name);
    const std::string hex(vector.input_hex);
    std::string input;
    for (size_t i = 0; i < hex.size(); i += 2)
      input.push_back(static_cast<char>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    const auto expected = utl::HashStringToBytes(std::string_view(vector.expected));
    for (const size_t chunk : {size_t(1), size_t(7), size_t(31), size_t(127), size_t(8192)})
      check(digest(*algorithm, input, chunk) == expected, vector.name);
  }
  for (const auto& vector : extended_long_vectors) {
    const auto algorithm = LegacyHashAlgorithm::ByName(vector.name);
    check(algorithm != nullptr, vector.name);
    std::string input(vector.size, '\0');
    for (size_t i = 0; i < input.size(); ++i) input[i] = static_cast<char>(i % 251);
    const auto expected = utl::HashStringToBytes(std::string_view(vector.expected));
    for (const size_t chunk : {size_t(127), size_t(8192), size_t(8193), input.size()})
      check(digest(*algorithm, input, chunk) == expected, vector.name);
  }
  std::printf("PASS: %zu extended hash vectors and %zu large RFC 9861 vectors\n",
      std::size(extended_vectors), std::size(extended_long_vectors));
}
static void large_hash_updates() {
  // One 512 MiB + 17 byte update overflowed size_t * 8 in x86 builds.
  // Independent hashlib/cSHAKE reference values are described in HashVectors.md.
  const std::string input((size_t(1) << 29) + 17, '\0');
  struct Vector { const char* name; const char* expected; };
  const Vector vectors[] = {
    {"SHAKE128-256", "3d68417459a8be08c7e49618c3fe61832f8ca388aee32360eab2975917c368fa"},
    {"PH128-264", "d3ed977f66fa8bfc05819e19c862376eb26165bee7cef8aaf8edf27d53c69b3cbb"},
    {"PH256-528", "7be21c8d2a9e804a6fc8893db8a3443f085a06c07186783e244dfba98cbf7237193fdc68e24eaa3489838a8ad4db1589ec37821499bb3143ea4bd082aaabc1a2059b"}
  };
  for (const auto& vector : vectors) {
    const auto algorithm = LegacyHashAlgorithm::ByName(vector.name);
    check(algorithm != nullptr, vector.name);
    check(digest(*algorithm, input, input.size()) == utl::HashStringToBytes(std::string_view(vector.expected)), vector.name);
    if (std::string_view(vector.name).substr(0, 2) == "PH")
      check(digest(*algorithm, input, 1024 * 1024) == utl::HashStringToBytes(std::string_view(vector.expected)), "ParallelHash total length across multiple updates");
  }
  std::puts("PASS: 512 MiB + 17 byte single updates for SHAKE and both ParallelHash variants");
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
  check(utl::HashStringToBytes(std::string_view(std::string(LegacyHashAlgorithm::k_max_size * 2, 'a'))).size() ==
      LegacyHashAlgorithm::k_max_size, "maximum hash length");
  check(utl::HashStringToBytes(std::string_view(std::string((LegacyHashAlgorithm::k_max_size + 1) * 2, 'a'))).empty(),
      "oversize hash rejected");
  check(utl::FindHashInString(std::wstring(1000, L'A')).empty(), "long clipboard hash rejected");
  const auto mixed_case_hash = std::vector<uint8_t>({0xab, 0x12, 0xcd, 0xef});
  for (const auto text : {L"ab12cdef", L"AB12CDEF", L"aB12CdEf", L"aB 12 Cd Ef",
                          L"checksum: aB12CdEf *file.bin"})
    check(utl::FindHashInString(text) == mixed_case_hash, "clipboard hash accepts either or mixed hex case");
  for (const auto text : {L"aB12CdE", L"aB12CdEf0", L"zaB12CdEf", L"aB12CdEfz"})
    check(utl::FindHashInString(text).empty(), "clipboard hash rejects partial hex words");
  check(utl::UTF8ToWide("\xff").empty(), "invalid UTF-8 rejected");
  check(utl::UTF8ToWide("\xd0\xa4\xd0\xb0\xd0\xb9\xd0\xbb") == L"\u0424\u0430\u0439\u043b", "Unicode conversion");
  auto sfv = parse("; comment\r\nfile with spaces.bin 352441c2\r\n");
  check(sfv.size() == 1 && sfv.front().first == "file with spaces.bin", "SFV filenames with spaces");
  for (const auto separator : {"  ", "\t", " \t "}) {
    const auto result = parse(std::string("file with spaces.bin") + separator + "352441c2\r\n");
    check(result.size() == 1 && result.front().first == "file with spaces.bin", "SFV whitespace separators");
  }
  check(parse("\xef\xbb\xbf" "352441c2 *file.bin\n").size() == 1, "UTF-8 BOM");
  check(parse("NSRBwg== *file.bin\n").size() == 1, "base64 sumfile");
  for (const auto prefix : {"352441c2 *", "352441c2  ", "NSRBwg== *", "NSRBwg==  "}) {
    const auto result = parse(std::string(prefix) + "file deadbeef\n");
    check(result.size() == 1 && result.front().first == "file deadbeef" &&
          result.front().second == utl::HashStringToBytes(std::string_view("352441c2")),
          "GNU checksum filename ending in hex is not misread as SFV");
  }
  for (const auto name : {"README", "123456789"}) {
    const auto result = parse(std::string(name) + "  352441c2\n");
    check(result.size() == 1 && result.front().first == name, "SFV after an invalid GNU digest candidate");
  }
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
static void ed2k_boundaries() {
  constexpr size_t block = 9728000;
  const auto md4 = LegacyHashAlgorithm::ByName("MD4");
  const std::string data(3 * block + 1, 'a');
  for (const auto size : {block - 1, block, block + 1, 2 * block, 3 * block + 1}) {
    const auto input = std::string_view(data).substr(0, size);
    for (const bool old : {false, true}) {
      std::string hashes;
      for (size_t offset = 0; offset < size; offset += block) {
        const auto hash = digest(*md4, input.substr(offset, block), block);
        hashes.append(reinterpret_cast<const char*>(hash.data()), hash.size());
      }
      if (old && size >= block && size % block == 0) {
        const auto empty = digest(*md4, "", 1);
        hashes.append(reinterpret_cast<const char*>(empty.data()), empty.size());
      }
      const auto expected = size < block || (!old && size == block)
          ? digest(*md4, input, block) : digest(*md4, hashes, hashes.size());
      const auto algorithm = LegacyHashAlgorithm::ByName(old ? "eD2k (Old)" : "eD2k");
      check(digest(*algorithm, input, data.size()) == expected, "eD2k multiple blocks in one Update");
      check(digest(*algorithm, input, 8192) == expected, "eD2k streaming chunk boundaries");
    }
  }
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
  const auto computed_report = VerificationReport(coordinator, {});
  check(computed_report.size() == LegacyHashAlgorithm::k_count, "report contains every computed algorithm");
  for (const auto& row : computed_report)
    check(row.status == oht::ResultStatus::Computed && row.expected.empty() && !row.actual.empty(), "computed report fields");
  const auto check_hash = digest(*LegacyHashAlgorithm::ByName("SHA-256"), "abc", 1);
  const auto checked_report = VerificationReport(coordinator, check_hash);
  bool checked_sha256 = false;
  for (const auto& row : checked_report) if (row.algorithm == "SHA-256") {
    checked_sha256 = row.status == oht::ResultStatus::Match && row.actual == row.expected;
  }
  check(checked_sha256, "report preserves GUI check-against value");
  for (const auto& task : coordinator.GetFiles()) {
    check(task->GetError() == ERROR_SUCCESS, "async Unicode file hash");
    for (const auto& algorithm : LegacyHashAlgorithm::Algorithms())
      check(task->GetHashResult()[algorithm.Idx()] == digest(algorithm, "abc", 1), "async hash matches algorithm");
    std::list<FileHashTask*> tasks{task.get()};
    coordinator.settings.sumfile_banner.SetNoSave(false);
    const auto exported = Exporter::k_exporters.back()->GetExportString(&coordinator.settings, false, tasks);
    check(parse(exported).size() == 1, "SFV export/import round trip");
    for (const auto& algorithm : LegacyHashAlgorithm::Algorithms()) {
      const auto exporter = Exporter::k_exporters[algorithm.Idx()];
      const auto result = parse(exporter->GetExportString(&coordinator.settings, false, tasks));
      check(result.size() == 1 && result.front().second == task->GetHashResult()[algorithm.Idx()], "algorithm export/import round trip");
    }
    const auto sha256 = LegacyHashAlgorithm::IdxByName("SHA-256");
    for (const auto hash : {
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
        "bA7816Bf8F01cFeA414140dE5DaE2223B00361a396177A9cB410fF61F20015Ad"}) {
      for (bool found : {false, true}) {
        http_reply = {};
        http_reply.http_code = 200;
        http_reply.body = utl::FormatString(
            R"({"data":[{"hash":"%s","found":%s,"positives":2,"total":70,"permalink":"https://www.virustotal.com/gui/file/%s"}]})",
            hash, found ? "true" : "false", hash);
        const auto reports = vt::Query(tasks, sha256);
        check(reports.size() == 1 && reports.front().file == task.get() && reports.front().found == found,
            "VirusTotal response is associated with the hashed file");
        if (found)
          check(reports.front().positives == 2 && reports.front().total == 70 &&
              reports.front().permalink == std::string("https://www.virustotal.com/gui/file/") + hash,
              "VirusTotal detection counts and report link are preserved");
        json_parser request{http_request_body.c_str()};
        check(request.root() && json_getType(request.root()) == JSON_ARRAY, "VirusTotal request is valid JSON");
        const auto entry = json_getChild(request.root());
        const auto name = entry ? json_getProperty(entry, "image_path") : nullptr;
        check(name && json_getType(name) == JSON_TEXT &&
            utl::UTF8ToWide(json_getValue(name)) == task->GetDisplayName(), "VirusTotal request preserves Unicode filenames");
      }
    }
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

  const auto checksum_file = root / L"sample.SHA256";
  write(root / L"sample.bin", "abc");
  const auto absolute_target = std::filesystem::absolute(root / L"sample.bin");
  for (const auto& target : {std::wstring(L"sample.bin"), absolute_target.wstring(),
                            std::wstring(L"\\") + absolute_target.relative_path().wstring()}) {
    for (const bool matches : {true, false}) {
      write(checksum_file, std::string(matches ? "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" :
          "0000000000000000000000000000000000000000000000000000000000000000") + " *" + utl::WideToUTF8(target.c_str()) + "\n");
      Coordinator verify({checksum_file.wstring()});
      verify.settings.hash_sumfile_too.SetNoSave(false);
      verify.AddFiles();
      verify.ProcessFiles();
      verify.WaitForCompletion();
      check(verify.IsSumfile() && verify.GetFiles().size() == 1, "uppercase checksum extension");
      const auto& task = verify.GetFiles().front();
      check(task->GetError() == ERROR_SUCCESS, "checksum target read");
      check(task->GetMatchState() == (matches ? static_cast<int>(LegacyHashAlgorithm::ByName("SHA-256")->Idx()) :
          FileHashTask::MatchState_Mismatch), "checksum match/mismatch classification");
      const auto report = VerificationReport(verify, {});
      const auto sha = std::find_if(report.begin(), report.end(), [](const auto& row) { return row.algorithm == "SHA-256"; });
      check(sha != report.end() && sha->status == (matches ? oht::ResultStatus::Match : oht::ResultStatus::Mismatch) &&
          !sha->expected.empty() && !sha->actual.empty(), "verification report match/mismatch fields");
    }
  }

  write(checksum_file, std::string(64, '0') + " *missing-report-target.bin\n");
  Coordinator failed_report({checksum_file.wstring()});
  failed_report.settings.hash_sumfile_too.SetNoSave(false);
  failed_report.AddFiles();
  failed_report.ProcessFiles();
  failed_report.WaitForCompletion();
  const auto failed_rows = VerificationReport(failed_report, {});
  check(failed_rows.size() == 1 && failed_rows[0].algorithm == "SHA-256" && failed_rows[0].expected == std::string(64, '0') &&
      failed_rows[0].actual.empty() && failed_rows[0].status == oht::ResultStatus::Error && !failed_rows[0].error.empty(),
      "unreadable file report retains expected algorithm and hash");

  Coordinator cancelled({file.wstring()});
  cancelled.AddFiles();
  cancelled.Cancel(false);
  cancelled.ProcessFiles();
  cancelled.WaitForCompletion();
  check(cancelled.GetFiles().front()->GetError() == ERROR_CANCELLED, "cancel before asynchronous submission");
  for (const auto& hash : cancelled.GetFiles().front()->GetHashResult()) check(hash.empty(), "cancelled file has no hash");

  const auto locked_file = root / L"locked.bin";
  write(locked_file, "abc");
  auto locked = CreateFileW(locked_file.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  check(locked != INVALID_HANDLE_VALUE, "exclusive fixture handle");
  Coordinator sharing({locked_file.wstring()});
  sharing.AddFiles();
  sharing.ProcessFiles();
  sharing.WaitForCompletion();
  CloseHandle(locked);
  check(sharing.GetFiles().front()->GetError() == ERROR_SHARING_VIOLATION, "locked file reports sharing violation");

  // Many immediate completions exercise the coordinator's publication order.
  std::list<std::wstring> batch;
  for (unsigned i = 0; i < 128; ++i) {
    const auto path = root / (L"batch-" + std::to_wstring(i));
    write(path, "");
    batch.push_back(path.wstring());
  }
  Coordinator many(std::move(batch));
  many.AddFiles();
  many.ProcessFiles();
  many.WaitForCompletion();
  check(many.GetFiles().size() == 128, "batch retained every file");
  for (const auto& task : many.GetFiles()) {
    check(task->GetError() == ERROR_SUCCESS, "all batch tasks completed");
    check(!task->GetHashResult()[LegacyHashAlgorithm::ByName("SHA-256")->Idx()].empty(), "batch completion publishes hashes");
  }
}
static INT_PTR CALLBACK empty_dialog(HWND, UINT, WPARAM, LPARAM) { return FALSE; }
static void large_file_hashing() {
  // Exercise OVERLAPPED.OffsetHigh with a nonzero tail beyond 4 GiB.
  const auto file = root / L"sparse-over-4GiB.bin";
  const auto handle = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  check(handle != INVALID_HANDLE_VALUE, "create large sparse fixture");
  DWORD transferred{};
  check(DeviceIoControl(handle, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &transferred, nullptr) != FALSE,
      "mark fixture as sparse");
  LARGE_INTEGER offset{};
  offset.QuadPart = 1ULL << 32;
  check(SetFilePointerEx(handle, offset, nullptr, FILE_BEGIN) != FALSE, "seek beyond 32-bit file offset");
  constexpr char tail[] = "OpenHashTab offset";
  check(WriteFile(handle, tail, sizeof(tail) - 1, &transferred, nullptr) != FALSE && transferred == sizeof(tail) - 1,
      "write nonzero sparse-file tail");
  CloseHandle(handle);
  if constexpr (sizeof(size_t) > 4) {
    // A single Update exposes truncated lengths/counters that chunked reads do not.
    const auto input = utl::OpenForRead(file.wstring());
    check(input != INVALID_HANDLE_VALUE, "open large-buffer fixture");
    const auto mapping = CreateFileMappingW(input, nullptr, PAGE_READONLY, 0, 0, nullptr);
    check(mapping != nullptr, "map large-buffer fixture");
    const auto data = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    check(data != nullptr, "view large-buffer fixture");
    const auto size = static_cast<size_t>((1ULL << 32) + sizeof(tail) - 1);
    const std::pair<const char*, const char*> cases[] = {
      {"CRC64", "7e3fbec98de8c6b6"},
      {"MD4", "cf1ad89acf14ad0e0cfceb7aa4597455"},
      {"MD5", "806fe73b29a32b261491798cd2a625e6"},
      {"RipeMD160", "070aa79aa3d6da5bb92a06a38f147e984ecdbff4"},
      {"SHA-1", "6d03306e9fbad8500bdd018917503cd728d4266d"},
      {"SHA-224", "156342a8eeae80f58b61df7bb978826c6513b230a8d20842948c370b"},
      {"SHA-256", "d1885540b2b008f0bb739130d1712a275c034811aa2828648f4bd931a371d6e3"},
    };
    for (const auto& [name, expected] : cases) {
      const auto actual = digest(*LegacyHashAlgorithm::ByName(name),
          std::string_view(static_cast<const char*>(data), size), size);
      check(actual == utl::HashStringToBytes(std::string_view(expected)),
          "single update includes the nonzero tail beyond 4 GiB");
      std::printf("PASS: %s DLL single 4 GiB + 18 byte update\n", name);
    }
    check(UnmapViewOfFile(data) != FALSE, "unmap large-buffer fixture");
    CloseHandle(mapping);
    CloseHandle(input);
  }
  Coordinator coordinator({file.wstring()});
  for (auto& enabled : coordinator.settings.algorithms) enabled.SetNoSave(false);
  const auto algorithm = LegacyHashAlgorithm::ByName("SHA-256");
  coordinator.settings.algorithms[algorithm->Idx()].SetNoSave(true);
  coordinator.AddFiles();
  coordinator.ProcessFiles();
  coordinator.WaitForCompletion();
  check(coordinator.GetFiles().size() == 1, "large file retained");
  const auto& task = coordinator.GetFiles().front();
  check(task->GetSize() == (1ULL << 32) + sizeof(tail) - 1, "64-bit file length");
  check(task->GetError() == ERROR_SUCCESS, "large asynchronous file read");
  const auto expected = utl::HashStringToBytes(std::string_view("d1885540b2b008f0bb739130d1712a275c034811aa2828648f4bd931a371d6e3"));
  check(task->GetHashResult()[algorithm->Idx()] == expected, "hash includes data beyond 4 GiB");
  std::puts("PASS: asynchronous SHA-256 of a 4 GiB + 18 byte sparse file");
}
static void dialog_templates() {
  for (const int resource : {101, 102}) {
    const auto dialog = wnd::CreateDialogFromChildDialogResourceParam(
        GetModuleHandleW(nullptr), MAKEINTRESOURCEW(resource), nullptr, empty_dialog, 0);
    check(dialog != nullptr, "create standard and extended dialog templates");
    const auto style = GetWindowLongPtrW(dialog, GWL_STYLE);
    check((style & WS_CHILD) == 0 && (style & WS_POPUP) != 0, "dialog style conversion");
    check((GetWindowLongPtrW(dialog, GWL_EXSTYLE) & WS_EX_APPWINDOW) != 0, "dialog extended style conversion");
    check(DestroyWindow(dialog) != FALSE, "destroy test dialog");
  }
  for (const int resource : {103, 104}) {
    SetLastError(ERROR_SUCCESS);
    const auto dialog = wnd::CreateDialogFromChildDialogResourceParam(
        GetModuleHandleW(nullptr), MAKEINTRESOURCEW(resource), nullptr, empty_dialog, 0);
    check(dialog == nullptr && GetLastError() == ERROR_INVALID_DATA, "truncated dialog template rejected");
  }
  std::puts("PASS: standard, extended and truncated dialog templates");
}
static void clipboard() {
  auto window = CreateWindowExW(0, L"STATIC", L"OpenHashTab clipboard test", 0,
      0, 0, 0, 0, HWND_MESSAGE, nullptr, GetModuleHandleW(nullptr), nullptr);
  check(window != nullptr, "clipboard owner window");
  const wchar_t input[] = {L'A', L'\u0424', L'B', L'X'};
  check(utl::SetClipboardText(window, std::wstring_view(input, 3)) == ERROR_SUCCESS, "copy non-terminated string view");
  check(utl::GetClipboardText(window) == L"A\u0424B", "Unicode clipboard round trip respects view length");
  check(utl::SetClipboardText(window, {}) == ERROR_SUCCESS && utl::GetClipboardText(window).empty(), "empty clipboard text");
  DestroyWindow(window);
}
int main() {
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
  try {
    root = std::filesystem::temp_directory_path() / (L"OpenHashTabTests-" + std::to_wstring(GetCurrentProcessId()));
    std::filesystem::create_directories(root);
    network_responses();
    ownership();
    hashing();
    official_hash_vectors();
    streaming_hash_vectors();
    extended_hash_vectors();
    large_hash_updates();
    ed2k_boundaries();
    parsers();
    file_hashing();
    large_file_hashing();
    dialog_templates();
    clipboard();
    std::filesystem::remove_all(utl::MakePathLongCompatible(root.wstring()));
    std::puts("PASS: hashing, parsing, resource lifetime, asynchronous I/O and export tests");
    return 0;
  } catch (const std::exception& error) {
    std::fprintf(stderr, "FAIL: %s\n", error.what());
    return 1;
  }
}
