// SPDX-License-Identifier: GPL-3.0-or-later
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <ShlObj.h>
#include <cstdio>
#include <string>
#include <cstring>

static bool ok(HRESULT result, const char* operation) {
  if (FAILED(result)) std::fprintf(stderr, "FAIL: %s (0x%08lx)\n", operation, static_cast<unsigned long>(result));
  return SUCCEEDED(result);
}
static BOOL CALLBACK add_page(HPROPSHEETPAGE page, LPARAM count) {
  ++*reinterpret_cast<unsigned*>(count);
  DestroyPropertySheetPage(page);
  return TRUE;
}
int wmain(int argc, wchar_t** argv) {
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
  if (argc != 2) return 2;
  if (!ok(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED), "COM initialization")) return 1;
  CLSID clsid{};
  CLSIDFromString(L"{23B5BDD4-7669-42B8-9CDC-BEEBC8A5BAA9}", &clsid);
  IShellExtInit* extension{};
  if (!ok(CoCreateInstance(clsid, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&extension)), "registered shell extension")) return 1;
  if (extension->Initialize(nullptr, nullptr, nullptr) != E_INVALIDARG) return 1;
  // The running executable is an existing file independent of the working directory.
  wchar_t file[32768]{};
  GetModuleFileNameW(nullptr, file, 32768);
  PIDLIST_ABSOLUTE absolute{};
  if (!ok(SHParseDisplayName(file, nullptr, &absolute, 0, nullptr), "parse shell item")) return 1;
  auto parent = ILCloneFull(absolute);
  PCUITEMID_CHILD children[] = {ILFindLastID(absolute)};
  ILRemoveLastID(parent);
  IDataObject* data{};
  if (!ok(SHCreateDataObject(parent, 1, children, nullptr, IID_PPV_ARGS(&data)), "shell data object")) return 1;
  if (!ok(extension->Initialize(nullptr, data, nullptr), "initialize selected file")) return 1;
  IShellPropSheetExt* properties{};
  if (!ok(extension->QueryInterface(IID_PPV_ARGS(&properties)), "property sheet interface")) return 1;
  unsigned pages{};
  if (!ok(properties->AddPages(add_page, reinterpret_cast<LPARAM>(&pages)), "create property page") || pages != 1) return 1;
  IContextMenu* context{};
  if (!ok(extension->QueryInterface(IID_PPV_ARGS(&context)), "context menu interface")) return 1;
  auto menu = CreatePopupMenu();
  const auto result = context->QueryContextMenu(menu, 0, 1, 100, CMF_NORMAL);
  if (!ok(result, "context menu") || GetMenuItemCount(menu) != 1) return 1;
  char help[128 * sizeof(wchar_t)]{};
  if (!ok(context->GetCommandString(0, GCS_HELPTEXTW, nullptr, help, 128), "Unicode context menu help")) return 1;
  wchar_t unicode[128]{};
  std::memcpy(unicode, help, sizeof(unicode));
  if (std::wstring(unicode) != L"Calculate and verify file hashes.") return 1;
  std::memset(help, 0x5a, sizeof(help));
  if (context->GetCommandString(0, GCS_HELPTEXTW, nullptr, help, 1) != HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)) return 1;
  for (const auto byte : help) if (byte != 0x5a) return 1;
  if (context->GetCommandString(0, GCS_HELPTEXTW, nullptr, nullptr, 0) != E_INVALIDARG) return 1;
  if (context->GetCommandString(1, GCS_HELPTEXTW, nullptr, help, 128) != E_INVALIDARG) return 1;
  // Verify that COM loaded the registration requested by the installer test.
  if (!GetModuleHandleW(argv[1])) { std::fprintf(stderr, "FAIL: unexpected COM DLL\n"); return 1; }
  DestroyMenu(menu);
  context->Release(); properties->Release(); extension->Release(); data->Release();
  CoTaskMemFree(absolute); CoTaskMemFree(parent);
  CoUninitialize();
  std::puts("PASS: COM activation, property page and classic context menu");
  return 0;
}
