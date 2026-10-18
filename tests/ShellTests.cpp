// SPDX-License-Identifier: GPL-3.0-or-later
#define WIN32_LEAN_AND_MEAN
#define STRICT_TYPED_ITEMIDS
#include <Windows.h>
#include <ShlObj.h>
#include <CommCtrl.h>
#include <urlmon.h>
#include <cstdio>
#include <string>
#include <cstring>
#include "../OpenHashTab/OpenHashTab/resource.h"

static bool ok(HRESULT result, const char* operation) {
  if (FAILED(result)) std::fprintf(stderr, "FAIL: %s (0x%08lx)\n", operation, static_cast<unsigned long>(result));
  return SUCCEEDED(result);
}
static BOOL CALLBACK add_page(HPROPSHEETPAGE page, LPARAM count) {
  ++*reinterpret_cast<unsigned*>(count);
  DestroyPropertySheetPage(page);
  return TRUE;
}
static BOOL CALLBACK find_dialog(HWND window, LPARAM result) {
  if (GetDlgItem(window, IDC_HASH_LIST)) {
    *reinterpret_cast<HWND*>(result) = window;
    return FALSE;
  }
  return TRUE;
}
static bool menu_closed = false;
static void CALLBACK close_menu(HWND, UINT, UINT_PTR timer, DWORD) {
  menu_closed = EndMenu() != FALSE;
  KillTimer(nullptr, timer);
}
static bool window_and_popup_menus(IContextMenu* context) {
  CMINVOKECOMMANDINFO command{};
  command.cbSize = sizeof(command);
  command.lpVerb = MAKEINTRESOURCEA(0);
  command.nShow = SW_SHOWNORMAL;
  if (!ok(context->InvokeCommand(&command), "invoke context menu command")) return false;
  HWND window{};
  EnumThreadWindows(GetCurrentThreadId(), find_dialog, reinterpret_cast<LPARAM>(&window));
  if (!window) return false;
  const auto list = GetDlgItem(window, IDC_HASH_LIST);
  for (unsigned attempt = 0; attempt < 100 && ListView_GetItemCount(list) == 0; ++attempt) {
    MSG message{};
    while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
      TranslateMessage(&message);
      DispatchMessageW(&message);
    }
    Sleep(50);
  }
  if (ListView_GetItemCount(list) == 0) return false;
  DWORD before{};
  for (unsigned attempt = 0; attempt < 18; ++attempt) {
    // Warm up common-control resources before checking USER handle growth.
    if (attempt == 2) before = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
    menu_closed = false;
    const auto timer = SetTimer(nullptr, 0, 50, close_menu);
    if (!timer) return false;
    NMITEMACTIVATE click{};
    click.hdr = {list, IDC_HASH_LIST, NM_RCLICK};
    click.ptAction = {10, 10};
    SendMessageW(window, WM_NOTIFY, IDC_HASH_LIST, reinterpret_cast<LPARAM>(&click));
    KillTimer(nullptr, timer);
    if (!menu_closed) return false;
  }
  const auto after = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
  if (!before || after > before + 2) {
    std::fprintf(stderr, "FAIL: popup menu USER handles grew from %lu to %lu\n", before, after);
    return false;
  }
  SendMessageW(window, WM_CLOSE, 0, 0);
  if (IsWindow(window)) return false;
  std::puts("PASS: context command opens/closes a window; repeated popup menus release USER handles");
  return true;
}
// Exercise Windows shell initialization before any OpenHashTab installation.
// The renamed control executable never activates or loads the project DLL.
static int windows_control() {
  if (!ok(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED), "control COM initialization")) return 1;
  wchar_t file[32768]{};
  GetModuleFileNameW(nullptr, file, 32768);
  PIDLIST_ABSOLUTE absolute{};
  if (!ok(SHParseDisplayName(file, nullptr, &absolute, 0, nullptr), "control shell item")) return 1;
  auto parent = ILCloneFull(absolute);
  if (!parent) return 1;
  PCUITEMID_CHILD children[] = {ILFindLastID(absolute)};
  ILRemoveLastID(parent);
  IDataObject* data{};
  if (!ok(SHCreateDataObject(parent, 1, children, nullptr, IID_PPV_ARGS(&data)), "control shell data object")) return 1;
  IInternetSecurityManager* security{};
  if (!ok(CoInternetCreateSecurityManager(nullptr, &security, 0), "control URL security manager")) return 1;
  DWORD zone{};
  // A local file URL performs zone classification without a network request.
  if (!ok(security->MapUrlToZone(L"file:///C:/Windows/explorer.exe", &zone, 0), "control local file zone")) return 1;
  // A real visible Windows window exercises GUI lifecycle side effects such as
  // BAM and notifications; the control still loads no OpenHashTab component.
  INITCOMMONCONTROLSEX common{sizeof(common), ICC_LISTVIEW_CLASSES};
  if (!InitCommonControlsEx(&common)) return 1;
  auto window = CreateWindowExW(WS_EX_APPWINDOW, L"STATIC", L"Windows shell control",
      WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 320, 200, nullptr, nullptr, nullptr, nullptr);
  if (!window) return 1;
  auto list = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT,
      0, 0, 300, 150, window, nullptr, nullptr, nullptr);
  if (!list) return 1;
  ShowWindow(window, SW_SHOWNORMAL);
  UpdateWindow(window);
  for (unsigned attempt = 0; attempt < 50; ++attempt) {
    MSG message{};
    while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
      TranslateMessage(&message);
      DispatchMessageW(&message);
    }
    Sleep(20);
  }
  DestroyWindow(window);
  security->Release(); data->Release();
  CoTaskMemFree(absolute); CoTaskMemFree(parent);
  CoUninitialize();
  if (GetModuleHandleW(L"OpenHashTab32.dll") || GetModuleHandleW(L"OpenHashTab64.dll")) return 1;
  std::puts("PASS: Windows-only shell control; no project DLL activation");
  return 0;
}
int wmain(int argc, wchar_t** argv) {
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
  if (argc == 2 && std::wstring(argv[1]) == L"--windows-control") return windows_control();
  if (argc == 3 && std::wstring(argv[1]) == L"--load-only") {
    const auto module = LoadLibraryExW(argv[2], nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) {
      std::fprintf(stderr, "FAIL: load shell extension DLL (Win32 error %lu)\n", GetLastError());
      return 1;
    }
    const bool exported = GetProcAddress(module, "DllGetClassObject") != nullptr;
    FreeLibrary(module);
    if (!exported) return 1;
    std::puts("PASS: shell extension manifest and DLL load");
    return 0;
  }
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
  if (!window_and_popup_menus(context)) return 1;
  DestroyMenu(menu);
  context->Release(); properties->Release(); extension->Release(); data->Release();
  CoTaskMemFree(absolute); CoTaskMemFree(parent);
  CoUninitialize();
  std::puts("PASS: COM activation, property page and classic context menu");
  return 0;
}
