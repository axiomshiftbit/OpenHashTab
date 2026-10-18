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
#include <cwchar>
#include <vector>
#include "../OpenHashTab/OpenHashTab/resource.h"
#include "../OpenHashTab/LegacyAlgorithms/Hasher.h"

static bool ok(HRESULT result, const char* operation) {
  if (FAILED(result)) std::fprintf(stderr, "FAIL: %s (0x%08lx)\n", operation, static_cast<unsigned long>(result));
  return SUCCEEDED(result);
}
static std::wstring resource_string(HMODULE module, WORD language, UINT id) {
  const auto resource = FindResourceExW(module, RT_STRING, MAKEINTRESOURCEW((id >> 4) + 1), language);
  if (!resource) return {};
  auto remaining = SizeofResource(module, resource) / sizeof(WORD);
  const auto loaded = LoadResource(module, resource);
  auto words = static_cast<const WORD*>(LockResource(loaded));
  if (!words) return {};
  for (UINT index = 0; index < 16 && remaining; ++index) {
    const auto length = *words++;
    --remaining;
    if (length > remaining) return {};
    if (index == (id & 15)) return {reinterpret_cast<const wchar_t*>(words), length};
    words += length;
    remaining -= length;
  }
  return {};
}
static BOOL CALLBACK collect_language(HMODULE, LPCWSTR, LPCWSTR, WORD language, LONG_PTR result) {
  reinterpret_cast<std::vector<WORD>*>(result)->push_back(language);
  return TRUE;
}
static bool localized_resources(HMODULE module) {
  std::vector<WORD> languages;
  if (!EnumResourceLanguagesW(module, RT_STRING, MAKEINTRESOURCEW((IDS_ALGORITHM >> 4) + 1),
      collect_language, reinterpret_cast<LONG_PTR>(&languages))) {
    std::fputs("FAIL: GUI string tables are absent from the compiled DLL\n", stderr);
    return false;
  }
  bool english = false, russian = false;
  for (const auto language : languages) {
    english |= language == MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);
    russian |= language == MAKELANGID(LANG_RUSSIAN, SUBLANG_RUSSIAN_RUSSIA);
    for (UINT id = IDS_ALGORITHM; id <= IDS_LAST; ++id) {
      if (resource_string(module, language, id).empty()) {
        std::fprintf(stderr, "FAIL: empty GUI string %u in language 0x%04x\n", id, language);
        return false;
      }
    }
  }
  if (!english || !russian || resource_string(module, 0x409, IDS_HASHES) != L"Hashes" ||
      resource_string(module, 0x419, IDS_HASHES) != L"\u0425\u044d\u0448\u0438") return false;
  std::printf("PASS: %u nonempty GUI strings in each of %zu compiled languages; English and Russian captions\n", IDS_LAST - IDS_ALGORITHM + 1, languages.size());
  return true;
}
static BOOL CALLBACK add_page(HPROPSHEETPAGE page, LPARAM result) {
  auto& saved = *reinterpret_cast<HPROPSHEETPAGE*>(result);
  if (saved) return FALSE;
  saved = page;
  return TRUE;
}
static bool property_page_title(IShellPropSheetExt* properties) {
  HPROPSHEETPAGE page{};
  if (!ok(properties->AddPages(add_page, reinterpret_cast<LPARAM>(&page)), "create property page") || !page) return false;
  PROPSHEETHEADERW header{};
  header.dwSize = sizeof(header);
  header.dwFlags = PSH_MODELESS | PSH_NOAPPLYNOW;
  header.pszCaption = L"OpenHashTab property page test";
  header.nPages = 1;
  header.phpage = &page;
  const auto sheet = reinterpret_cast<HWND>(PropertySheetW(&header));
  if (!sheet || sheet == reinterpret_cast<HWND>(-1)) return false;
  wchar_t title[128]{};
  TCITEMW item{};
  item.mask = TCIF_TEXT;
  item.pszText = title;
  item.cchTextMax = 128;
  const auto tab = PropSheet_GetTabControl(sheet);
  const bool valid = TabCtrl_GetItemCount(tab) == 1 && TabCtrl_GetItem(tab, 0, &item) && title[0] &&
      GetDlgItem(PropSheet_GetCurrentPageHwnd(sheet), IDC_HASH_LIST);
  DestroyWindow(sheet);
  if (!valid) std::fputs("FAIL: property sheet hash tab or its localized title is missing\n", stderr);
  return valid;
}
static BOOL CALLBACK find_dialog(HWND window, LPARAM result) {
  if (GetDlgItem(window, IDC_HASH_LIST)) {
    *reinterpret_cast<HWND*>(result) = window;
    return FALSE;
  }
  return TRUE;
}
static bool menu_closed = false;
static bool settings_checked = false;
static BOOL CALLBACK find_settings(HWND window, LPARAM result) {
  if (GetDlgItem(window, IDC_ALGORITHM_LIST)) {
    *reinterpret_cast<HWND*>(result) = window;
    return FALSE;
  }
  return TRUE;
}
static bool settings_options_aligned(HWND window) {
  const int options[] = {
    IDC_CHECK_DISPLAY_UPPERCASE, IDC_CHECK_DISPLAY_MONOSPACE, IDC_CHECK_LOOK_FOR_SUMFILES,
    IDC_CHECK_SUMFILE_UPPERCASE, IDC_CHECK_SUMFILE_UNIX_ENDINGS, IDC_CHECK_SUMFILE_USE_DOUBLE_SPACE,
    IDC_CHECK_SUMFILE_FORWARD_SLASHES, IDC_CHECK_SUMFILE_DOT_HASH_COMPATIBLE, IDC_CHECK_SUMFILE_BANNER,
    IDC_CHECK_SUMFILE_BANNER_DATE, IDC_CHECK_CLIPBOARD_AUTOENABLE, IDC_CHECK_CLIPBOARD_AUTOENABLE_IF_NONE,
    IDC_CHECK_CLIPBOARD_AUTOENABLE_EXCLUSIVE, IDC_CHECK_CHECKAGAINST_AUTOFORMAT, IDC_CHECK_CHECKAGAINST_STRICT,
    IDC_CHECK_HASH_SUMFILE_TOO, IDC_CHECK_SUMFILE_ALGORITHM_ONLY,
  };
  RECT first{};
  if (!GetWindowRect(GetDlgItem(window, options[0]), &first)) return false;
  for (const auto id : options) {
    RECT rectangle{};
    if (!GetWindowRect(GetDlgItem(window, id), &rectangle) || rectangle.left != first.left ||
        rectangle.right != first.right) {
      std::fprintf(stderr, "FAIL: settings checkbox %d is misaligned\n", id);
      return false;
    }
  }
  return true;
}
static bool settings_algorithm_controls(HWND window) {
  const auto list = GetDlgItem(window, IDC_ALGORITHM_LIST);
  const auto search = GetDlgItem(window, IDC_ALGORITHM_SEARCH);
  const auto presets = GetDlgItem(window, IDC_ALGORITHM_PRESET);
  const auto description = GetDlgItem(window, IDC_ALGORITHM_DESCRIPTION);
  if (!search || !presets || !description || ListView_GetItemCount(list) != LegacyHashAlgorithm::k_count) return false;
  std::vector<bool> saved;
  for (int i = 0; i < LegacyHashAlgorithm::k_count; ++i) saved.push_back(ListView_GetCheckState(list, i) != FALSE);
  bool passed = SendMessageW(presets, CB_GETCOUNT, 0, 0) == 5;
  RECT client{};
  GetClientRect(list, &client);
  for (int i = 0; i < LegacyHashAlgorithm::k_count; ++i) {
    ListView_SetItemState(list, i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_EnsureVisible(list, i, FALSE);
    RECT row{};
    passed &= ListView_GetItemRect(list, i, &row, LVIR_BOUNDS) != FALSE &&
        row.top >= 0 && row.bottom <= client.bottom;
    wchar_t text[1024]{};
    GetWindowTextW(description, text, 1024);
    passed &= text[0] != 0;
    RECT area{};
    GetClientRect(description, &area);
    RECT measured = area;
    const auto dc = GetDC(description);
    if (dc) {
      const auto old_font = SelectObject(dc, reinterpret_cast<HFONT>(SendMessageW(description, WM_GETFONT, 0, 0)));
      DrawTextW(dc, text, -1, &measured, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
      passed &= measured.bottom <= area.bottom;
      SelectObject(dc, old_font);
      ReleaseDC(description, dc);
    } else passed = false;
  }
  SetWindowTextW(search, L"sHa-512/");
  passed &= ListView_GetItemCount(list) == 2;
  wchar_t selected_name[128]{};
  ListView_GetItemText(list, 0, 0, selected_name, 128);
  const bool old_check = ListView_GetCheckState(list, 0) != FALSE;
  ListView_SetCheckState(list, 0, !old_check);
  SetWindowTextW(search, L"");
  passed &= ListView_GetItemCount(list) == LegacyHashAlgorithm::k_count;
  bool found = false;
  for (int i = 0; i < ListView_GetItemCount(list); ++i) {
    wchar_t name[128]{};
    ListView_GetItemText(list, i, 0, name, 128);
    if (std::wcscmp(name, selected_name) == 0) {
      found = true;
      passed &= (ListView_GetCheckState(list, i) != FALSE) != old_check;
    }
  }
  passed &= found;
  SetWindowTextW(search, L"no-such-algorithm");
  passed &= ListView_GetItemCount(list) == 0 && GetWindowTextLengthW(description) > 0;
  for (const auto preset : {4, 3, 1, 2}) {
    // Applying a preset while all rows are hidden must still affect all algorithms.
    SendMessageW(presets, CB_SETCURSEL, preset, 0);
    SendMessageW(window, WM_COMMAND, MAKEWPARAM(IDC_ALGORITHM_PRESET, CBN_SELCHANGE), reinterpret_cast<LPARAM>(presets));
    SetWindowTextW(search, L"");
    for (int i = 0; i < ListView_GetItemCount(list); ++i) {
      wchar_t name[128]{};
      ListView_GetItemText(list, i, 0, name, 128);
      const std::wstring n(name);
      const bool expected = preset == 3 || (preset == 1 && (n == L"SHA-256" || n == L"BLAKE3")) ||
          (preset == 2 && (n == L"MD5" || n == L"SHA-1" || n == L"SHA-256" || n == L"SHA-512"));
      passed &= (ListView_GetCheckState(list, i) != FALSE) == expected;
    }
    SetWindowTextW(search, L"no-such-algorithm");
  }
  SetWindowTextW(search, L"");
  for (int i = 0; i < LegacyHashAlgorithm::k_count; ++i) ListView_SetCheckState(list, i, saved[i]);
  if (!passed) std::fputs("FAIL: algorithm search, presets, description layout or scrolling\n", stderr);
  return passed;
}
static void CALLBACK inspect_settings(HWND, UINT, UINT_PTR timer, DWORD) {
  KillTimer(nullptr, timer);
  HWND window{};
  EnumThreadWindows(GetCurrentThreadId(), find_settings, reinterpret_cast<LPARAM>(&window));
  if (!window) return;
  const int labels[] = {
    IDC_CHECK_DISPLAY_UPPERCASE, IDC_CHECK_DISPLAY_MONOSPACE, IDC_CHECK_LOOK_FOR_SUMFILES,
    IDC_CHECK_SUMFILE_UPPERCASE, IDC_CHECK_SUMFILE_UNIX_ENDINGS, IDC_CHECK_SUMFILE_USE_DOUBLE_SPACE,
    IDC_CHECK_SUMFILE_FORWARD_SLASHES, IDC_CHECK_SUMFILE_DOT_HASH_COMPATIBLE, IDC_CHECK_SUMFILE_BANNER,
    IDC_CHECK_SUMFILE_BANNER_DATE, IDC_CHECK_CLIPBOARD_AUTOENABLE, IDC_CHECK_CLIPBOARD_AUTOENABLE_IF_NONE,
    IDC_CHECK_CLIPBOARD_AUTOENABLE_EXCLUSIVE, IDC_CHECK_CHECKAGAINST_AUTOFORMAT, IDC_CHECK_CHECKAGAINST_STRICT,
    IDC_CHECK_HASH_SUMFILE_TOO, IDC_CHECK_SUMFILE_ALGORITHM_ONLY, IDC_BUTTON_CHECK_FOR_UPDATES,
    IDC_UNKNOWN_GROUP, IDC_UNKNOWN_FG_CHECK, IDC_UNKNOWN_BG_CHECK,
    IDC_MATCH_GROUP, IDC_MATCH_FG_CHECK, IDC_MATCH_BG_CHECK,
    IDC_MISMATCH_GROUP, IDC_MISMATCH_FG_CHECK, IDC_MISMATCH_BG_CHECK,
    IDC_INSECURE_GROUP, IDC_INSECURE_FG_CHECK, IDC_INSECURE_BG_CHECK,
    IDC_ERROR_GROUP, IDC_ERROR_FG_CHECK, IDC_ERROR_BG_CHECK,
    IDC_STATIC_ALGORITHM_SEARCH, IDC_STATIC_ALGORITHM_PRESET, IDC_ALGORITHM_DESCRIPTION,
  };
  settings_checked = GetWindowTextLengthW(window) > 0 && settings_options_aligned(window);
  RECT client{};
  GetClientRect(window, &client);
  for (const auto id : labels) {
    const auto control = GetDlgItem(window, id);
    RECT rectangle{};
    GetWindowRect(control, &rectangle);
    MapWindowPoints(HWND_DESKTOP, window, reinterpret_cast<POINT*>(&rectangle), 2);
    if (!control || !IsWindowVisible(control) || !GetWindowTextLengthW(control) ||
        rectangle.left < 0 || rectangle.top < 0 || rectangle.right > client.right || rectangle.bottom > client.bottom) {
      std::fprintf(stderr, "FAIL: settings control %d is missing, blank or outside the dialog\n", id);
      settings_checked = false;
    }
  }
  const auto list = GetDlgItem(window, IDC_ALGORITHM_LIST);
  if (ListView_GetItemCount(list) != LegacyHashAlgorithm::k_count) settings_checked = false;
  const auto main_list = GetDlgItem(GetWindow(window, GW_OWNER), IDC_HASH_LIST);
  const auto algorithm_width = ListView_GetColumnWidth(main_list, 1);
  for (int index = 0; index < ListView_GetItemCount(list); ++index) {
    wchar_t name[128]{};
    ListView_GetItemText(list, index, 0, name, 128);
    if (!name[0]) settings_checked = false;
    if (!main_list || algorithm_width <= ListView_GetStringWidth(main_list, name)) {
      std::fprintf(stderr, "FAIL: main algorithm column clips settings algorithm %d\n", index);
      settings_checked = false;
    }
  }
  settings_checked &= settings_algorithm_controls(window);
  EndDialog(window, IDCANCEL);
}
static void CALLBACK close_menu(HWND, UINT, UINT_PTR timer, DWORD) {
  menu_closed = EndMenu() != FALSE;
  KillTimer(nullptr, timer);
}
static bool comparison_checked = false;
static unsigned comparison_polls = 0;
static bool comparison_started = false;
static BOOL CALLBACK find_comparison(HWND window, LPARAM result) {
  if (GetDlgItem(window, IDC_COMPARE_RESULTS)) {
    *reinterpret_cast<HWND*>(result) = window;
    return FALSE;
  }
  return TRUE;
}
static void CALLBACK inspect_comparison(HWND, UINT, UINT_PTR timer, DWORD) {
  HWND window{};
  EnumThreadWindows(GetCurrentThreadId(), find_comparison, reinterpret_cast<LPARAM>(&window));
  if (!window) {
    if (++comparison_polls > 200) KillTimer(nullptr, timer);
    return;
  }
  if (++comparison_polls > 200) {
    comparison_checked = false;
    KillTimer(nullptr, timer);
    SendMessageW(window, WM_CLOSE, 0, 0);
    return;
  }
  if (!comparison_started) {
    comparison_started = true;
    comparison_checked = GetWindowTextLengthW(window) > 0;
    RECT client{};
    GetClientRect(window, &client);
    for (const auto id : {IDC_COMPARE_LEFT_LABEL, IDC_COMPARE_RIGHT_LABEL, IDC_COMPARE_ALGORITHM_LABEL,
        IDC_COMPARE_LEFT_FILE, IDC_COMPARE_LEFT_FOLDER, IDC_COMPARE_RIGHT_FILE, IDC_COMPARE_RIGHT_FOLDER,
        IDC_COMPARE_START, IDC_COMPARE_CANCEL, IDC_COMPARE_JSON, IDC_COMPARE_CSV, IDCANCEL}) {
      const auto control = GetDlgItem(window, id);
      RECT rectangle{};
      GetWindowRect(control, &rectangle);
      MapWindowPoints(HWND_DESKTOP, window, reinterpret_cast<POINT*>(&rectangle), 2);
      comparison_checked &= IsWindowVisible(control) && GetWindowTextLengthW(control) > 0 &&
          rectangle.left >= 0 && rectangle.top >= 0 && rectangle.right <= client.right && rectangle.bottom <= client.bottom;
    }
    comparison_checked &= SendDlgItemMessageW(window, IDC_COMPARE_ALGORITHM, CB_GETCOUNT, 0, 0) == LegacyHashAlgorithm::k_count;
    comparison_checked &= !IsWindowEnabled(GetDlgItem(window, IDC_COMPARE_CANCEL));
    comparison_checked &= !IsWindowEnabled(GetDlgItem(window, IDC_COMPARE_JSON));
    wchar_t file[32768]{};
    comparison_checked &= GetModuleFileNameW(nullptr, file, 32768) != 0;
    SetDlgItemTextW(window, IDC_COMPARE_LEFT, file);
    SetDlgItemTextW(window, IDC_COMPARE_RIGHT, file);
    SendDlgItemMessageW(window, IDC_COMPARE_START, BM_CLICK, 0, 0);
    comparison_checked &= !IsWindowEnabled(GetDlgItem(window, IDC_COMPARE_LEFT)) &&
        IsWindowEnabled(GetDlgItem(window, IDC_COMPARE_CANCEL));
    return;
  }
  if (!IsWindowEnabled(GetDlgItem(window, IDC_COMPARE_START))) return;
  const auto list = GetDlgItem(window, IDC_COMPARE_RESULTS);
  comparison_checked &= ListView_GetItemCount(list) == 1;
  wchar_t expected[257]{}, actual[257]{}, error[1024]{};
  ListView_GetItemText(list, 0, 2, expected, 257);
  ListView_GetItemText(list, 0, 3, actual, 257);
  ListView_GetItemText(list, 0, 4, error, 1024);
  comparison_checked &= std::wcslen(expected) == 64 && !std::wcscmp(expected, actual) && !error[0];
  comparison_checked &= IsWindowEnabled(GetDlgItem(window, IDC_COMPARE_JSON)) &&
      IsWindowEnabled(GetDlgItem(window, IDC_COMPARE_CSV)) && !IsWindowEnabled(GetDlgItem(window, IDC_COMPARE_CANCEL));
  comparison_checked &= GetWindowTextLengthW(GetDlgItem(window, IDC_COMPARE_SUMMARY)) > 0 &&
      GetWindowTextLengthW(GetDlgItem(window, IDC_COMPARE_PROGRESS)) > 0;
  KillTimer(nullptr, timer);
  EndDialog(window, IDCANCEL);
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
  for (unsigned attempt = 0; attempt < 100 && !IsWindowEnabled(GetDlgItem(window, IDC_BUTTON_SETTINGS)); ++attempt) {
    MSG message{};
    while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
      TranslateMessage(&message);
      DispatchMessageW(&message);
    }
    Sleep(50);
  }
  if (ListView_GetItemCount(list) == 0) return false;
  for (const auto id : {IDC_STATIC_CHECK_AGAINST, IDC_STATIC_EXPORT_TO, IDC_STATIC_PROCESSING,
                       IDC_BUTTON_CLIPBOARD, IDC_BUTTON_EXPORT, IDC_BUTTON_COMPARE, IDC_BUTTON_REPORT, IDC_PROGRESS_DETAILS}) {
    if (!GetWindowTextLengthW(GetDlgItem(window, id))) {
      std::fprintf(stderr, "FAIL: main GUI control %d has no localized caption\n", id);
      return false;
    }
  }
  wchar_t algorithm[128]{}, hash[LegacyHashAlgorithm::k_max_size * 2 + 1]{}, result[512]{};
  ListView_GetItemText(list, 0, 1, algorithm, 128);
  ListView_GetItemText(list, 0, 2, hash, static_cast<int>(std::size(hash)));
  if (!algorithm[0] || !hash[0]) return false;
  for (int form = 0; form < 3; ++form) {
    for (size_t i = 0; hash[i]; ++i) {
      if (hash[i] >= L'A' && hash[i] <= L'F') hash[i] += L'a' - L'A';
      if (hash[i] >= L'a' && hash[i] <= L'f' && (form == 1 || (form == 2 && i % 2)))
        hash[i] -= L'a' - L'A';
    }
    SetDlgItemTextW(window, IDC_EDIT_HASH, hash);
    GetDlgItemTextW(window, IDC_STATIC_CHECK_RESULT, result, 512);
    if (std::wstring(result).find(algorithm) == std::wstring::npos) {
      std::fprintf(stderr, "FAIL: GUI hash comparison rejected hex case form %d\n", form);
      return false;
    }
  }
  SetDlgItemTextW(window, IDC_EDIT_HASH, L"");
  const auto settings_timer = SetTimer(nullptr, 0, 100, inspect_settings);
  if (!settings_timer) return false;
  SendMessageW(window, WM_COMMAND, MAKEWPARAM(IDC_BUTTON_SETTINGS, BN_CLICKED),
      reinterpret_cast<LPARAM>(GetDlgItem(window, IDC_BUTTON_SETTINGS)));
  KillTimer(nullptr, settings_timer);
  if (!settings_checked) return false;
  comparison_checked = false;
  comparison_started = false;
  comparison_polls = 0;
  const auto comparison_timer = SetTimer(nullptr, 0, 50, inspect_comparison);
  if (!comparison_timer) return false;
  SendDlgItemMessageW(window, IDC_BUTTON_COMPARE, BM_CLICK, 0, 0);
  KillTimer(nullptr, comparison_timer);
  if (!comparison_checked) {
    std::fputs("FAIL: comparison dialog controls, calculation or report state\n", stderr);
    return false;
  }
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
    const bool exported = GetProcAddress(module, "DllGetClassObject") != nullptr && localized_resources(module);
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
  if (!property_page_title(properties)) return 1;
  IContextMenu* context{};
  if (!ok(extension->QueryInterface(IID_PPV_ARGS(&context)), "context menu interface")) return 1;
  auto menu = CreatePopupMenu();
  const auto result = context->QueryContextMenu(menu, 0, 1, 100, CMF_NORMAL);
  if (!ok(result, "context menu") || GetMenuItemCount(menu) != 1) return 1;
  wchar_t menu_caption[128]{};
  if (!GetMenuStringW(menu, 0, menu_caption, 128, MF_BYPOSITION)) {
    std::fputs("FAIL: the file context menu hash command has no caption\n", stderr);
    return 1;
  }
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
  const auto module = GetModuleHandleW(argv[1]);
  if (!module) { std::fprintf(stderr, "FAIL: unexpected COM DLL\n"); return 1; }
  if (!localized_resources(module)) return 1;
  if (!window_and_popup_menus(context)) return 1;
  DestroyMenu(menu);
  context->Release(); properties->Release(); extension->Release(); data->Release();
  CoTaskMemFree(absolute); CoTaskMemFree(parent);
  CoUninitialize();
  std::puts("PASS: COM activation, property page and classic context menu");
  return 0;
}
