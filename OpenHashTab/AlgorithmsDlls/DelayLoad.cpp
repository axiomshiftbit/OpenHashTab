// SPDX-License-Identifier: GPL-3.0-or-later
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <delayimp.h>
#include <cstring>
#include <cwchar>
#include <initializer_list>

// Explorer's executable directory and current directory are not the extension's
// installation directory. Resolve private dependencies relative to this module.
static FARPROC WINAPI load_private_dependency(unsigned notification, PDelayLoadInfo info) {
  if (notification != dliNotePreLoadLibrary) return nullptr;
  HMODULE loaded{};
  if (_stricmp(info->szDll, "winhttp.dll") == 0) {
    loaded = LoadLibraryExW(L"winhttp.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  } else {
    bool algorithms = false;
    for (const auto name : {"AlgorithmsDll_x86.dll", "AlgorithmsDll_SSE2.dll", "AlgorithmsDll_AVX2.dll",
                            "AlgorithmsDll_AVX512.dll", "AlgorithmsDll_ARM64.dll"})
      algorithms = algorithms || _stricmp(info->szDll, name) == 0;
    if (!algorithms) return nullptr;
    HMODULE self{};
    wchar_t path[32768]{};
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                          reinterpret_cast<LPCWSTR>(&load_private_dependency), &self)) {
      const auto length = GetModuleFileNameW(self, path, 32768);
      if (length && length < 32768) {
        if (auto slash = wcsrchr(path, L'\\')) {
          const auto remaining = 32768 - static_cast<int>(slash + 1 - path);
          if (MultiByteToWideChar(CP_ACP, 0, info->szDll, -1, slash + 1, remaining))
            loaded = LoadLibraryExW(path, nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        }
      }
    }
  }
  if (!loaded) {
    // Returning null would fall back to the unsafe default DLL search order.
    const ULONG_PTR arguments[] = {reinterpret_cast<ULONG_PTR>(info)};
    RaiseException(VcppException(ERROR_SEVERITY_ERROR, ERROR_MOD_NOT_FOUND),
                   EXCEPTION_NONCONTINUABLE, 1, arguments);
  }
  return reinterpret_cast<FARPROC>(loaded);
}
extern "C" const PfnDliHook __pfnDliNotifyHook2 = load_private_dependency;
