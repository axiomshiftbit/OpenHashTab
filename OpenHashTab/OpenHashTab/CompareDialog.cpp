// SPDX-License-Identifier: GPL-3.0-or-later
#include "CompareDialog.h"
#include "ProgressText.h"
#include "ReportUI.h"
#include <Hasher.h>

CompareDialog::~CompareDialog() {
  Stop();
  if (_worker.joinable()) _worker.join();
}

void CompareDialog::Stop() {
  _cancelled.store(true);
  if (_worker.joinable()) CancelSynchronousIo(_worker.native_handle());
}

void CompareDialog::SetRunning(bool running) {
  _running = running;
  for (const auto id : {IDC_COMPARE_LEFT, IDC_COMPARE_RIGHT, IDC_COMPARE_LEFT_FILE, IDC_COMPARE_LEFT_FOLDER,
      IDC_COMPARE_RIGHT_FILE, IDC_COMPARE_RIGHT_FOLDER, IDC_COMPARE_ALGORITHM, IDC_COMPARE_START}) {
    EnableWindow(GetDlgItem(_hwnd, id), !running);
  }
  EnableWindow(GetDlgItem(_hwnd, IDC_COMPARE_CANCEL), running);
  EnableWindow(GetDlgItem(_hwnd, IDC_COMPARE_JSON), !running && !_rows.empty());
  EnableWindow(GetDlgItem(_hwnd, IDC_COMPARE_CSV), !running && !_rows.empty());
}

void CompareDialog::PickPath(int control, bool folder) {
  std::wstring path;
  if (folder) {
    const auto initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    {
      ATL::CComPtr<IFileOpenDialog> picker;
      auto hr = picker.CoCreateInstance(CLSID_FileOpenDialog);
      if (SUCCEEDED(hr)) hr = picker->SetOptions(FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
      if (SUCCEEDED(hr)) hr = picker->Show(_hwnd);
      if (SUCCEEDED(hr)) {
        ATL::CComPtr<IShellItem> item;
        hr = picker->GetResult(&item);
        if (SUCCEEDED(hr)) {
          PWSTR value{};
          hr = item->GetDisplayName(SIGDN_FILESYSPATH, &value);
          if (SUCCEEDED(hr)) path = value;
          CoTaskMemFree(value);
        }
      }
      if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
        const auto text = utl::FormatString(L"0x%08X", static_cast<unsigned>(hr));
        MessageBoxW(_hwnd, text.c_str(), utl::GetString(IDS_ERROR).c_str(), MB_OK | MB_ICONERROR);
      }
    }
    if (SUCCEEDED(initialized)) CoUninitialize();
  } else {
    std::vector<wchar_t> buffer(32768);
    OPENFILENAMEW picker{};
    picker.lStructSize = sizeof(picker);
    picker.hwndOwner = _hwnd;
    picker.lpstrFile = buffer.data();
    picker.nMaxFile = static_cast<DWORD>(buffer.size());
    picker.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameW(&picker)) path = buffer.data();
    else if (const auto error = CommDlgExtendedError()) {
      const auto text = utl::FormatString(L"0x%08X", error);
      MessageBoxW(_hwnd, text.c_str(), utl::GetString(IDS_ERROR).c_str(), MB_OK | MB_ICONERROR);
    }
  }
  if (!path.empty()) SetDlgItemTextW(_hwnd, control, path.c_str());
}

void CompareDialog::Start() {
  if (_running) return;
  const auto left = utl::GetWindowTextString(GetDlgItem(_hwnd, IDC_COMPARE_LEFT));
  const auto right = utl::GetWindowTextString(GetDlgItem(_hwnd, IDC_COMPARE_RIGHT));
  const auto index = ComboBox_GetCurSel(GetDlgItem(_hwnd, IDC_COMPARE_ALGORITHM));
  if (left.empty() || right.empty() || index < 0 || index >= LegacyHashAlgorithm::k_count) {
    MessageBoxW(_hwnd, utl::GetString(IDS_COMPARE_EMPTY_PATH).c_str(), utl::GetString(IDS_ERROR).c_str(), MB_OK | MB_ICONERROR);
    return;
  }
  _rows.clear();
  _error = {};
  _done = false;
  _cancelled = false;
  _processed = _total = 0;
  _started = GetTickCount64();
  ListView_DeleteAllItems(GetDlgItem(_hwnd, IDC_COMPARE_RESULTS));
  SetDlgItemTextW(_hwnd, IDC_COMPARE_SUMMARY, utl::GetString(IDS_PROCESSING).c_str());
  SetDlgItemTextW(_hwnd, IDC_COMPARE_PROGRESS, L"");
  if (!SetTimer(_hwnd, 1, 250, nullptr)) {
    const auto error = GetLastError();
    SetDlgItemTextW(_hwnd, IDC_COMPARE_SUMMARY, utl::GetString(IDS_ERROR).c_str());
    SetRunning(false);
    MessageBoxW(_hwnd, utl::ErrorToString(error).c_str(), utl::GetString(IDS_ERROR).c_str(), MB_OK | MB_ICONERROR);
    return;
  }
  SetRunning(true);
  const auto algorithm = &LegacyHashAlgorithm::Algorithms()[index];
  try {
    _worker = std::thread([this, left, right, algorithm] {
      try {
        _rows = oht::ComparePaths(left, right, *algorithm, _cancelled, [this](oht::ProgressSnapshot progress) {
          _total = progress.total;
          _processed = progress.processed;
        });
      } catch (...) { _error = std::current_exception(); }
      _done = true;
    });
  } catch (const std::exception& error) {
    KillTimer(_hwnd, 1);
    SetRunning(false);
    SetDlgItemTextW(_hwnd, IDC_COMPARE_SUMMARY, utl::GetString(IDS_ERROR).c_str());
    MessageBoxW(_hwnd, utl::UTF8ToWide(error.what()).c_str(), utl::GetString(IDS_ERROR).c_str(), MB_OK | MB_ICONERROR);
  }
}

void CompareDialog::Poll() {
  const auto done = _done.load();
  SetDlgItemTextW(_hwnd, IDC_COMPARE_PROGRESS,
      ProgressText({_processed.load(), _total.load()}, GetTickCount64() - _started, done || _cancelled.load()).c_str());
  if (!done || !_running) return;
  KillTimer(_hwnd, 1);
  _worker.join();
  SetRunning(false);
  if (_closing) { EndDialog(_hwnd, IDCANCEL); return; }
  if (_error) {
    SetDlgItemTextW(_hwnd, IDC_COMPARE_SUMMARY, utl::GetString(IDS_ERROR).c_str());
    try { std::rethrow_exception(_error); }
    catch (const std::exception& error) {
      MessageBoxW(_hwnd, utl::UTF8ToWide(error.what()).c_str(), utl::GetString(IDS_ERROR).c_str(), MB_OK | MB_ICONERROR);
    }
    catch (...) { MessageBoxW(_hwnd, utl::GetString(IDS_ERROR).c_str(), L"OpenHashTab", MB_OK | MB_ICONERROR); }
    return;
  }
  const auto list = GetDlgItem(_hwnd, IDC_COMPARE_RESULTS);
  SendMessageW(list, WM_SETREDRAW, FALSE, 0);
  unsigned long long matches = 0, differences = 0, missing = 0, errors = 0;
  int hash_width = utl::GetDPIScaledPixels(list, 100);
  for (const auto& row : _rows) {
    const std::wstring values[] = {utl::UTF8ToWide(row.path.c_str()), ResultStatusText(row.status),
        utl::UTF8ToWide(row.expected.c_str()), utl::UTF8ToWide(row.actual.c_str()), utl::UTF8ToWide(row.error.c_str())};
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iItem = INT_MAX;
    item.pszText = const_cast<LPWSTR>(values[0].c_str());
    const auto index = ListView_InsertItem(list, &item);
    for (int column = 1; column < 5; ++column) ListView_SetItemText(list, index, column, const_cast<LPWSTR>(values[column].c_str()));
    hash_width = std::max(hash_width, ListView_GetStringWidth(list, values[2].c_str()) + utl::GetDPIScaledPixels(list, 16));
    hash_width = std::max(hash_width, ListView_GetStringWidth(list, values[3].c_str()) + utl::GetDPIScaledPixels(list, 16));
    matches += row.status == oht::ResultStatus::Match;
    differences += row.status == oht::ResultStatus::Mismatch;
    missing += row.status == oht::ResultStatus::MissingLeft || row.status == oht::ResultStatus::MissingRight;
    errors += row.status == oht::ResultStatus::Error;
  }
  ListView_SetColumnWidth(list, 2, hash_width);
  ListView_SetColumnWidth(list, 3, hash_width);
  SendMessageW(list, WM_SETREDRAW, TRUE, 0);
  InvalidateRect(list, nullptr, TRUE);
  auto summary = utl::FormatString(utl::GetString(IDS_COMPARE_SUMMARY).c_str(), matches, differences, missing, errors);
  if (oht::ResultExitCode(_rows) == 4) summary += L" · " + utl::GetString(IDS_CANCELLED);
  SetDlgItemTextW(_hwnd, IDC_COMPARE_SUMMARY, summary.c_str());
}

INT_PTR CompareDialog::DlgProc(UINT message, WPARAM wparam, LPARAM) {
  if (message == WM_INITDIALOG) {
    utl::SetFontForChildren(_hwnd, _font.get());
    utl::SetWindowTextStringFromTable(_hwnd, IDS_COMPARE_TITLE);
    const std::pair<int, int> labels[] = {
      {IDC_COMPARE_LEFT_LABEL, IDS_COMPARE_LEFT}, {IDC_COMPARE_RIGHT_LABEL, IDS_COMPARE_RIGHT},
      {IDC_COMPARE_ALGORITHM_LABEL, IDS_ALGORITHM}, {IDC_COMPARE_START, IDS_COMPARE_START},
      {IDC_COMPARE_CANCEL, IDS_CANCEL}, {IDCANCEL, IDS_CLOSE}, {IDC_COMPARE_JSON, IDS_REPORT_JSON}, {IDC_COMPARE_CSV, IDS_REPORT_CSV},
      {IDC_COMPARE_LEFT_FILE, IDS_BROWSE_FILE}, {IDC_COMPARE_RIGHT_FILE, IDS_BROWSE_FILE},
      {IDC_COMPARE_LEFT_FOLDER, IDS_BROWSE_FOLDER}, {IDC_COMPARE_RIGHT_FOLDER, IDS_BROWSE_FOLDER},
    };
    for (const auto& [control, text] : labels) utl::SetWindowTextStringFromTable(GetDlgItem(_hwnd, control), text);
    for (const auto& algorithm : LegacyHashAlgorithm::Algorithms()) {
      ComboBox_AddString(GetDlgItem(_hwnd, IDC_COMPARE_ALGORITHM), utl::UTF8ToWide(algorithm.GetName()).c_str());
    }
    ComboBox_SetCurSel(GetDlgItem(_hwnd, IDC_COMPARE_ALGORITHM), LegacyHashAlgorithm::IdxByName("SHA-256"));
    for (const auto id : {IDC_COMPARE_LEFT, IDC_COMPARE_RIGHT}) SendDlgItemMessageW(_hwnd, id, EM_SETLIMITTEXT, 32767, 0);
    const auto list = GetDlgItem(_hwnd, IDC_COMPARE_RESULTS);
    ListView_SetExtendedListViewStyle(list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    const int columns[] = {IDS_FILENAME, IDS_RESULT_STATUS, IDS_EXPECTED_HASH, IDS_ACTUAL_HASH, IDS_ERROR};
    const int widths[] = {220, 180, 300, 300, 400};
    for (int i = 0; i < 5; ++i) {
      const auto name = utl::GetString(columns[i]);
      LVCOLUMNW column{};
      column.mask = LVCF_TEXT | LVCF_WIDTH;
      column.pszText = const_cast<LPWSTR>(name.c_str());
      column.cx = utl::GetDPIScaledPixels(list, widths[i]);
      ListView_InsertColumn(list, i, &column);
    }
    SetRunning(false);
    return TRUE;
  }
  if (message == WM_TIMER && wparam == 1) { Poll(); return TRUE; }
  if (message == WM_CLOSE || (message == WM_COMMAND && LOWORD(wparam) == IDCANCEL)) {
    if (_running) { _closing = true; Stop(); }
    else EndDialog(_hwnd, IDCANCEL);
    return TRUE;
  }
  if (message == WM_COMMAND && HIWORD(wparam) == BN_CLICKED) {
    const auto id = LOWORD(wparam);
    if (id == IDC_COMPARE_CANCEL) { Stop(); return TRUE; }
    if (_running) return FALSE;
    switch (id) {
    case IDC_COMPARE_START: Start(); return TRUE;
    case IDC_COMPARE_LEFT_FILE: PickPath(IDC_COMPARE_LEFT, false); return TRUE;
    case IDC_COMPARE_LEFT_FOLDER: PickPath(IDC_COMPARE_LEFT, true); return TRUE;
    case IDC_COMPARE_RIGHT_FILE: PickPath(IDC_COMPARE_RIGHT, false); return TRUE;
    case IDC_COMPARE_RIGHT_FOLDER: PickPath(IDC_COMPARE_RIGHT, true); return TRUE;
    case IDC_COMPARE_JSON: SaveReport(_hwnd, _rows, oht::ReportFormat::Json); return TRUE;
    case IDC_COMPARE_CSV: SaveReport(_hwnd, _rows, oht::ReportFormat::Csv); return TRUE;
    }
  }
  return FALSE;
}
