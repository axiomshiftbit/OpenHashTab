//    Copyright 2019-2025 namazso <admin@namazso.eu>
//    This file is part of OpenHashTab.
//
//    OpenHashTab is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    OpenHashTab is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with OpenHashTab.  If not, see <https://www.gnu.org/licenses/>.
#include "SettingsDialog.h"

#include "Settings.h"
#include "utl.h"

struct SettingCheckbox {
  RegistrySetting<bool> Settings::*setting;
  int control_id;
  int string_id;
};

#define CTLSTR(name) IDC_CHECK_##name, IDS_##name

// clang-format off
static constexpr SettingCheckbox s_boxes[] =
{
  { &Settings::display_uppercase,               CTLSTR(DISPLAY_UPPERCASE              ) },
  { &Settings::display_monospace,               CTLSTR(DISPLAY_MONOSPACE              ) },
  { &Settings::look_for_sumfiles,               CTLSTR(LOOK_FOR_SUMFILES              ) },
  { &Settings::sumfile_uppercase,               CTLSTR(SUMFILE_UPPERCASE              ) },
  { &Settings::sumfile_unix_endings,            CTLSTR(SUMFILE_UNIX_ENDINGS           ) },
  { &Settings::sumfile_use_double_space,        CTLSTR(SUMFILE_USE_DOUBLE_SPACE       ) },
  { &Settings::sumfile_forward_slashes,         CTLSTR(SUMFILE_FORWARD_SLASHES        ) },
  { &Settings::sumfile_dot_hash_compatible,     CTLSTR(SUMFILE_DOT_HASH_COMPATIBLE    ) },
  { &Settings::sumfile_banner,                  CTLSTR(SUMFILE_BANNER                 ) },
  { &Settings::sumfile_banner_date,             CTLSTR(SUMFILE_BANNER_DATE            ) },
  { &Settings::clipboard_autoenable,            CTLSTR(CLIPBOARD_AUTOENABLE           ) },
  { &Settings::clipboard_autoenable_if_none,    CTLSTR(CLIPBOARD_AUTOENABLE_IF_NONE   ) },
  { &Settings::clipboard_autoenable_exclusive,  CTLSTR(CLIPBOARD_AUTOENABLE_EXCLUSIVE ) },
  { &Settings::checkagainst_autoformat,         CTLSTR(CHECKAGAINST_AUTOFORMAT        ) },
  { &Settings::checkagainst_strict,             CTLSTR(CHECKAGAINST_STRICT            ) },
  { &Settings::hash_sumfile_too,                CTLSTR(HASH_SUMFILE_TOO               ) },
  { &Settings::sumfile_algorithm_only,          CTLSTR(SUMFILE_ALGORITHM_ONLY         ) },
};
// clang-format on

#undef CTLSTR

static bool DoColorButton(HWND owner, RegistrySetting<COLORREF>& setting) {
  static COLORREF defcolors[16] = {
    RGB(45, 170, 23),
    RGB(170, 82, 23),
    RGB(230, 55, 23),
    RGB(255, 55, 23),
    RGB(255, 255, 255),
    RGB(255, 255, 255),
    RGB(255, 255, 255),
    RGB(255, 255, 255),
    RGB(255, 255, 255),
    RGB(255, 255, 255),
    RGB(255, 255, 255),
    RGB(255, 255, 255),
    RGB(255, 255, 255),
    RGB(255, 255, 255),
    RGB(255, 255, 255),
    RGB(255, 255, 255),
  };

  CHOOSECOLORW ccw{};
  ccw.lStructSize = sizeof(ccw);
  ccw.hwndOwner = owner;
  ccw.rgbResult = setting.Get();
  ccw.lpCustColors = defcolors;
  ccw.Flags = CC_ANYCOLOR | CC_FULLOPEN | CC_RGBINIT;
  if (ChooseColorW(&ccw)) {
    setting.Set(ccw.rgbResult);
    return true;
  }
  return false;
}

static std::wstring FormatColor(COLORREF clr) {
  return utl::FormatString(L"#%06X", ((uint32_t)GetRValue(clr) << 16) | ((uint32_t)GetGValue(clr) << 8) | GetBValue(clr));
}

void SettingsDialog::UpdateCheckboxAvailability() {
  const auto banner = BST_CHECKED == Button_GetCheck(_hwnd_CHECK_SUMFILE_BANNER);
  Button_Enable(_hwnd_CHECK_SUMFILE_BANNER_DATE, banner);

  const auto clipboard = BST_CHECKED == Button_GetCheck(_hwnd_CHECK_CLIPBOARD_AUTOENABLE);
  Button_Enable(_hwnd_CHECK_CLIPBOARD_AUTOENABLE_IF_NONE, clipboard);
  Button_Enable(_hwnd_CHECK_CLIPBOARD_AUTOENABLE_EXCLUSIVE, clipboard);
}

void SettingsDialog::UpdateColorItems() {
  for (const auto& e : HASH_COLOR_SETTING_MAP) {
    Button_SetCheck(GetDlgItem(_hwnd, e.settings_dlg_fg_check), _settings->*e.fg_enabled ? BST_CHECKED : 0);
    Button_SetCheck(GetDlgItem(_hwnd, e.settings_dlg_bg_check), _settings->*e.bg_enabled ? BST_CHECKED : 0);
    SetWindowTextW(GetDlgItem(_hwnd, e.settings_dlg_fg_btn), FormatColor((_settings->*e.fg_color).Get()).c_str());
    SetWindowTextW(GetDlgItem(_hwnd, e.settings_dlg_bg_btn), FormatColor((_settings->*e.bg_color).Get()).c_str());
    RedrawWindow(GetDlgItem(_hwnd, e.settings_dlg_sample), nullptr, nullptr, RDW_INVALIDATE);
  }
}

void SettingsDialog::UpdateAlgorithmDescription() {
  const auto list = _hwnd_ALGORITHM_LIST;
  const auto selected = ListView_GetNextItem(list, -1, LVNI_SELECTED);
  LVITEMW item{};
  item.mask = LVIF_PARAM;
  item.iItem = selected;
  if (selected < 0 || !ListView_GetItem(list, &item) || !item.lParam) {
    utl::SetWindowTextStringFromTable(GetDlgItem(_hwnd, IDC_ALGORITHM_DESCRIPTION), IDS_ALGORITHM_NO_RESULTS);
    return;
  }
  const auto& algorithm = *reinterpret_cast<const LegacyHashAlgorithm*>(item.lParam);
  const std::string_view name = algorithm.GetName();
  const auto noncrypto = name.starts_with("CRC") || name.starts_with("XXH") || name == "QuickXorHash";
  const auto category = noncrypto ? IDS_ALGORITHM_NONCRYPTO :
      algorithm.IsSecure() ? IDS_ALGORITHM_CRYPTO : IDS_ALGORITHM_LEGACY;
  UINT note{};
  if (name.starts_with("Ascon-CXOF") || name.starts_with("KT256")) note = IDS_ALGORITHM_EMPTY_CUSTOM;
  else if (name.starts_with("Ascon")) note = IDS_ALGORITHM_ASCON;
  else if (name.starts_with("TurboSHAKE")) note = IDS_ALGORITHM_TURBOSHAKE;
  else if (name.starts_with("K12")) note = IDS_ALGORITHM_K12;
  else if (name.starts_with("Skein")) note = IDS_ALGORITHM_SKEIN;
  else if (name == "Whirlpool") note = IDS_ALGORITHM_WHIRLPOOL;
  else if (name.starts_with("SHAKE") || name.starts_with("PH") || name.starts_with("BLAKE3")) note = IDS_ALGORITHM_XOF;
  auto description = utl::FormatString(utl::GetString(IDS_ALGORITHM_DESCRIPTION).c_str(),
      utl::UTF8ToWide(algorithm.GetName()).c_str(), algorithm.GetSize() * 8u, utl::GetString(category).c_str());
  if (note) description += L"\n" + utl::GetString(note);
  SetWindowTextW(GetDlgItem(_hwnd, IDC_ALGORITHM_DESCRIPTION), description.c_str());
}

void SettingsDialog::UpdateAlgorithmList() {
  const auto list = _hwnd_ALGORITHM_LIST;
  const auto filter = utl::GetWindowTextString(GetDlgItem(_hwnd, IDC_ALGORITHM_SEARCH));
  const auto was_setup = _done_setup;
  _done_setup = false; // Deleting/inserting rows also raises LVN_ITEMCHANGED.
  SendMessageW(list, WM_SETREDRAW, FALSE, 0);
  ListView_DeleteAllItems(list);
  for (const auto& algorithm : LegacyHashAlgorithm::Algorithms()) {
    const auto name = utl::UTF8ToWide(algorithm.GetName());
    if (!filter.empty() && !StrStrIW(name.c_str(), filter.c_str())) continue;
    LVITEMW item{};
    item.mask = LVIF_PARAM | LVIF_TEXT;
    item.iItem = INT_MAX;
    item.pszText = const_cast<LPWSTR>(name.c_str());
    item.lParam = reinterpret_cast<LPARAM>(&algorithm);
    const auto index = ListView_InsertItem(list, &item);
    ListView_SetCheckState(list, index, _settings->algorithms[algorithm.Idx()]);
  }
  if (ListView_GetItemCount(list)) ListView_SetItemState(list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
  ListView_SetColumnWidth(list, 0, LVSCW_AUTOSIZE);
  SendMessageW(list, WM_SETREDRAW, TRUE, 0);
  InvalidateRect(list, nullptr, TRUE);
  _done_setup = was_setup;
  UpdateAlgorithmDescription();
}

void SettingsDialog::ApplyAlgorithmPreset(int preset) {
  if (preset <= 0 || preset > 4) return;
  // A preset replaces the complete selection, including rows hidden by search.
  for (const auto& algorithm : LegacyHashAlgorithm::Algorithms()) {
    const std::string_view name = algorithm.GetName();
    const auto enabled = preset == 3 ||
        (preset == 1 && (name == "SHA-256" || name == "BLAKE3")) ||
        (preset == 2 && (name == "MD5" || name == "SHA-1" || name == "SHA-256" || name == "SHA-512"));
    _settings->algorithms[algorithm.Idx()].Set(enabled);
  }
  UpdateAlgorithmList();
}

INT_PTR SettingsDialog::DlgProc(UINT uMsg, WPARAM wParam, LPARAM lParam) {
  const auto pnmhdr = (LPNMHDR)lParam;
  switch (uMsg) {
  case WM_INITDIALOG: {
    const auto icon = LoadIconW(utl::GetInstance(), MAKEINTRESOURCEW(IDI_ICON_COG));
    SendMessageW(_hwnd, WM_SETICON, ICON_BIG, (LPARAM)icon);

    SetWindowTextW(_hwnd_PROJECT_NAME, L"OpenHashTab " CI_VERSION);

    utl::SetWindowTextStringFromTable(_hwnd, IDS_SETTINGS_TITLE);
    utl::SetWindowTextStringFromTable(_hwnd_BUTTON_CHECK_FOR_UPDATES, IDS_CHECK_FOR_UPDATES);

    const auto fg_text = utl::GetString(IDS_FOREGROUND);
    const auto bg_text = utl::GetString(IDS_BACKGROUND);

    for (const auto& e : HASH_COLOR_SETTING_MAP) {
      const auto wnd = GetDlgItem(_hwnd, e.settings_dlg_group);
      const auto str = utl::GetString(e.settings_dlg_group_str);
      SetWindowTextW(wnd, str.c_str());
      SetWindowTextW(GetDlgItem(_hwnd, e.settings_dlg_fg_check), fg_text.c_str());
      SetWindowTextW(GetDlgItem(_hwnd, e.settings_dlg_bg_check), bg_text.c_str());
    }

    UpdateColorItems();

    utl::SetFontForChildren(_hwnd, _font.get());

    const auto list = _hwnd_ALGORITHM_LIST;
    ListView_SetExtendedListViewStyleEx(list, LVS_EX_CHECKBOXES, LVS_EX_CHECKBOXES);
    LVCOLUMNW column{};
    column.mask = LVCF_FMT;
    column.fmt = LVCFMT_LEFT;
    ListView_InsertColumn(list, 0, &column);
    utl::SetWindowTextStringFromTable(GetDlgItem(_hwnd, IDC_STATIC_ALGORITHM_SEARCH), IDS_ALGORITHM_SEARCH);
    utl::SetWindowTextStringFromTable(GetDlgItem(_hwnd, IDC_STATIC_ALGORITHM_PRESET), IDS_ALGORITHM_PRESET);
    SendDlgItemMessageW(_hwnd, IDC_ALGORITHM_SEARCH, EM_SETLIMITTEXT, 128, 0);
    const auto presets = GetDlgItem(_hwnd, IDC_ALGORITHM_PRESET);
    for (const auto id : {IDS_PRESET_CUSTOM, IDS_PRESET_RECOMMENDED, IDS_PRESET_COMPATIBILITY, IDS_PRESET_ALL, IDS_PRESET_NONE})
      ComboBox_AddString(presets, utl::GetString(id).c_str());
    ComboBox_SetCurSel(presets, 0);
    UpdateAlgorithmList();

    for (const auto& ctl : s_boxes) {
      const auto ctl_hwnd = GetDlgItem(_hwnd, ctl.control_id);
      Button_SetCheck(ctl_hwnd, _settings->*ctl.setting);
      SetWindowTextW(ctl_hwnd, utl::GetString((UINT)ctl.string_id).c_str());
    }

    UpdateCheckboxAvailability();

    _done_setup = true;
    return FALSE; // do not select default control
  }

  case WM_COMMAND: {
    const auto id = LOWORD(wParam);
    const auto code = HIWORD(wParam);
    if (_done_setup && id == IDC_ALGORITHM_SEARCH && code == EN_CHANGE) {
      UpdateAlgorithmList();
      return TRUE;
    }
    if (_done_setup && id == IDC_ALGORITHM_PRESET && code == CBN_SELCHANGE) {
      ApplyAlgorithmPreset(ComboBox_GetCurSel(GetDlgItem(_hwnd, IDC_ALGORITHM_PRESET)));
      return TRUE;
    }
    if (code == BN_CLICKED && (id == IDOK || id == IDCANCEL)) {
      EndDialog(_hwnd, LOWORD(wParam));
      return TRUE;
    }
    if (code == BN_CLICKED && id == IDC_BUTTON_CHECK_FOR_UPDATES) {
      try {
        static constexpr auto current = utl::Version{CI_VERSION_MAJOR, CI_VERSION_MINOR, CI_VERSION_PATCH};
        if constexpr (current.AsNumber() == 0) {
          MessageBoxW(
            _hwnd,
            utl::GetString(IDS_UPDATE_DISABLED_IN_DEV_BUILD).c_str(),
            utl::GetString(IDS_ERROR).c_str(),
            MB_OK | MB_ICONERROR
          );
        } else if (const auto v = utl::GetLatestVersion(); v > current)
          utl::FormattedMessageBox(
            _hwnd,
            utl::GetString(IDS_UPDATE_AVAILABLE_TITLE).c_str(),
            MB_OK | MB_ICONINFORMATION,
            utl::GetString(IDS_UPDATE_AVAILABLE_TEXT).c_str(),
            v.major,
            v.minor,
            v.patch
          );
        else
          MessageBoxW(
            _hwnd,
            utl::GetString(IDS_UPDATE_NEWEST_TEXT).c_str(),
            utl::GetString(IDS_UPDATE_NEWEST_TITLE).c_str(),
            MB_OK
          );

      } catch (const std::runtime_error& e) {
        MessageBoxW(
          _hwnd,
          utl::UTF8ToWide(e.what()).c_str(),
          L"Runtime error",
          MB_ICONERROR | MB_OK
        );
      }
      break;
    }
    if (code == BN_CLICKED) {
      for (const auto& ctl : s_boxes)
        if (id == ctl.control_id)
          (_settings->*ctl.setting).Set(BST_CHECKED == Button_GetCheck(GetDlgItem(_hwnd, ctl.control_id)));

      UpdateCheckboxAvailability();

      for (const auto& e : HASH_COLOR_SETTING_MAP) {
        bool changed = true;
        if (id == e.settings_dlg_fg_check)
          (_settings->*e.fg_enabled).Set(BST_CHECKED == Button_GetCheck(GetDlgItem(_hwnd, e.settings_dlg_fg_check)));
        else if (id == e.settings_dlg_bg_check)
          (_settings->*e.bg_enabled).Set(BST_CHECKED == Button_GetCheck(GetDlgItem(_hwnd, e.settings_dlg_bg_check)));
        else if (id == e.settings_dlg_fg_btn)
          changed = DoColorButton(_hwnd, _settings->*e.fg_color);
        else if (id == e.settings_dlg_bg_btn)
          changed = DoColorButton(_hwnd, _settings->*e.bg_color);
        else
          changed = false;

        if (changed)
          UpdateColorItems();
      }
    }
    break;
  }

  case WM_NOTIFY:
    if (pnmhdr->idFrom == IDC_ALGORITHM_LIST && pnmhdr->code == LVN_ITEMCHANGED && _done_setup) {
      const auto pnmlv = reinterpret_cast<LPNMLISTVIEW>(lParam);
      const auto idx = pnmlv->iItem;
      if (idx < 0 || !(pnmlv->uChanged & LVIF_STATE)) break;
      const auto list = pnmhdr->hwndFrom;
      const auto check = static_cast<bool>(ListView_GetCheckState(list, idx));
      LVITEMW lvitem{
        LVIF_PARAM,
        static_cast<int>(idx)};
      if (!ListView_GetItem(list, &lvitem) || !lvitem.lParam) break;
      const auto algorithm = reinterpret_cast<const LegacyHashAlgorithm*>(lvitem.lParam);
      if ((pnmlv->uOldState ^ pnmlv->uNewState) & LVIS_STATEIMAGEMASK) {
        _settings->algorithms[algorithm->Idx()].Set(check);
        ComboBox_SetCurSel(GetDlgItem(_hwnd, IDC_ALGORITHM_PRESET), 0);
      }
      UpdateAlgorithmDescription();
      return TRUE;
    } else if (pnmhdr->idFrom == IDC_PROJECT_LINK && (pnmhdr->code == NM_CLICK || pnmhdr->code == NM_RETURN)) {
      const auto pnmlink = (PNMLINK)pnmhdr;
      ShellExecuteW(
        nullptr,
        L"open",
        pnmlink->item.szUrl,
        nullptr,
        nullptr,
        SW_SHOW
      );
      return TRUE;
    }
    break;

  case WM_CTLCOLORSTATIC:
    for (size_t i = 0; i < std::size(HASH_COLOR_SETTING_MAP); ++i) {
      const auto& e = HASH_COLOR_SETTING_MAP[i];
      if ((HWND)lParam == _samples[i]) {
        auto hdc = (HDC)wParam;

        if (_settings->*e.fg_enabled)
          SetTextColor(hdc, _settings->*e.fg_color);
        else
          SetTextColor(hdc, GetSysColor(COLOR_WINDOWTEXT));

        if (_settings->*e.bg_enabled)
          SetBkColor(hdc, _settings->*e.bg_color);
        else
          SetBkColor(hdc, GetSysColor(COLOR_WINDOW));

        return (INT_PTR)GetSysColorBrush(COLOR_WINDOW);
      }
    }
    break;
  default:
    break;
  }
  return FALSE;
}
