// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "BatchOperations.h"
#include "utl.h"
#include <exception>
#include <thread>

class CompareDialog {
  HWND _hwnd;
  utl::UniqueFont _font{utl::GetDPIScaledFont()};
  std::thread _worker;
  std::atomic<bool> _cancelled{}, _done{};
  std::atomic<uint64_t> _processed{}, _total{};
  std::vector<oht::ResultRow> _rows;
  std::exception_ptr _error;
  uint64_t _started{};
  bool _running{}, _closing{};
  void PickPath(int control, bool folder);
  void Start();
  void Poll();
  void Stop();
  void SetRunning(bool running);
public:
  CompareDialog(HWND window, void*) : _hwnd(window) {}
  ~CompareDialog();
  INT_PTR DlgProc(UINT message, WPARAM wparam, LPARAM lparam);
};
