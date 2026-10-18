// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "Report.h"

class Coordinator;
std::wstring ResultStatusText(oht::ResultStatus status);
void SaveReport(HWND owner, const std::vector<oht::ResultRow>& rows, oht::ReportFormat format);
std::vector<oht::ResultRow> VerificationReport(const Coordinator& coordinator, const std::vector<uint8_t>& check_against);
