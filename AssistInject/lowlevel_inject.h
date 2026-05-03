#pragma once

#include <windows.h>
#include <string>

struct InjectExecResult
{
    ULONG errlvl = 0;
    DWORD last_error = 0;
};

bool LowLevelInjectInitialize();
bool LowLevelInjectProcess(
    DWORD pid,
    unsigned long long create_time,
    const std::wstring& nt_path,
    InjectExecResult* result = nullptr);
