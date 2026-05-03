#include "pch.h"

#include "lowlevel_inject.h"

#include <cstdarg>

HMODULE Dll_Instance = NULL;
HMODULE Dll_Ntdll = NULL;
HMODULE Dll_KernelBase = NULL;
ULONG Dll_Windows = 0;
ULONG Dll_OsBuild = 0;

ULONG SbieDll_InjectLow_InitHelper();
ULONG SbieDll_InjectLow_InitSyscalls(BOOLEAN drv_init);
ULONG SbieDll_InjectLow(HANDLE hProcess, ULONG init_flags, BOOLEAN dup_drv_handle);

namespace {

std::once_flag g_lowLevelInitOnce;
ULONG g_lowLevelInitStatus = ERROR_NOT_READY;

std::wstring GetModuleDirectory()
{
    WCHAR path[MAX_PATH] = { 0 };
    HMODULE module = Dll_Instance ? Dll_Instance : GetModuleHandleW(nullptr);
    if (!GetModuleFileNameW(module, path, ARRAYSIZE(path)))
        return L"";

    WCHAR* slash = wcsrchr(path, L'\\');
    if (slash)
        *slash = L'\0';
    return path;
}

void InitVersionInfo()
{
    using RtlGetVersionFn = LONG(WINAPI*)(LPOSVERSIONINFOW);

    OSVERSIONINFOW versionInfo = {};
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);

    auto rtlGetVersion = reinterpret_cast<RtlGetVersionFn>(
        GetProcAddress(Dll_Ntdll, "RtlGetVersion"));
    if (rtlGetVersion && rtlGetVersion(&versionInfo) == 0) {
        Dll_Windows = versionInfo.dwMajorVersion;
        Dll_OsBuild = versionInfo.dwBuildNumber;
    }
}

void EnsureLowLevelInitialized()
{
    Dll_Instance = GetModuleHandleW(nullptr);
    Dll_Ntdll = GetModuleHandleW(L"ntdll.dll");
    Dll_KernelBase = GetModuleHandleW(L"kernelbase.dll");

    if (!Dll_Instance || !Dll_Ntdll || !Dll_KernelBase) {
        g_lowLevelInitStatus = ERROR_MOD_NOT_FOUND;
        return;
    }

    InitVersionInfo();

    g_lowLevelInitStatus = SbieDll_InjectLow_InitHelper();
    if (g_lowLevelInitStatus != 0)
        return;

    g_lowLevelInitStatus = SbieDll_InjectLow_InitSyscalls(FALSE);
}

HANDLE OpenTargetProcess(DWORD pid)
{
    const DWORD desiredAccess =
        PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME |
        PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE;

    for (int attempt = 0; attempt < 40; ++attempt) {
        HANDLE processHandle = OpenProcess(desiredAccess, FALSE, pid);
        if (processHandle)
            return processHandle;
        Sleep(50);
    }

    return NULL;
}

bool ValidateCreateTime(HANDLE processHandle, unsigned long long expectedCreateTime)
{
    if (expectedCreateTime == 0)
        return true;

    FILETIME createTime = {};
    FILETIME exitTime = {};
    FILETIME kernelTime = {};
    FILETIME userTime = {};
    if (!GetProcessTimes(processHandle, &createTime, &exitTime, &kernelTime, &userTime))
        return false;

    ULARGE_INTEGER currentCreateTime = {};
    currentCreateTime.LowPart = createTime.dwLowDateTime;
    currentCreateTime.HighPart = createTime.dwHighDateTime;
    return currentCreateTime.QuadPart == expectedCreateTime;
}

void DebugLogV(const wchar_t* prefix, const wchar_t* format, va_list args)
{
    wchar_t body[512] = { 0 };
    _vsnwprintf_s(body, _countof(body), _TRUNCATE, format, args);

    std::wstring text = prefix;
    text += body;
    text += L"\n";
    OutputDebugStringW(text.c_str());
}

} // namespace

LONG SbieApi_Call(ULONG api_code, LONG arg_num, ...)
{
    UNREFERENCED_PARAMETER(api_code);
    UNREFERENCED_PARAMETER(arg_num);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

LONG SbieApi_Log(ULONG msgid, const WCHAR* format, ...)
{
    va_list args;
    va_start(args, format);

    wchar_t prefix[64] = { 0 };
    _snwprintf_s(prefix, _countof(prefix), _TRUNCATE, L"[SbieApi_Log:%lu] ", msgid);
    DebugLogV(prefix, format ? format : L"", args);

    va_end(args);
    return 0;
}

LONG SbieApi_GetHomePath(WCHAR* NtPath, ULONG NtPathMaxLen, WCHAR* DosPath, ULONG DosPathMaxLen)
{
    const std::wstring homePath = GetModuleDirectory();
    if (homePath.empty())
        return ERROR_PATH_NOT_FOUND;

    if (DosPath && DosPathMaxLen) {
        if (homePath.size() + 1 > DosPathMaxLen)
            return ERROR_INSUFFICIENT_BUFFER;
        wcscpy_s(DosPath, DosPathMaxLen, homePath.c_str());
    }

    if (NtPath && NtPathMaxLen) {
        if (homePath.size() + 1 > NtPathMaxLen)
            return ERROR_INSUFFICIENT_BUFFER;
        wcscpy_s(NtPath, NtPathMaxLen, homePath.c_str());
    }

    return 0;
}

bool LowLevelInjectInitialize()
{
    std::call_once(g_lowLevelInitOnce, EnsureLowLevelInitialized);
    if (g_lowLevelInitStatus != 0) {
        SetLastError(g_lowLevelInitStatus);
        return false;
    }
    return true;
}

bool LowLevelInjectProcess(DWORD pid, unsigned long long create_time, const std::wstring& nt_path, InjectExecResult* result)
{
    InjectExecResult localResult = {};
    if (!LowLevelInjectInitialize()) {
        localResult.last_error = GetLastError();
        if (result)
            *result = localResult;
        return false;
    }

    HANDLE processHandle = OpenTargetProcess(pid);
    if (!processHandle) {
        localResult.last_error = GetLastError();
        if (result)
            *result = localResult;
        return false;
    }

    if (!ValidateCreateTime(processHandle, create_time)) {
        localResult.last_error = ERROR_INVALID_HANDLE;
        CloseHandle(processHandle);
        if (result)
            *result = localResult;
        return false;
    }

    localResult.errlvl = SbieDll_InjectLow(processHandle, 0, FALSE);
    localResult.last_error = GetLastError();
    CloseHandle(processHandle);

    if (localResult.errlvl != 0) {
        std::wstring text = L"LowLevelInject failed: ";
        text += nt_path;
        text += L"\n";
        OutputDebugStringW(text.c_str());
        if (result)
            *result = localResult;
        return false;
    }

    if (result)
        *result = localResult;
    return true;
}
