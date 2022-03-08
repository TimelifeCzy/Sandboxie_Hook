/*
 * Copyright 2004-2020 Sandboxie Holdings, LLC 
 * Copyright 2020-2021 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//---------------------------------------------------------------------------
// Sandboxie DLL -- private include
//---------------------------------------------------------------------------


#ifndef _MY_DLL_H
#define _MY_DLL_H

#include <ntstatus.h>
#define WIN32_NO_STATUS
typedef long NTSTATUS;

#include <windows.h>
#include "../common/win32_ntddk.h"
#include "../common/defines.h"
#include "../common/list.h"

//---------------------------------------------------------------------------
// Defines
//---------------------------------------------------------------------------

extern const ULONG tzuk;
extern const WCHAR* Dll_ImageName;
extern const WCHAR* Dll_BoxName;
extern ULONG64 Dll_ProcessFlags;

#define TRUE_NAME_BUFFER        0
#define COPY_NAME_BUFFER        1
#define TMPL_NAME_BUFFER        2
#define NAME_BUFFER_COUNT       3
#define NAME_BUFFER_DEPTH       12


#ifdef _WIN64
#define Dll_IsWin64 1
#else
#define Dll_IsWin64 Dll_IsWow64
#endif _WIN64

#ifdef _WIN64

// Pointer to 64-bit PEB_LDR_DATA is at offset 0x0018 of 64-bit PEB
#define GET_ADDR_OF_PEB __readgsqword(0x60)
#define GET_PEB_LDR_DATA (*(PEB_LDR_DATA **)(GET_ADDR_OF_PEB + 0x18))
#define GET_PEB_IMAGE_BASE (*(ULONG_PTR *)(GET_ADDR_OF_PEB + 0x10))
#define GET_PEB_MAJOR_VERSION (*(USHORT *)(GET_ADDR_OF_PEB + 0x118))
#define GET_PEB_MINOR_VERSION (*(USHORT *)(GET_ADDR_OF_PEB + 0x11c))
#define GET_PEB_IMAGE_BUILD (*(USHORT *)(GET_ADDR_OF_PEB + 0x120))

#else

// Pointer to 32-bit PEB_LDR_DATA is at offset 0x000C of 32-bit PEB
#define GET_ADDR_OF_PEB __readfsdword(0x30)
#define GET_PEB_LDR_DATA (*(PEB_LDR_DATA **)(GET_ADDR_OF_PEB + 0x0C))
#define GET_PEB_IMAGE_BASE (*(ULONG_PTR *)(GET_ADDR_OF_PEB + 0x08))
#define GET_PEB_MAJOR_VERSION (*(USHORT *)(GET_ADDR_OF_PEB + 0xa4))
#define GET_PEB_MINOR_VERSION (*(USHORT *)(GET_ADDR_OF_PEB + 0xa8))
#define GET_PEB_IMAGE_BUILD (*(USHORT *)(GET_ADDR_OF_PEB + 0xac))

#endif  _WIN64

#ifdef __cplusplus
extern "C" {
#endif

extern __declspec(dllexport) int __CRTDECL Sbie_snwprintf(wchar_t* _Buffer, size_t Count, const wchar_t* const _Format, ...);
extern __declspec(dllexport) int __CRTDECL Sbie_snprintf(char* _Buffer, size_t Count, const char* const _Format, ...);

typedef struct _THREAD_DATA {

    //
    // name buffers:  first index is for true name, second for copy name
    //

    WCHAR* name_buffer[NAME_BUFFER_COUNT][NAME_BUFFER_DEPTH];
    ULONG name_buffer_len[NAME_BUFFER_COUNT][NAME_BUFFER_DEPTH];
    int depth;

    //
    // locks
    //

    BOOLEAN key_NtCreateKey_lock;

    BOOLEAN file_NtCreateFile_lock;
    BOOLEAN file_NtClose_lock;
    BOOLEAN file_GetCurDir_lock;

    BOOLEAN ipc_KnownDlls_lock;

    BOOLEAN obj_NtQueryObject_lock;

    //
    // file module
    //

    ULONG file_dont_strip_write_access;

    //
    // proc module:  image path for a child process being started
    //

    ULONG           proc_create_process;
    BOOLEAN         proc_create_process_capture_image;
    BOOLEAN         proc_create_process_force_elevate;
    BOOLEAN         proc_create_process_as_invoker;
    BOOLEAN         proc_image_is_copy;
    WCHAR* proc_image_path;
    WCHAR* proc_command_line;

    ULONG           sh32_shell_execute;

    //
    // gui module
    //

    ULONG_PTR       gui_himc;

    HWND            gui_dde_client_hwnd;
    HWND            gui_dde_proxy_hwnd;
    WPARAM          gui_dde_post_wparam;
    LPARAM          gui_dde_post_lparam;

    ULONG           gui_create_window;

    BOOLEAN         gui_hooks_installed;

    BOOL            gui_should_suppress_msgbox;

    //
    // sbieapi:  SbieSvc port handle
    //

    HANDLE          PortHandle;
    ULONG           MaxDataLen;
    ULONG           SizeofPortMsg;
    BOOLEAN         bOperaFileDlgThread;

    //
    // rpc module
    //

    ULONG_PTR       rpc_caller;

} THREAD_DATA;

//---------------------------------------------------------------------------
// Functions (dllmem)
//---------------------------------------------------------------------------
void* Dll_AllocCode128(void);
void Dll_FreeCode128(void* ptr);

//---------------------------------------------------------------------------
// Functions (dllhook)
//---------------------------------------------------------------------------
NTSTATUS Dll_GetSettingsForImageName(
    const WCHAR* setting, WCHAR* value, ULONG value_size, const WCHAR* deftext);

BOOLEAN Dll_SkipHook(const WCHAR *HookName);

void *Dll_JumpStub(void *OldCode, void *NewCode, ULONG_PTR StubArg);

ULONG_PTR *Dll_JumpStubData(void);

ULONG_PTR *Dll_JumpStubDataForCode(void *StubCode);

#ifdef _WIN64

#define Dll_FixWow64Syscall()

#else ! _WIN64

void Dll_FixWow64Syscall(void);

#endif _WIN64

#ifdef __cplusplus
}
#endif

//---------------------------------------------------------------------------


#endif /* _MY_DLL_H */
