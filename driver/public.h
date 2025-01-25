#pragma once
#ifndef _PUBLIC_H
#define _PUBLIC_H

#include <ntifs.h>
#include <ntstrsafe.h>

typedef struct _PPIDCMD {
	int		type;
    int	    processId;
} PPIDCMD, * PPPIDCMD;

#define NF_REQ_SET_INJECT_PROCESS \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 101, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_REQ_SET_PROCESSPID \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 102, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY64    InLoadOrderLinks;
    LIST_ENTRY64    InMemoryOrderLinks;
    LIST_ENTRY64    InInitializationOrderLinks;
    PVOID            DllBase;
    PVOID            EntryPoint;
    ULONG            SizeOfImage;
    UNICODE_STRING    FullDllName;
    UNICODE_STRING     BaseDllName;
    ULONG            Flags;
    USHORT            LoadCount;
    USHORT            TlsIndex;
    PVOID            SectionPointer;
    ULONG            CheckSum;
    PVOID            LoadedImports;
    PVOID            EntryPointActivationContext;
    PVOID            PatchInformation;
    LIST_ENTRY64    ForwarderLinks;
    LIST_ENTRY64    ServiceTagLinks;
    LIST_ENTRY64    StaticLinks;
    PVOID            ContextInformation;
    ULONG64            OriginalBase;
    LARGE_INTEGER    LoadTime;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;

typedef NTSTATUS(*PfnNtQueryInformationProcess) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
    );
static PfnNtQueryInformationProcess ZwQueryInformationProcess = NULL;

#endif