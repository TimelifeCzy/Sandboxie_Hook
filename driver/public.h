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

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out PULONG ReturnLength
);

enum MIN_COMMAND
{
    IPS_PROCESSSTART = 1,
    IPS_PROCESSINJECT = 2,
    IPS_IMAGEDLL = 3,
};

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

#define HADES_READ_BUFFER_SIZE  4096 
typedef struct _HADES_REPLY {
    DWORD SafeToOpen;
} HADES_REPLY, * PHADES_REPLY;

typedef struct _HADES_NOTIFICATION {
    ULONG CommandId;
    ULONG Reserved;
    UCHAR Contents[HADES_READ_BUFFER_SIZE];
} HADES_NOTIFICATION, * PHADES_NOTIFICATION;

#endif