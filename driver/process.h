#pragma once
#ifndef _PROCESS_H
#define _PROCESS_H

#define MEM_TAG_PROCESS	'PROC'
#define MEM_TAG_PROCESS_INJECT	'PINJ'

typedef struct _PROC_ENTRY {
	LIST_ENTRY lEntry;
	HANDLE pid;
} PROC_ENTRY, * PPROC_ENTRY;

typedef struct _PROCESSINFO
{
	int parentprocessid;
	int pid;
	int endprocess;
	wchar_t processpath[301 * 2];
	wchar_t commandLine[301 * 2];
	wchar_t queryprocesspath[301 * 2];
}PROCESSINFO, * PPROCESSINFO;

// init
void ProcessInit(const PDRIVER_OBJECT pDriverObject);
void ProcessUnInit();

// register notify callback
NTSTATUS SetInjectProcess(PIRP irp, PIO_STACK_LOCATION irpSp);
NTSTATUS ProcessNotifyRoutine_Init();
NTSTATUS ProcessNotifyRoutine_UnInit();

// register protect callback
NTSTATUS ProcessProtect_Init(const PDRIVER_OBJECT pDriverObject);
NTSTATUS ProcessProtect_UnInit(void);
NTSTATUS ProcessProtect_SetProcPid(const int hPid);

#endif
