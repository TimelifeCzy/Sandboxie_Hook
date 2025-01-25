#pragma once
#ifndef _PROCESS_H
#define _PROCESS_H

#define MEM_TAG_PROCESS	'PROC'

typedef struct _PROC_ENTRY {
	LIST_ENTRY lEntry;
	HANDLE pid;
} PROC_ENTRY, * PPROC_ENTRY;

// init
void ProcessInit(const PDRIVER_OBJECT pDriverObject);
void ProcessUnInit();

// register notify callback
NTSTATUS ProcessNotifyRoutine_Init();
NTSTATUS ProcessNotifyRoutine_UnInit();

// register protect callback
NTSTATUS ProcessProtect_Init(const PDRIVER_OBJECT pDriverObject);
NTSTATUS ProcessProtect_UnInit(void);
NTSTATUS ProcessProtect_SetProcPid(const int hPid);

#endif
