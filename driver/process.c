#include "public.h"
#include "process.h"
#define MAX_PROCESS_PATH_LEN 300

static LIST_ENTRY g_procListHead;
static KSPIN_LOCK g_procListLock;

// Inject process list
static PWCHAR	g_pInjectProcs = NULL;

// extern process name
NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);

// protect init
static int		g_nProtectPid = 0;
static PVOID	g_pObHandle = NULL;

// callback init
static int		g_bInitNotify = 0;

BOOLEAN QueryProcessNamePath(__in DWORD pid, __out PWCHAR path, __in DWORD pathlen)
{
	HANDLE hProc = NULL;
	BOOLEAN bRet = FALSE;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	CLIENT_ID cid;
	OBJECT_ATTRIBUTES obj;
	InitializeObjectAttributes(&obj, NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = NULL;
	status = ZwOpenProcess(&hProc, GENERIC_ALL, &obj, &cid);
	if (NT_SUCCESS(status) && hProc && ZwQueryInformationProcess) 
	{
		DWORD dwProcessLen = 0;
		WCHAR ProcessPath[MAX_PROCESS_PATH_LEN + sizeof(UNICODE_STRING)] = { 0, };
		status = ZwQueryInformationProcess(hProc, ProcessImageFileName, ProcessPath, sizeof(ProcessPath), &dwProcessLen);
		if (NT_SUCCESS(status))
		{
			PUNICODE_STRING ProcessPathUString = (PUNICODE_STRING)ProcessPath;
			if (ProcessPathUString && ProcessPathUString->Length) {
				if (pathlen > (DWORD)ProcessPathUString->Length + sizeof(WCHAR))
				{
					RtlMoveMemory(path, ProcessPathUString->Buffer, ProcessPathUString->Length + sizeof(WCHAR));
					bRet = TRUE;
				}
			}
		}
		if (hProc)
			ZwClose(hProc);
	}
	return bRet;
}

BOOLEAN RemoveProcessId(__in HANDLE hProcessId)
{
	BOOLEAN bRet = FALSE;
	PLIST_ENTRY pListHead, t;
	KIRQL irql;

	KeAcquireSpinLock(&g_procListLock, &irql);
	pListHead = &g_procListHead;
	for (t = pListHead->Flink; t != pListHead; t = t->Flink)
	{
		PPROC_ENTRY pEntry = CONTAINING_RECORD(t, PROC_ENTRY, lEntry);
		if (pEntry->pid == hProcessId)
		{
			RemoveEntryList((PLIST_ENTRY)pEntry);
			ExFreePool(pEntry);
			bRet = TRUE;
			break;
		}
	}
	KeReleaseSpinLock(&g_procListLock, irql);
	return bRet;
}

BOOLEAN IsInjectProcess(__in PWCHAR path)
{
	if (!path)
		return FALSE;

	BOOLEAN bRet = FALSE;
	if (g_pInjectProcs)
	{
		PWCHAR pName = wcsrchr(path, L'\\');
		if (pName)
		{
			PWCHAR pGame = g_pInjectProcs;
			pName++;
			while (*pGame)
			{
				if (wcscmp(pGame, pName) == 0)
				{
					bRet = TRUE;
					break;
				}
				while (*pGame++);
			}
		}
	}
	return bRet;
}

static VOID Process_NotifyProcess(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE hProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);
    if (KeGetCurrentIrql() > APC_LEVEL)
        return;
	do
	{
		if (NULL == g_pInjectProcs)
			break;

		if (!CreateInfo) {
			RemoveProcessId(hProcessId);
			break;
		}

		WCHAR path[MAX_PROCESS_PATH_LEN] = { 0, };
		if (!QueryProcessNamePath((DWORD)hProcessId, path, sizeof(path)))
			break;

		_wcsupr(path);
		if (!IsInjectProcess(path))
			break;

		// send inject process to r3 handle
		PPROC_ENTRY pProcEntry = (PPROC_ENTRY)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(PROC_ENTRY), MEM_TAG_PROCESS);
		if (pProcEntry)
		{
			KIRQL irql;
			pProcEntry->pid = hProcessId;
			KeAcquireSpinLock(&g_procListLock, &irql);
			InsertHeadList(&g_procListHead, &pProcEntry->lEntry);
			KeReleaseSpinLock(&g_procListLock, irql);
		}

	} while (FALSE);
}

OB_PREOP_CALLBACK_STATUS PreOperationCallback(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION PreInfo)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	if (KeGetCurrentIrql() > APC_LEVEL)
		return OB_PREOP_SUCCESS;

	// PROCESS_TERMINATE
	const ACCESS_MASK AccessBitsToClear = 0x0001;
	do
	{
		// process type 
		if (PreInfo->ObjectType != *PsProcessType)
			break;
		// get object
		PEPROCESS process = (PEPROCESS)PreInfo->Object;
		if (!process)
			break;
		// get pid
		const int iProcessId = (int)PsGetProcessId(process);
		// get processName
		//const PUCHAR processName = PsGetProcessImageFileName(process);
		//if (_stricmp((char*)processName, "PPSpeedUp.exe") != 0) {
		//	return OB_PREOP_SUCCESS;
		//}
		// authorization system process
		if (iProcessId < 1000)
			break;
		// block access process
		if (iProcessId == g_nProtectPid)
		{
			if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
				PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~AccessBitsToClear;
			}
			if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
				PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~AccessBitsToClear;
			}
		}
	} while (FALSE);
	return OB_PREOP_SUCCESS;
}

void ProcessInit(const PDRIVER_OBJECT pDriverObject) {
	InitializeListHead(&g_procListHead);
	KeInitializeSpinLock(&g_procListLock);

	ProcessNotifyRoutine_Init();
	ProcessProtect_Init(pDriverObject);
}

void ProcessUnInit() {
	KIRQL irql;
	PLIST_ENTRY pHead = NULL, pt = NULL;
	KeAcquireSpinLock(&g_procListLock, &irql);
	pHead = &g_procListHead;
	while (!IsListEmpty(pHead))
	{
		PPROC_ENTRY pEntry = NULL;
		pt = RemoveHeadList(pHead);
		if (pt == pHead)
			break;
		pEntry = CONTAINING_RECORD(pt, PROC_ENTRY, lEntry);
		if (pEntry)
			ExFreePool(pEntry);
	}
	KeReleaseSpinLock(&g_procListLock, irql);

	ProcessNotifyRoutine_UnInit();
	ProcessProtect_UnInit();
}

NTSTATUS ProcessNotifyRoutine_Init() {
	// See: Available starting with Windows Vista with SP1 and Windows Server 2008.
	// Msdn: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
	if (NT_SUCCESS(STATUS_SUCCESS) == PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)Process_NotifyProcess, FALSE))
		g_bInitNotify = 1;
	return STATUS_SUCCESS;
}

NTSTATUS ProcessNotifyRoutine_UnInit() {
	if (g_bInitNotify)
		return PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)Process_NotifyProcess, TRUE);
	return STATUS_SUCCESS;
}

NTSTATUS ProcessProtect_Init(const PDRIVER_OBJECT pDriverObject) {
	// return
	return STATUS_SUCCESS;

	PLDR_DATA_TABLE_ENTRY64 ldr = NULL;
	ldr = (PLDR_DATA_TABLE_ENTRY64)pDriverObject->DriverSection;
	ldr->Flags |= 0x20;

	// Set type callout
	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;
	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"321000");

	memset(&opReg, 0, sizeof(opReg));
	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&PreOperationCallback;
	obReg.OperationRegistration = &opReg;

	// See: Available starting with Windows Vista with Service Pack 1 (SP1) and Windows Server 2008.
	// Msdn: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks
	return ObRegisterCallbacks(&obReg, &g_pObHandle);
}

NTSTATUS ProcessProtect_UnInit(void)
{
	if (g_pObHandle)
	{
		ObUnRegisterCallbacks(g_pObHandle);
		g_pObHandle = NULL;
	}
	return STATUS_SUCCESS;
}

NTSTATUS ProcessProtect_SetProcPid(const int hPid)
{
	g_nProtectPid = hPid;
	return STATUS_SUCCESS;
}
