#include "public.h"
#include "process.h"

NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);

// protect init
static int g_nProtectPid = 0;
static PVOID g_pObHandle = NULL;

// callback init
static int g_bInitNotify = 0;

static VOID Process_NotifyProcessEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(CreateInfo);
    if (KeGetCurrentIrql() > APC_LEVEL)
        return;

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
	ProcessNotifyRoutine_Init();
	ProcessProtect_Init(pDriverObject);
}

void ProcessUnInit() {
	ProcessNotifyRoutine_UnInit();
	ProcessProtect_UnInit();
}

NTSTATUS ProcessNotifyRoutine_Init() {
	// See: Available starting with Windows Vista with SP1 and Windows Server 2008.
	// Msdn: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
	if (NT_SUCCESS(STATUS_SUCCESS) == PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)Process_NotifyProcessEx, FALSE))
		g_bInitNotify = 1;
	return STATUS_SUCCESS;
}

NTSTATUS ProcessNotifyRoutine_UnInit() {
	if (g_bInitNotify)
		return PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)Process_NotifyProcessEx, TRUE);
	return STATUS_SUCCESS;
}

NTSTATUS ProcessProtect_SetProcPid(const int hPid)
{
	g_nProtectPid = hPid;
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