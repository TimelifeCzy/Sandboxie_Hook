#include "public.h"
#include "process.h"
#include <fltKernel.h>
#include <dontuse.h>
#include "minifilter.h"
#include "kflt.h"

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

static UNICODE_STRING g_devicename;
static UNICODE_STRING g_devicesyslink;
static PDEVICE_OBJECT g_deviceControl;

ULONG   gTraceFlags = 0;
#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

EXTERN_C_START
DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

VOID driverUnload(
    _In_ struct _DRIVER_OBJECT* DriverObject
);

EXTERN_C_END

//
//  Assign text sections for each routine.
//
#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, driverUnload)
#endif

VOID driverUnload(_In_ struct _DRIVER_OBJECT* DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    PAGED_CODE();
    
    Fsflt_freePort();
    FsMini_Free();
    ProcessUnInit();

    if (g_deviceControl)
    {
        IoDeleteDevice(g_deviceControl);
        g_deviceControl = NULL;
        IoDeleteSymbolicLink(&g_devicesyslink);
    }
    return;
}

NTSTATUS devctrl_close(PIRP irp, PIO_STACK_LOCATION irpSp) {
    UNREFERENCED_PARAMETER(irpSp);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS devctrl_dispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpSp;
    irpSp = IoGetCurrentIrpStackLocation(irp);
    ASSERT(irpSp);

    if (IRP_MJ_DEVICE_CONTROL == irpSp->MajorFunction) {
        switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
        {
        // 进程注入
        case NF_REQ_SET_INJECT_PROCESS:
            return SetInjectProcess(irp, irpSp);
        // 进程保护
        case NF_REQ_SET_PROCESSPID:
        {
            const PVOID inputBuffer = irp->AssociatedIrp.SystemBuffer;
            const ULONG inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
            if ((NULL == inputBuffer) || (inputBufferLength < sizeof(PPIDCMD)))
                break;
            const PPPIDCMD pCmdNode = (PPPIDCMD)inputBuffer;
            if (!pCmdNode)
                break;
            ProcessProtect_SetProcPid(pCmdNode->processId);
        }
        break;
        }
    }
    else if (IRP_MJ_CLOSE == irpSp->MajorFunction) {
        return devctrl_close(irp, irpSp);
    }

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS devctrl_default(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp)
{
    NTSTATUS 	status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(DeviceObject);

    irp->IoStatus.Information = 0;
    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS devctrl_ioInit(PDRIVER_OBJECT DriverObject) {
	NTSTATUS status = STATUS_SUCCESS;
	// Create Device
	RtlInitUnicodeString(&g_devicename, L"\\Device\\HadesBox");
	RtlInitUnicodeString(&g_devicesyslink, L"\\DosDevices\\HadesBoxDevice");
	status = IoCreateDevice(
		DriverObject,
		0,
		&g_devicename,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&g_deviceControl);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	g_deviceControl->Flags &= ~DO_DEVICE_INITIALIZING;

	status = IoCreateSymbolicLink(&g_devicesyslink, &g_devicename);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	g_deviceControl->Flags &= ~DO_DEVICE_INITIALIZING;
	g_deviceControl->Flags |= DO_DIRECT_IO;
	return status;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNREFERENCED_PARAMETER(RegistryPath);

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("driver!DriverEntry: Entered\n"));

    // Init MiniFilter
    status = FsMini_Init(DriverObject);
    if (!NT_SUCCESS(status))
        return status;
    status = Mini_StartFilter();
    if (!NT_SUCCESS(status))
        return status;
    status = Fsflt_initPort();
    if (!NT_SUCCESS(status))
    {
        FsMini_Free();
        return status;
    }

    int i = 0;
    for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
    {
        DriverObject->MajorFunction[i] = (PDRIVER_DISPATCH)devctrl_default;
    }
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)devctrl_dispatch;
    DriverObject->DriverUnload = driverUnload;

    // Init Event Handler
    status = devctrl_ioInit(DriverObject);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // Register Process
    ProcessInit(DriverObject);

    return STATUS_SUCCESS;
}