#include "driver.h"
#include "main.h"
#include "leafnet.h"

#define LEAF_DEVICE_NAME		L"\\Device\\Leaf_NetFilter"
#define LEAF_SYM_NAME			L"\\??\\Leaf_NetFilter"


NTSTATUS DriverEntry(PDRIVER_OBJECT DrvObj, PUNICODE_STRING RegistryPath) {
	NTSTATUS status = STATUS_SUCCESS;

	WDFDRIVER WdfDriver;
	WDFDEVICE WdfDevice;

	BOOLEAN IsLeafInit = FALSE;
	
	status = InitWdfObjects(DrvObj, RegistryPath, &WdfDriver, &WdfDevice);
	if (!NT_SUCCESS(status)) {
		goto end0;
	}
	
	status = LeafNetInit(WdfDevice);
	if (!NT_SUCCESS(status)) {
		goto end0;
	}
	IsLeafInit = TRUE;
	

end0:
	if (!NT_SUCCESS(status)) {
		if (IsLeafInit) {
			LeafNetDestroy();
		}
	}
	return status;
}

VOID DriverUnload(WDFDRIVER WdfDriver) {
	UNREFERENCED_PARAMETER(WdfDriver);
	LeafNetDestroy();
}

NTSTATUS InitWdfObjects(
	IN PDRIVER_OBJECT DrvObj,
	IN PUNICODE_STRING RegistryPath,
	OUT WDFDRIVER* OutWdfDriver,
	OUT WDFDEVICE* OutWdfDevice)
{
	NTSTATUS status = STATUS_SUCCESS;

	WDFDRIVER WdfDriver;
	WDFDEVICE WdfDevice;

	WDF_DRIVER_CONFIG WdfDriverConf;

	PWDFDEVICE_INIT pWdfDeviceInit = NULL;

	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(LEAF_DEVICE_NAME);
	UNICODE_STRING SymName = RTL_CONSTANT_STRING(LEAF_SYM_NAME);


	WDF_DRIVER_CONFIG_INIT(&WdfDriverConf, WDF_NO_EVENT_CALLBACK);
	WdfDriverConf.DriverInitFlags |= WdfDriverInitNonPnpDriver;
	WdfDriverConf.EvtDriverUnload = DriverUnload;

	status = WdfDriverCreate(DrvObj,
		RegistryPath, 
		WDF_NO_OBJECT_ATTRIBUTES,
		&WdfDriverConf,
		&WdfDriver);

	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wdf drvier create failed, status = 0x%x\n", status));
		goto end0;
	}

	pWdfDeviceInit = WdfControlDeviceInitAllocate(WdfDriver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
	if (!pWdfDeviceInit) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto end0;
	}

	WdfDeviceInitSetDeviceType(pWdfDeviceInit, FILE_DEVICE_NETWORK);
	WdfDeviceInitSetCharacteristics(pWdfDeviceInit, FILE_DEVICE_SECURE_OPEN, FALSE);

	status = WdfDeviceInitAssignName(pWdfDeviceInit, &DeviceName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wdf device assign name, status = 0x%x\n", status));
		goto end0;
	}

	WdfDeviceInitSetDeviceClass(pWdfDeviceInit, &GUID_DEVCLASS_NET);

	status = WdfDeviceCreate(&pWdfDeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &WdfDevice);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] Wdf device create failed, status = 0x%x\n", status));
		goto end0;
	}

	status = WdfDeviceCreateSymbolicLink(WdfDevice, &SymName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[LeafNet] symbolic link create failed, status: 0x%08X\n", status));
		goto end0;
	}


	/*
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig,
                                    WdfIoQueueDispatchSequential);
    ioQueueConfig.EvtIoRead = FileEvtIoRead;
    ioQueueConfig.EvtIoWrite = FileEvtIoWrite;
    ioQueueConfig.EvtIoDeviceControl = FileEvtIoDeviceControl;
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    status = WdfIoQueueCreate(controlDevice,
                              &ioQueueConfig,
                              &attributes,
                              &queue // pointer to default queue
                              );
    if (!NT_SUCCESS(status)) {
        goto End;
    }
	*/

	WdfControlFinishInitializing(WdfDevice);

	*OutWdfDriver = WdfDriver;
	*OutWdfDevice = WdfDevice;

end0:
	if (pWdfDeviceInit) WdfDeviceInitFree(pWdfDeviceInit);
	return status;
}