#pragma once
#ifndef __MAIN_H
#define __MAIN_H

#include "driver.h"

VOID DriverUnload(WDFDRIVER WdfDriver);

NTSTATUS InitWdfObjects(
	IN PDRIVER_OBJECT DrvObj,
	IN PUNICODE_STRING RegistryPath,
	OUT WDFDRIVER* OutWdfDriver,
	OUT WDFDEVICE* OutWdfDevice);

#endif
