#pragma once
#include "main.h"

VOID
NetworkFilterUnitialize(
);

NTSTATUS
NetworkFilterInitialize(
    _In_ PDRIVER_OBJECT DriverObject
);