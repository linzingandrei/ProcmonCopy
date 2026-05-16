#pragma once
#include "main.h"
//#include "DbgEng.h"

typedef struct _MY_NETWORK_CONTEXT
{
    UINT32 localIpv4;
    BYTE localIpv6[16];
    UINT16 localPort;
    UINT32 remoteIpv4;
    BYTE remoteIpv6[16];
    UINT16 remotePort;
    UINT8 protocol;
    UINT8 icmpType;
    UNICODE_STRING appPathString;
    UINT32 remoteAddressType;
    UINT32 localAddressType;
    BOOLEAN ok;
} MY_NETWORK_CONTEXT, * PMY_NETWORK_CONTEXT;

VOID
NetworkFilterUnitialize(
);

NTSTATUS
NetworkFilterInitialize(
    _In_ PDRIVER_OBJECT DriverObject
);