#pragma once
#pragma warning (disable : 4201)

#define NDIS_SUPPORT_NDIS6 1
#define INITGUID

#include <ntifs.h>
#include <wdm.h>
#include "ntstrsafe.h"
#include "fltKernel.h"

#include <ndis.h>

#include <fwpsk.h>
#include <guiddef.h>
#include <fwpmk.h>
#include "ipmib.h"

#include <ip2string.h>

#include "networking.h"
#include "threadpool.h"


extern UNICODE_STRING gAltitude;
extern LARGE_INTEGER gRegistryCookie;

extern PFLT_FILTER gFilterRegistration;
extern PFLT_PORT gServerPort;
extern PFLT_PORT gClientPort;
extern PDRIVER_OBJECT gDriverObject;

extern KSPIN_LOCK gClientPortLock;

extern BOOLEAN gProcessMonitoringEnabled;
extern BOOLEAN gImageMonitoringEnabled;
extern BOOLEAN gThreadMonitoringEnabled;
extern BOOLEAN gRegistryMonitoringEnabled;
extern BOOLEAN gFileMonitoringEnabled;

extern DRIVER_INITIALIZE DriverEntry;

typedef struct _REPLY_DATA
{
    WCHAR message[1024];
    ULONG messageLength;
} REPLY_DATA, * PREPLY_DATA;

typedef struct _MY_CUSTOM_MESSAGE
{
    FILTER_MESSAGE_HEADER headers;
    REPLY_DATA replyData;

} MY_CUSTOM_MESSAGE, * PMY_CUSTOM_MESSAGE;

extern BOOLEAN hasBeenInitialized;

typedef struct _MY_CONTEXT
{
    KSPIN_LOCK ContextLock;
    UINT32 Number;
} MY_CONTEXT;

typedef struct _MY_THREADPOOL {
    MY_THREAD_POOL tp;
    MY_CONTEXT ctx;

    int numberOfThreadPools;
} MY_THREADPOOL, * PMY_THREADPOOL;

extern PMY_THREADPOOL gThreadPool;

VOID SendWorker(
    PVOID ctx
);