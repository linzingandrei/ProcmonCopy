#define CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "stdio.h"
#include "ws2tcpip.h"
#include "fwpmu.h"
#include "conio.h"
#include <vector>
#include <string>

#pragma comment(lib, "Fwpuclnt.lib")
#pragma comment(lib, "Ws2_32.lib")

using namespace std;


vector<wstring> GetIpsOfWebsite(WCHAR* nodeName)
{
    ADDRINFOW addrInfo = { 0 };
    ADDRINFOW* addrInfoRes = NULL;

    memset(&addrInfo, 0, sizeof(addrInfo));
    addrInfo.ai_family = AF_UNSPEC;
    int ret = GetAddrInfoW(nodeName, NULL, &addrInfo, &addrInfoRes);
    if (ret != 0) {
        printf("GetAddrInfoW failed with error: %d\n", ret);
        FreeAddrInfo(addrInfoRes);
    }
    else
    {
        WCHAR ipStr[NI_MAXHOST];
        vector<wstring> ipStrRes;
        //ipStrRes = (WCHAR*)malloc(NI_MAXHOST * sizeof(WCHAR));

        for (ADDRINFOW* ptr = addrInfoRes; ptr != NULL; ptr = ptr->ai_next) {
            ret = GetNameInfoW(ptr->ai_addr, (socklen_t)ptr->ai_addrlen, ipStr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (ret == 0)
            {
                //wprintf(L"IP Address: %ls\n", ipStr);

                ipStrRes.push_back(ipStr);
            }
        }

        // Only last ip, ignore others.
        //wcscpy_s(ipStrRes, NI_MAXHOST, ipStr);

        FreeAddrInfo(addrInfoRes);
        return ipStrRes;
    }
}

int main()
{
    WSAData wsa;
    int ret = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (ret != 0) {
        printf("WSAStartup failed with error: %d\n", ret);
        return 1;
    }

    WCHAR* nodeName = NULL;
    nodeName = (WCHAR*)malloc(1024 * sizeof(WCHAR));

    printf("Enter website name to block: ");
    scanf_s("%ls", nodeName, 1024);

    vector<wstring> ipStr = GetIpsOfWebsite(nodeName);

	//wprintf(L"IP Address to block: %ls\n", ipStr);

    for (auto el : ipStr)
    {
		wprintf(L"Ip: %ls\n", el.c_str());
    }
    //free(nodeName);

    WCHAR processName[512] = L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";

    FWPM_FILTER filter = { 0 };
    FWPM_FILTER_CONDITION *filterConditions = (FWPM_FILTER_CONDITION*)malloc(ipStr.size() * sizeof(FWPM_FILTER_CONDITION));
    FWP_BYTE_BLOB* pAppId = NULL;
    DWORD error = NULL;
    HANDLE hEngine;

    FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);

    if (processName != NULL)
    {
        error = FwpmGetAppIdFromFileName(processName, &pAppId);

        if (error != ERROR_SUCCESS)
        {
            printf("FwpmGetAppIdFromFileName failed with error: %d\n", error);
            free(filterConditions);
            free(processName);
            WSACleanup();
            return 1;
        }
    }

    if (pAppId)
    {
        wprintf(L"%.*s", (int)(pAppId->size / sizeof(WCHAR)), (WCHAR*)pAppId->data);
    }

    for (int i = 0; i < ipStr.size(); i++)
    {
        ZeroMemory(&filterConditions[i], sizeof(FWPM_FILTER_CONDITION));
    }
    filterConditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    filterConditions[0].matchType = FWP_MATCH_EQUAL;
    filterConditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
    filterConditions[0].conditionValue.byteBlob = pAppId;

    for (int i = 1; i < ipStr.size(); i++)
    {
        filterConditions[i].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        filterConditions[i].matchType = FWP_MATCH_EQUAL;

		wstring ip = ipStr[i];

        IN_ADDR ipv4;
        if (InetPtonW(AF_INET, ip.c_str(), &ipv4) == 1)
        {
            FWP_V4_ADDR_AND_MASK* ipAddrMask = (FWP_V4_ADDR_AND_MASK*)malloc(sizeof(FWP_V4_ADDR_AND_MASK));
            if (!ipAddrMask)
            {
                free(filterConditions);
                free(nodeName);
                WSACleanup();
                return 1;
			}

            ZeroMemory(ipAddrMask, sizeof(FWP_V4_ADDR_AND_MASK));

            ipAddrMask->addr = ipv4.S_un.S_addr;
            ipAddrMask->mask = 0xFFFFFFFF;

            filterConditions[i].conditionValue.type = FWP_V4_ADDR_MASK;
            filterConditions[i].conditionValue.v4AddrMask = ipAddrMask;
        }
        else
        {
            IN6_ADDR ipv6;
            if (InetPtonW(AF_INET6, ip.c_str(), &ipv6) == 1)
            {
                FWP_V6_ADDR_AND_MASK* ipAddrMask = (FWP_V6_ADDR_AND_MASK*)malloc(sizeof(FWP_V6_ADDR_AND_MASK));
                if (!ipAddrMask)
                {
                    free(filterConditions);
                    free(nodeName);
                    WSACleanup();
                    return 1;
                }

                ZeroMemory(ipAddrMask, sizeof(FWP_V6_ADDR_AND_MASK));

                memcpy(&ipAddrMask->addr, &ipv6, sizeof(IN6_ADDR));
                ipAddrMask->prefixLength = 128;

                filterConditions[i].conditionValue.type = FWP_V6_ADDR_MASK;
                filterConditions[i].conditionValue.v6AddrMask = ipAddrMask;
            }
        }
    }

    ZeroMemory(&filter, sizeof(FWPM_FILTER));
    filter.displayData.name = nodeName;
    filter.displayData.description = NULL;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = ipStr.size() + 1;
    filter.filterCondition = filterConditions;
    filter.action.type = FWP_ACTION_BLOCK;

    int res = FwpmFilterAdd(hEngine, &filter, NULL, NULL);
    if (res != ERROR_SUCCESS)
    {
        printf("FwpmFilterAdd failed with error: %d\n", res);
        free(filterConditions);
        free(nodeName);
        WSACleanup();
        return 1;
    }

	printf("Press ESC to stop blocking...\n");
    while (true)
    {
        if (_kbhit())
        {
            int c = _getch();

            if (c == 27)
            {
                break;
            }
        }
    }

    FwpmFilterDeleteById(hEngine, filter.filterId);

    FwpmEngineClose(hEngine);

    free(filterConditions);
    free(nodeName);

    WSACleanup();

    return 0;
}