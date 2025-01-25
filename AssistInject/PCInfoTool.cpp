#include "pch.h"
#include "PCInfoTool.h"

bool PCInfoTool::GetPCName(string& strPCName)
{
	char PCnameBuffer[128];    //获得本地计算机名

	WSAData data;              //初始化:如果不初始化，以下代码将无法执行
	if (WSAStartup(MAKEWORD(1, 1), &data) != 0)
	{
		return false;
	}
	else
	{
		if (0 == gethostname(PCnameBuffer, 128))
			strPCName = PCnameBuffer;
		else
			return false;
	}
	return true;
}

bool PCInfoTool::GetMacByGetAdaptersInfo(std::string& macOUT)
{
	bool ret = false;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL)
		return false;
	// Make an initial call to GetAdaptersInfo to get the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
		if (pAdapterInfo == NULL)
			return false;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR)
	{
		for (PIP_ADAPTER_INFO pAdapter = pAdapterInfo; pAdapter != NULL; pAdapter = pAdapter->Next)
		{
			// 确保是以太网
			if (pAdapter->Type != MIB_IF_TYPE_ETHERNET)
				continue;
			// 确保MAC地址的长度为 00-00-00-00-00-00
			if (pAdapter->AddressLength != 6)
				continue;
			char acMAC[32];
			sprintf_s(acMAC,
					  "%02X%02X%02X%02X%02X%02X",
					  int(pAdapter->Address[0]),
					  int(pAdapter->Address[1]),
					  int(pAdapter->Address[2]),
					  int(pAdapter->Address[3]),
					  int(pAdapter->Address[4]),
					  int(pAdapter->Address[5]));
			macOUT = acMAC;
			ret = true;
			break;
		}
	}

	free(pAdapterInfo);
	return ret;
}

bool PCInfoTool::GetMacByGetAdaptersAddresses(std::string& macOUT)
{
	bool ret = false;

	ULONG outBufLen = sizeof(IP_ADAPTER_ADDRESSES);
	PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
	if (pAddresses == NULL)
		return false;
	// Make an initial call to GetAdaptersAddresses to get the necessary size into the ulOutBufLen variable
	if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		free(pAddresses);
		pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
		if (pAddresses == NULL)
			return false;
	}

	if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen) == NO_ERROR)
	{
		// If successful, output some information from the data we received
		for (PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses; pCurrAddresses != NULL; pCurrAddresses = pCurrAddresses->Next)
		{
			// 确保MAC地址的长度为 00-00-00-00-00-00
			if (pCurrAddresses->PhysicalAddressLength != 6)
				continue;
			char acMAC[32];
			sprintf_s(acMAC,
					  "%02X%02X%02X%02X%02X%02X",
					  int(pCurrAddresses->PhysicalAddress[0]),
					  int(pCurrAddresses->PhysicalAddress[1]),
					  int(pCurrAddresses->PhysicalAddress[2]),
					  int(pCurrAddresses->PhysicalAddress[3]),
					  int(pCurrAddresses->PhysicalAddress[4]),
					  int(pCurrAddresses->PhysicalAddress[5]));
			macOUT = acMAC;
			ret = true;
			break;
		}
	}

	free(pAddresses);
	return ret;
}
