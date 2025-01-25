#pragma once

#include <winsock2.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include "FileDetailReader.h"

using namespace std;

class PCInfoTool
{
public:
	static bool GetPCName(string& strPCName);
	static bool GetMacByGetAdaptersInfo(std::string& macOUT);		//通过GetAdaptersInfo获取，适用于Windows 2000及以上版本
	static bool GetMacByGetAdaptersAddresses(std::string& macOUT);	//通过GetAdaptersAddresses获取，适用于Windows XP及以上版本
};

