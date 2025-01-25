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
	static bool GetMacByGetAdaptersInfo(std::string& macOUT);		//ͨ��GetAdaptersInfo��ȡ��������Windows 2000�����ϰ汾
	static bool GetMacByGetAdaptersAddresses(std::string& macOUT);	//ͨ��GetAdaptersAddresses��ȡ��������Windows XP�����ϰ汾
};

