#include "pch.h"
#include "low/lowdata.h"
#include "HlprMiniCom.h"

#include <iostream>
#include <algorithm>

const int WriteIoctProcess (const int code, std::string sData)
{
	if (!g_hDevice || (INVALID_HANDLE_VALUE == g_hDevice))
		return 1;
	
	const std::wstring sProcessList = CodeTool::Str2WStr(sData).c_str();
	if (sProcessList.empty())
		return 2;

	DWORD dwBytesReturned = 0;
	if (DeviceIoControl(
		g_hDevice,
		code,
		(LPVOID)sProcessList.c_str(),
		(sData.size() + 1) * sizeof(WCHAR),
		NULL, 0,
		&dwBytesReturned, NULL)) {
		std::cout << ("[+] write driver inject process succes. " + sData).c_str() << std::endl;
		return 0;
	}

	std::cout << ("[+] write driver inject process err. code " + std::to_string(GetLastError())).c_str() << std::endl;
	return 2;
}

void CloseHandleDevice() {
	if (g_hDevice) {
		CloseHandle(g_hDevice);
		g_hDevice = nullptr;
	}
}

const int OpenHandleDevice(const std::string& sDevSylinkName) {
	if (sDevSylinkName.empty())
		return 1;

	// Open Driver
	g_hDevice = CreateFileA(
		sDevSylinkName.c_str(),
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (g_hDevice == INVALID_HANDLE_VALUE)
		return GetLastError();
	return 0;
}

const bool ConfigProcessParsing(std::string& strProcessNameList)
{
	std::string sPath = "";
	CodeTool::CGetCurrentDirectory(sPath);
	if (sPath.empty())
		return false;
	sPath.append("Assistcfg.json");

	const HANDLE FileHandle = CreateFileA(
		sPath.c_str(),
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (!FileHandle || (INVALID_HANDLE_VALUE == FileHandle))
		return false;

	DWORD lpFileSizeHigh = 0;
	const DWORD dwFileSize = GetFileSize(FileHandle, &lpFileSizeHigh) + 1;
	char* const data = new char[dwFileSize];
	if (data)
		RtlSecureZeroMemory(data, dwFileSize);
	else
	{
		CloseHandle(FileHandle);
		return false;
	}

	bool nRet = false;
	do {
		DWORD dwRead = 0;
		if (!ReadFile(FileHandle, data, dwFileSize, &dwRead, NULL))
			break;
		rapidjson::Document document;
		document.Parse<0>(data);
		if (document.HasParseError())
			break;
		if (!document.HasMember("processName"))
			break;
		strProcessNameList = document["processName"].GetString();
		nRet = true;
	} while (false);

	if (FileHandle)
		CloseHandle(FileHandle);
	if (data)
		delete[] data;
	return nRet;
}

int main()
{
	// read inject process name list
	std::string sProcessList = "";
	ConfigProcessParsing(sProcessList);
	if (sProcessList.empty()) {
		std::cout << "[-] get process json err." << std::endl;
		system("pause");
		return 0;
	}
	sProcessList.append("||");
	std::string sProcessListTou = "";
	std::transform(sProcessList.begin(), sProcessList.end(), back_inserter(sProcessListTou), ::toupper);
	std::cout << "[+] get process json success." << sProcessListTou.c_str() << std::endl;

    // init sbie dll inject
    //ULONG errlvl = SbieDll_InjectLow_InitHelper();
    //if (errlvl != 0) {
    //    return false;
    //}

    // open driver 
	const int code = OpenHandleDevice("\\??\\HadesBoxDevice");
	if (g_hDevice == INVALID_HANDLE_VALUE) {
		std::cout << "[-] open driver error. " << code << std::endl;
		system("pause");
		return 0;
	}
	std::cout << "[+] open driver success." << std::endl;

    // open miniport
	SingletonMiniPortIpc::instance()->MiniPortInit(L"\\HadesBoxMiniPort");

    // write driver inject processName List
	WriteIoctProcess(NF_REQ_SET_INJECT_PROCESS, sProcessListTou);

    // wait exit event
	g_hExit = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (g_hExit) {
		std::cout << "[+]  wait exit." << std::endl;
		WaitForSingleObject(g_hExit, INFINITE);
	}

	CloseHandleDevice();
	std::cout << "[+] process exit." << std::endl;
	system("pause");
	return 0;
}