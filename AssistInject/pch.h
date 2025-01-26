#ifndef PCH_H
#define PCH_H

// 添加要在此处预编译的标头
#include "framework.h"

#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
#include <io.h>
#include <winioctl.h>

#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS
#include <atlbase.h>
#include <atlstr.h>

#include <iostream>
#include <string>
#include <thread>
#include <fstream>
#include <vector>
#include <map>
using namespace std;

#pragma comment(lib, "version")
#pragma comment(lib ,"Shlwapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "FltLib.lib")

#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <rapidjson/filereadstream.h>
#include <rapidjson/filewritestream.h>

#include "CodeTool.h"
#include "inlcude/SingletonHandler.h"

// exit event
static HANDLE g_hExit = INVALID_HANDLE_VALUE;
// device name
static HANDLE g_hDevice = INVALID_HANDLE_VALUE;

#define NF_REQ_SET_INJECT_PROCESS \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 101, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NF_REQ_SET_PROCESSPID \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 102, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

enum MIN_COMMAND
{
	IPS_PROCESSSTART = 1,
	IPS_PROCESSINJECT = 2,
	IPS_IMAGEDLL = 3,
};

typedef struct _PROCESSINFO
{
    int parentprocessid;
    int pid;
    int endprocess;
    wchar_t processpath[301 * 2];
    wchar_t commandLine[301 * 2];
    wchar_t queryprocesspath[301 * 2];
}PROCESSINFO, * PPROCESSINFO;

#endif //PCH_H
