#include "pch.h"
#include "HlprMiniCom.h"
#include "lowlevel_inject.h"

#include <fltuser.h>

static HANDLE g_hPort = INVALID_HANDLE_VALUE;
static BOOL   g_InitPortStatus = FALSE;

#define HADES_READ_BUFFER_SIZE  4096

typedef struct _HADES_NOTIFICATION {

	ULONG CommandId;
	ULONG Reserved;
	UCHAR Contents[HADES_READ_BUFFER_SIZE];
} HADES_NOTIFICATION, * PHADES_NOTIFICATION;

typedef struct _HADES_REPLY {
	DWORD SafeToOpen;
} HADES_REPLY, * PHADES_REPLY;

typedef struct _COMAND_MESSAGE
{
	FILTER_MESSAGE_HEADER MessageHeader;
	HADES_NOTIFICATION Notification;
	OVERLAPPED Overlapped;
} COMMAND_MESSAGE, * PCOMMAND_MESSAGE;

typedef struct _REPLY_MESSAGE
{
	FILTER_REPLY_HEADER ReplyHeader;
	HADES_REPLY Reply;
} REPLY_MESSAGE, * PREPLY_MESSAGE;

static DWORD WINAPI ThreadMiniPortConnectNotify(LPVOID pData)
{
	(reinterpret_cast<HlprMiniPortIpc*>(pData))->StartMiniPortWaitConnectWork();
	return 0;
}

static DWORD WINAPI ThreadMiniPortGetMsgNotify(LPVOID pData)
{
	(reinterpret_cast<HlprMiniPortIpc*>(pData))->GetMsgNotifyWork();
	return 0;
}

HlprMiniPortIpc::HlprMiniPortIpc()
{
}

HlprMiniPortIpc::~HlprMiniPortIpc()
{
	g_InitPortStatus = FALSE;
	if (g_hPort && g_hPort != INVALID_HANDLE_VALUE)
		CloseHandle(g_hPort);
	g_hPort = INVALID_HANDLE_VALUE;
}

void HlprMiniPortIpc::MiniPortInit(const std::wstring& sPortName) {
	m_MiniPortName = sPortName.c_str();

	DWORD threadid = 0;
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadMiniPortConnectNotify, this, 0, &threadid);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadMiniPortGetMsgNotify, this, 0, &threadid);
}

bool HlprMiniPortIpc::SetRuleProcess(PVOID64 rulebuffer, unsigned int buflen, unsigned int processnamelen) {
	UNREFERENCED_PARAMETER(processnamelen);

	if (FALSE == g_InitPortStatus)
		return false;

	DWORD bytesReturned = 0;
	unsigned int total = sizeof(COMMAND_MESSAGE) + buflen + 1;
	auto inputBuffer = VirtualAlloc(NULL, total, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!inputBuffer)
		return false;

	COMMAND_MESSAGE commandMessage = {};
	memcpy(inputBuffer, &commandMessage, sizeof(COMMAND_MESSAGE));
	memcpy((void*)((DWORD64)inputBuffer + sizeof(COMMAND_MESSAGE)), rulebuffer, buflen);

	bool ok = false;
	if (g_hPort && g_hPort != INVALID_HANDLE_VALUE) {
		ok = (FilterSendMessage(g_hPort, inputBuffer, total, NULL, NULL, &bytesReturned) == S_OK);
	}

	VirtualFree(inputBuffer, 0, MEM_RELEASE);
	return ok;
}

void HlprMiniPortIpc::StartMiniPortWaitConnectWork()
{
	HRESULT hrResult = 0;
	g_hPort = INVALID_HANDLE_VALUE;

	int counter = 0;
	do {
		hrResult = FilterConnectCommunicationPort(
			m_MiniPortName.c_str(),
			0,
			NULL,
			0,
			NULL,
			&g_hPort);
		if (hrResult == HRESULT_FROM_WIN32(S_OK))
		{
			g_InitPortStatus = true;
			std::wcout << (L"[+] connect sysmondriver miniport success. name " + m_MiniPortName).c_str() << std::endl;
			break;
		}

		if (++counter > 3)
			break;
		std::wcout << (L"[-] open miniport error. name " + m_MiniPortName + L" code " + std::to_wstring(hrResult)).c_str() << std::endl;
		Sleep(2000);
	} while (TRUE);
}

void HlprMiniPortIpc::GetMsgNotifyWork()
{
	REPLY_MESSAGE replyMessage = {};

	do {
		if (g_InitPortStatus && (g_hPort != INVALID_HANDLE_VALUE))
			break;

		std::cout << "[-] wait init connect mini port. " << std::endl;
		Sleep(2000);
	} while (TRUE);

	do {
		COMMAND_MESSAGE message = {};
		HRESULT result = FilterGetMessage(
			g_hPort,
			&message.MessageHeader,
			FIELD_OFFSET(COMMAND_MESSAGE, Overlapped),
			nullptr
		);
		if (result != S_OK) {
			std::cout << ("[-] FilterGetMessage miniPort Error " + std::to_string(result)).c_str() << std::endl;
			if (g_hPort == INVALID_HANDLE_VALUE)
				break;
			Sleep(500);
			continue;
		}

		replyMessage = {};
		replyMessage.Reply.SafeToOpen = ERROR_CALL_NOT_IMPLEMENTED;

		PHADES_NOTIFICATION notification = &message.Notification;
		if (notification) {
			switch (notification->CommandId)
			{
			case MIN_COMMAND::IPS_PROCESSSTART:
			{
				const PROCESSINFO* processinfo = (PROCESSINFO*)notification->Contents;
				if (processinfo) {
					std::wstring command = processinfo->queryprocesspath;
					std::wcout << (L"process inject start path " + command + L" pid " + std::to_wstring(processinfo->pid)).c_str() << std::endl;

					InjectExecResult injectResult = {};
					if (LowLevelInjectProcess((DWORD)processinfo->pid, processinfo->create_time, command, &injectResult)) {
						replyMessage.Reply.SafeToOpen = 0;
						std::wcout << (L"[+] inject success pid " + std::to_wstring(processinfo->pid)).c_str() << std::endl;
					}
					else {
						replyMessage.Reply.SafeToOpen = injectResult.errlvl ? injectResult.errlvl :
							(injectResult.last_error ? injectResult.last_error : ERROR_GEN_FAILURE);
						std::wcout << (L"[-] inject failed pid " + std::to_wstring(processinfo->pid) +
							L" errlvl " + std::to_wstring(injectResult.errlvl) +
							L" last " + std::to_wstring(injectResult.last_error)).c_str() << std::endl;
					}
				}
			}
			break;
			case MIN_COMMAND::IPS_PROCESSINJECT:
				replyMessage.Reply.SafeToOpen = 0;
				break;
			case MIN_COMMAND::IPS_IMAGEDLL:
				replyMessage.Reply.SafeToOpen = 0;
				break;
			default:
				break;
			}
		}

		replyMessage.ReplyHeader.Status = 0;
		replyMessage.ReplyHeader.MessageId = message.MessageHeader.MessageId;
		result = FilterReplyMessage(
			g_hPort,
			(PFILTER_REPLY_HEADER)&replyMessage,
			sizeof(replyMessage)
		);
		if (result != S_OK)
			break;
	} while (TRUE);
}
