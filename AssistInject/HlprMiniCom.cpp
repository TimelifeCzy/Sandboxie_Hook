#include "pch.h"
#include "HlprMiniCom.h"
#include <fltuser.h>
#include <memory>

#define NOTIFICATION_KEY ((ULONG_PTR)-1)

static HANDLE g_hPort = INVALID_HANDLE_VALUE;
static HANDLE g_comPletion = INVALID_HANDLE_VALUE;
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

// GetMsg
typedef struct _COMAND_MESSAGE
{
	FILTER_MESSAGE_HEADER MessageHeader;
	HADES_NOTIFICATION Notification;
	OVERLAPPED Overlapped;
} COMMAND_MESSAGE, * PCOMMAND_MESSAGE;

// Reply
typedef struct _REPLY_MESSAGE
{
	FILTER_REPLY_HEADER ReplyHeader;
	HADES_REPLY			Reply;
}REPLY_MESSAGE, * PREPLY_MESSAGE;

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
	if (g_hPort)
		CloseHandle(g_hPort);
	if (g_comPletion)
		CloseHandle(g_comPletion);
	g_hPort = nullptr;
	g_comPletion = nullptr;
}

void HlprMiniPortIpc::MiniPortInit(const std::wstring& sPortName) {
	m_MiniPortName = sPortName.c_str();

	DWORD threadid = 0;
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadMiniPortConnectNotify, this, 0, &threadid);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadMiniPortGetMsgNotify, this, 0, &threadid);
}

bool HlprMiniPortIpc::SetRuleProcess(PVOID64 rulebuffer, unsigned int buflen, unsigned int processnamelen) {
	if (FALSE == g_InitPortStatus)
		return false;
	
	DWORD bytesReturned = 0;
	DWORD hResult = 0;
	unsigned int total = sizeof(COMMAND_MESSAGE) + buflen + 1;
	auto InputBuffer = VirtualAlloc(NULL, total, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!InputBuffer)
		return false;

	COMMAND_MESSAGE command_message;
	memcpy(InputBuffer, &command_message, sizeof(COMMAND_MESSAGE));
	memcpy((void*)((DWORD64)InputBuffer + sizeof(COMMAND_MESSAGE)), rulebuffer, buflen);

	if (g_hPort)
	{
		hResult = FilterSendMessage(g_hPort, InputBuffer, total, NULL, NULL, &bytesReturned);
		if (InputBuffer)
			VirtualFree(InputBuffer, total, MEM_RESERVE);
		if (hResult != S_OK)
		{
			return hResult;
		}
	}

	return true;
}

void HlprMiniPortIpc::StartMiniPortWaitConnectWork()
{
	HRESULT hrRsult = 0;
	g_hPort = INVALID_HANDLE_VALUE;
	g_comPletion = INVALID_HANDLE_VALUE;

	int counter = 0;
	do {
		hrRsult = FilterConnectCommunicationPort(
			m_MiniPortName.c_str(),
			0,
			NULL,
			0,
			NULL,
			&g_hPort);
		if (hrRsult == HRESULT_FROM_WIN32(S_OK))
		{
			// 绑定IoComplet
			g_comPletion = CreateIoCompletionPort(g_hPort, NULL, 0, 4);
			if (nullptr == g_comPletion)
			{
				CloseHandle(g_hPort);
				g_hPort = nullptr;
				continue;
			}

			// 初始化先GetMsg, Notify线程等待处理  
			int iGetMessageCounter = 0;
			for (size_t i = 0; i < 4; ++i) 
			{
				std::shared_ptr<COMMAND_MESSAGE> pCommandMsg = std::make_shared<COMMAND_MESSAGE>();
				if (nullptr == pCommandMsg || (!pCommandMsg))
				{
					hrRsult = ERROR;
					break;
				}

				RtlSecureZeroMemory(&pCommandMsg->Overlapped, sizeof(OVERLAPPED));
				hrRsult = FilterGetMessage(
					g_hPort,
					&pCommandMsg->MessageHeader,
					FIELD_OFFSET(COMMAND_MESSAGE, Overlapped),
					&pCommandMsg->Overlapped
				);

				// Pending状态成功
				if (hrRsult != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
					break;

				iGetMessageCounter++;
			}

			if (!iGetMessageCounter) {
				CloseHandle(g_hPort);
				CloseHandle(g_comPletion);
				g_hPort = nullptr;
				g_comPletion = nullptr;
				g_InitPortStatus = false;
				return;
			}

			g_InitPortStatus = true;
			std::wcout << (L"[+] connect sysmondriver miniport success. name " + m_MiniPortName).c_str() << std::endl;
			break;
		}		
		else {
			if (++counter > 3)
				break;
			std::wcout << (L"[-] open miniport error. name " + m_MiniPortName + L" code " + std::to_wstring(hrRsult)).c_str() << std::endl;
			Sleep(2000);
		}
	} while (TRUE);
}

void HlprMiniPortIpc::GetMsgNotifyWork()
{
	DWORD outSize = 0;
	ULONG_PTR key = 0;
	BOOL nRet = FALSE;
	LPOVERLAPPED pOvlp = nullptr;
	HRESULT result = FALSE;
	PCOMMAND_MESSAGE message = nullptr;
	REPLY_MESSAGE replyMessage;
	PHADES_NOTIFICATION notification = nullptr;
	RtlSecureZeroMemory(&replyMessage, sizeof(REPLY_MESSAGE));

	// Waiting Connect Driver MiniPort_Server - Modify EventWaiting
	do {
		if (g_InitPortStatus && (nullptr != g_hPort) && (nullptr != g_comPletion))
			break;
		else {
			std::cout << "[-] wait init connect mini port. " << std::endl;
			Sleep(2000);
		}
	} while (1);

	// Recv While Driver Send to Client Msg_Handler
	DWORD error_code = 0;
	do {
		if (g_comPletion)
			nRet = GetQueuedCompletionStatus(g_comPletion, &outSize, &key, &pOvlp, INFINITE);
		if (FALSE == nRet) {
			std::cout << ("[-] GetQueuedCompletionStatus miniPort Error " + std::to_string(nRet)).c_str() << std::endl;
			if (!g_comPletion)
				break;
			continue;
		}
		else if (!pOvlp || (key == NOTIFICATION_KEY))
			continue;

		message = CONTAINING_RECORD(pOvlp, COMMAND_MESSAGE, Overlapped);
		do
		{
			if (!message)
				break;
			notification = &message->Notification;
			if (!notification)
				break;

			replyMessage.Reply.SafeToOpen = 2;
			switch (notification->CommandId)
			{
			case MIN_COMMAND::IPS_PROCESSSTART:
			{
				const PROCESSINFO* processinfo = (PROCESSINFO*)notification->Contents;
				if (processinfo) {
					std::wstring sCommand = processinfo->queryprocesspath;
					std::wcout << (L"process inject start path " + sCommand).c_str() << std::endl;
				}
			}
			break;
			case MIN_COMMAND::IPS_PROCESSINJECT:
			{

			}
			break;
			case MIN_COMMAND::IPS_IMAGEDLL: 
				break;
			}
		} while (false);

		if (!g_hPort)
			break;
		replyMessage.ReplyHeader.Status = 0;
		replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;
		result = FilterReplyMessage(
			g_hPort,
			(PFILTER_REPLY_HEADER)&replyMessage,
			sizeof(replyMessage)
		);
		//if (S_OK != result)
		//{
		//	break;
		//}
		memset(&message->Overlapped, 0, sizeof(OVERLAPPED));
		result = FilterGetMessage(
			g_hPort,
			&message->MessageHeader,
			FIELD_OFFSET(COMMAND_MESSAGE, Overlapped),
			&message->Overlapped
		);
		if (result != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
			break;
#pragma warning(push)
#pragma warning(disable:4127)
	} while (TRUE);
#pragma warning(pop)
}