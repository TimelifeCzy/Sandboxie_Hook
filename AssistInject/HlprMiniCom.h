#pragma once

class HlprMiniPortIpc
{
public:
	HlprMiniPortIpc();
	~HlprMiniPortIpc();

	void MiniPortInit(const std::wstring& sPortName);
	void GetMsgNotifyWork();
	void StartMiniPortWaitConnectWork();
	bool SetRuleProcess(PVOID64 rulebuffer, unsigned int buflen, unsigned int processnamelen);

private:
	std::wstring m_MiniPortName = L"";
};

using SingletonMiniPortIpc = ustdex::Singleton<HlprMiniPortIpc>;


