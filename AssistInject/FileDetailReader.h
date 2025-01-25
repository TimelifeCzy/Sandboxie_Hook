#pragma once

#include <string>

class FileDetailReader
{
public:
	static bool QueryValue(const std::string& ValueName, const std::string& szModuleName, std::string& RetStr);
	static bool GetFileDescription(const std::string& szModuleName, std::string& RetStr);	//��ȡ�ļ�˵��
	static bool GetFileVersion(const std::string& szModuleName, std::string& RetStr);		//��ȡ�ļ��汾	
	static bool GetInternalName(const std::string& szModuleName, std::string& RetStr);		//��ȡ�ڲ�����
	static bool GetCompanyName(const std::string& szModuleName, std::string& RetStr);		//��ȡ��˾����
	static bool GetLegalCopyright(const std::string& szModuleName, std::string& RetStr);	//��ȡ��Ȩ
	static bool GetOriginalFilename(const std::string& szModuleName, std::string& RetStr);	//��ȡԭʼ�ļ���
	static bool GetProductName(const std::string& szModuleName, std::string& RetStr);		//��ȡ��Ʒ����
	static bool GetProductVersion(const std::string& szModuleName, std::string& RetStr);	//��ȡ��Ʒ�汾
	static bool GetOEM(const std::string& szModuleName, std::string& RetStr);
};