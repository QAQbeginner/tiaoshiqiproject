#include <stdio.h>
#include <windows.h>
#include <string.h>

#define PALUGIN_NAME "���ײ��"
#define PALUGIN_VERSION "1.1.1"

// dll�����Ҫ����ָ���ĺ�����
extern "C" _declspec(dllexport) bool OnInit_Plugin(WORD dwVersion, CHAR * plugin_name, CHAR * plugin_version)
{
	// Ӧ�ó���汾��һ��
	if (dwVersion != 1)
	{
		return false;
	}
	// �����������
	strcpy_s(plugin_name, MAX_PATH, PALUGIN_NAME);
	strcpy_s(plugin_version, MAX_PATH, PALUGIN_VERSION);
	return true;
}


extern "C" _declspec(dllexport)  void OnCreate_Plugin(CHAR * sWindowName)
{
	MessageBox(0, L"��������", 0, 0);
	printf("���ײ����%s\n", sWindowName);
}

extern "C" _declspec(dllexport) void OnClose_Plugin()
{
	printf("���ײ������������\n");
}

extern "C" _declspec(dllexport)void OnEixt_Plugin()
{
	printf("���ײ���������˳�\n");
}