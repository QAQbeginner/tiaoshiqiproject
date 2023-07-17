#include"plug.h"
#include <stdio.h>
#include <windows.h>
#include <list>

// Ӧ�ó���汾
#define APP_VERSION 1

using std::list;

// �����Ϣ
typedef  struct _PLUGIN_INFO {
	HMODULE hModule;				// ���ģ���������������
	CHAR szName[MAX_PATH];			// ��������ַ���
	CHAR szVersionName[MAX_PATH];	// ����汾�ַ���	
	WORD dwVesrion;					// ������汾
}PLUGIN_INFO;

// ��������ȫ������
list<PLUGIN_INFO> g_plugins;

// �����ʼ������
// ����ֵ��ʾ��������Ƿ�ɹ�
// ����1��Ӧ�ó���İ汾
// ����2�����������
// ����3������汾������
typedef bool (*INIT_PLUGIN)(WORD, CHAR*, CHAR*);

// ���ڴ���ʱ���õĺ���
// ����1����������
typedef void (*CREATE_PLUGIN)(CHAR* WindowName);

// ��������ʱ���õĺ���
typedef void (*CLOSE_PLUGIN)();

// �����˳�ʱ���õĺ���
typedef void (*EXIT_PLUGIN)();

// 1. �ҵ�ָ��Ŀ¼(.plugin)�²��
// 2. ����ָ���ļ�  .pb51
// 3. �Ƿ񵼳�ָ������ OnInit_Plugin
// 4. ������汾
// 5. ��������Ϣ
// 6. �ڳ������в�ͬʱ�̵��ò������

// �����ʼ
void OnInit()
{
	// ������ǰĿ¼��plugin�º�׺��Ϊ.pb51    .\\plugin\\*.pb51   ..\\Debug\\dbgtarget.exe
	WIN32_FIND_DATAA data;
	HANDLE hFile = FindFirstFileA("..\\Debug\\plugin\\*.pb51", &data);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		do {
			// �ϲ�����·��
			char path[MAX_PATH] = {};
			sprintf_s(path, ".\\plugin\\%s", data.cFileName);
			// �������ģ��
			HMODULE hmod = LoadLibraryA(path);
			if (hmod != NULL)
			{
				// ��ȡָ������
				INIT_PLUGIN PInitFun = (INIT_PLUGIN)GetProcAddress(hmod, "OnInit_Plugin");
				if (PInitFun != NULL)
				{
					PLUGIN_INFO info;
					// ���������Ƿ���سɹ�
					if (PInitFun(APP_VERSION, info.szName, info.szVersionName))
					{
						// ���浽����б���
						info.dwVesrion = APP_VERSION;
						info.hModule = hmod;
						g_plugins.push_back(info);
						continue;
					}
				}
				FreeLibrary(hmod);
			}
			// ������һ���ļ�
		} while (FindNextFileA(hFile, &data));
	}
}
// ���ڴ���
void OnCreate()
{
	//�������в�������ò����ָ���ĺ���
	for (auto& info : g_plugins)
	{
		// ��ȡָ������
		auto pCreateFun = (CREATE_PLUGIN)GetProcAddress(info.hModule, "OnCreate_Plugin");
		if (pCreateFun != NULL)
		{
			// ����ָ������
			pCreateFun((char*)"������Գ���");
		}
	}

}
// ���ڹر�
void OnClose()
{
	//�������в�������ò����ָ���ĺ���
	for (auto& info : g_plugins)
	{
		// ��ȡָ������
		auto pFun = (CLOSE_PLUGIN)GetProcAddress(info.hModule, "OnClose_Plugin");
		if (pFun != NULL)
		{
			// ����ָ������
			pFun();
		}
	}
}
// �����˳�
void OnExit()
{
	//�������в�������ò����ָ���ĺ���
	for (auto& info : g_plugins)
	{
		// ��ȡָ������
		auto pFun = (EXIT_PLUGIN)GetProcAddress(info.hModule, "OnEixt_Plugin");
		if (pFun != NULL)
		{
			// ����ָ������
			pFun();
		}
		// �ͷ����в��
		FreeLibrary(info.hModule);
	}
	// ɾ��list
	g_plugins.clear();

}
// ������
void PlugHandle()
{
	OnInit();
	OnCreate();
	OnClose();
	OnExit();
}