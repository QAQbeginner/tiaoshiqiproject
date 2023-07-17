#include"plug.h"
#include <stdio.h>
#include <windows.h>
#include <list>

// 应用程序版本
#define APP_VERSION 1

using std::list;

// 插件信息
typedef  struct _PLUGIN_INFO {
	HMODULE hModule;				// 插件模块句柄，方便管理插件
	CHAR szName[MAX_PATH];			// 插件名称字符串
	CHAR szVersionName[MAX_PATH];	// 插件版本字符串	
	WORD dwVesrion;					// 主程序版本
}PLUGIN_INFO;

// 管理插件的全局链表
list<PLUGIN_INFO> g_plugins;

// 插件初始化函数
// 返回值表示插件加载是否成功
// 参数1：应用程序的版本
// 参数2：插件的名称
// 参数3：插件版本的名称
typedef bool (*INIT_PLUGIN)(WORD, CHAR*, CHAR*);

// 窗口创建时调用的函数
// 参数1：窗口名称
typedef void (*CREATE_PLUGIN)(CHAR* WindowName);

// 窗口销毁时调用的函数
typedef void (*CLOSE_PLUGIN)();

// 程序退出时调用的函数
typedef void (*EXIT_PLUGIN)();

// 1. 找到指定目录(.plugin)下插件
// 2. 过滤指定文件  .pb51
// 3. 是否导出指定函数 OnInit_Plugin
// 4. 检测插件版本
// 5. 保存插件信息
// 6. 在程序运行不同时刻调用插件功能

// 程序初始
void OnInit()
{
	// 遍历当前目录下plugin下后缀名为.pb51    .\\plugin\\*.pb51   ..\\Debug\\dbgtarget.exe
	WIN32_FIND_DATAA data;
	HANDLE hFile = FindFirstFileA("..\\Debug\\plugin\\*.pb51", &data);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		do {
			// 合并完整路径
			char path[MAX_PATH] = {};
			sprintf_s(path, ".\\plugin\\%s", data.cFileName);
			// 加载这个模块
			HMODULE hmod = LoadLibraryA(path);
			if (hmod != NULL)
			{
				// 获取指定函数
				INIT_PLUGIN PInitFun = (INIT_PLUGIN)GetProcAddress(hmod, "OnInit_Plugin");
				if (PInitFun != NULL)
				{
					PLUGIN_INFO info;
					// 检查插件插件是否加载成功
					if (PInitFun(APP_VERSION, info.szName, info.szVersionName))
					{
						// 保存到插件列表中
						info.dwVesrion = APP_VERSION;
						info.hModule = hmod;
						g_plugins.push_back(info);
						continue;
					}
				}
				FreeLibrary(hmod);
			}
			// 遍历下一个文件
		} while (FindNextFileA(hFile, &data));
	}
}
// 窗口创建
void OnCreate()
{
	//遍历所有插件，调用插件中指定的函数
	for (auto& info : g_plugins)
	{
		// 获取指定函数
		auto pCreateFun = (CREATE_PLUGIN)GetProcAddress(info.hModule, "OnCreate_Plugin");
		if (pCreateFun != NULL)
		{
			// 调用指定函数
			pCreateFun((char*)"插件测试程序");
		}
	}

}
// 窗口关闭
void OnClose()
{
	//遍历所有插件，调用插件中指定的函数
	for (auto& info : g_plugins)
	{
		// 获取指定函数
		auto pFun = (CLOSE_PLUGIN)GetProcAddress(info.hModule, "OnClose_Plugin");
		if (pFun != NULL)
		{
			// 调用指定函数
			pFun();
		}
	}
}
// 程序退出
void OnExit()
{
	//遍历所有插件，调用插件中指定的函数
	for (auto& info : g_plugins)
	{
		// 获取指定函数
		auto pFun = (EXIT_PLUGIN)GetProcAddress(info.hModule, "OnEixt_Plugin");
		if (pFun != NULL)
		{
			// 调用指定函数
			pFun();
		}
		// 释放所有插件
		FreeLibrary(info.hModule);
	}
	// 删除list
	g_plugins.clear();

}
// 程序处理
void PlugHandle()
{
	OnInit();
	OnCreate();
	OnClose();
	OnExit();
}