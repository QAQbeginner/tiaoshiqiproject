#include <stdio.h>
#include <windows.h>
#include <string.h>

#define PALUGIN_NAME "简易插件"
#define PALUGIN_VERSION "1.1.1"

// dll插件需要导出指定的函数有
extern "C" _declspec(dllexport) bool OnInit_Plugin(WORD dwVersion, CHAR * plugin_name, CHAR * plugin_version)
{
	// 应用程序版本号一致
	if (dwVersion != 1)
	{
		return false;
	}
	// 拷贝插件名称
	strcpy_s(plugin_name, MAX_PATH, PALUGIN_NAME);
	strcpy_s(plugin_version, MAX_PATH, PALUGIN_VERSION);
	return true;
}


extern "C" _declspec(dllexport)  void OnCreate_Plugin(CHAR * sWindowName)
{
	MessageBox(0, L"诡术妖姬", 0, 0);
	printf("简易插件：%s\n", sWindowName);
}

extern "C" _declspec(dllexport) void OnClose_Plugin()
{
	printf("简易插件：窗口销毁\n");
}

extern "C" _declspec(dllexport)void OnEixt_Plugin()
{
	printf("简易插件：程序退出\n");
}