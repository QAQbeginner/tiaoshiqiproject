#include"CDebug.h"
#include<iostream>
//..\\Debug\\dbgtarget.exe   反调试  条件断点和peb检测
#define TARGET_PATH (TCHAR*)L"..\\Debug\\inject.exe"
CHAR path[0x100];
#include"plug.h"
int main()
{
	// 调用插件
	PlugHandle();
	CDebug MyDebug;
	printf("请添加路径\n");
	int idex=0;
	scanf_s("%s", path, 0x100);
	printf("请输入进程打开方式：0：打开进程 1：附加进程\n");
	scanf_s("%d", &idex);
	if (idex == 0)
	{
		MyDebug.isAct = 0;
	}
	else if (idex == 1)
	{
		MyDebug.isAct = 1;
	}
	if (MyDebug.Create_Process(path))
		MyDebug.DebugEventLoop();
	printf("结束\n");
}