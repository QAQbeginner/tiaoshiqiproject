#include"CDebug.h"
#include<iostream>
//..\\Debug\\dbgtarget.exe   ������  �����ϵ��peb���
#define TARGET_PATH (TCHAR*)L"..\\Debug\\inject.exe"
CHAR path[0x100];
#include"plug.h"
int main()
{
	// ���ò��
	PlugHandle();
	CDebug MyDebug;
	printf("�����·��\n");
	int idex=0;
	scanf_s("%s", path, 0x100);
	printf("��������̴򿪷�ʽ��0���򿪽��� 1�����ӽ���\n");
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
	printf("����\n");
}