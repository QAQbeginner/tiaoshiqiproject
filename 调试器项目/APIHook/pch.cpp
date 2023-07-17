// pch.cpp: 与预编译标头对应的源文件

#include "pch.h"

// 当使用预编译的头时，需要使用此源文件，编译才能成功。
// 目标函数所在的地址
DWORD OldAddr = NULL;

// 保存修改前的OPCODE
UCHAR OldOpCode[5] = { 0 };

// 新的用于替换的 OpCode， E9 表示 jmp offset
UCHAR NewOpCode[5] = { 0xE9 };


// 1. 确定需要HOOK的API并且自己实现一个类型完全匹配的函数
BOOL WINAPI MyIsDebuggerPresent(VOID)
{

	return FALSE;
}

// 初始化需要用到的数据
void Initialize()
{
	IsDebuggerPresent;
	// 1. 获取目标函数的地址，推荐使用动态获取的方式获取
	HMODULE Module = GetModuleHandleA("kernel32.dll");
	OldAddr = (DWORD)GetProcAddress(Module, "IsDebuggerPresent");

	// 2. 计算跳转的偏移: 目标地址(跳到哪里) - 指令所在地址 - 指令长度(5)
	*(int*)&NewOpCode[1] = (DWORD)MyIsDebuggerPresent - OldAddr - 5;

	// 3. 保存原始 OPCODE 用于还原
	memcpy(OldOpCode, (LPVOID)OldAddr, 5);
}

void OnHook()
{
	// 由于指令存储在 text 中，所以修改其内容需要考虑分页属性
	DWORD OldProtect = NULL;
	VirtualProtect((LPVOID)OldAddr, 4, PAGE_EXECUTE_READWRITE, &OldProtect);
	memcpy((LPVOID)OldAddr, NewOpCode, 5);
	VirtualProtect((LPVOID)OldAddr, 4, OldProtect, &OldProtect);
}

void OffHook()
{
	// 由于指令存储在 text 中，所以修改其内容需要考虑分页属性
	DWORD OldProtect = NULL;
	VirtualProtect((LPVOID)OldAddr, 4, PAGE_EXECUTE_READWRITE, &OldProtect);
	memcpy((LPVOID)OldAddr, OldOpCode, 5);
	VirtualProtect((LPVOID)OldAddr, 4, OldProtect, &OldProtect);
}