// pch.cpp: 与预编译标头对应的源文件

#include "pch.h"
#include<iostream>

// 当使用预编译的头时，需要使用此源文件，编译才能成功。
DWORD OldPath = 0;


// 保存以前的页属性
DWORD OldProtect;

// 开启Hook功能函数
VOID OnHook()
{
	BOOL BeginDebug=TRUE;
	_asm {
		mov eax, fs: [0x30] ;
		mov [eax + 0x02], 0;
		mov [eax + 0x068], 0;
		mov [eax + 0x90] + 0x40, 2;
		mov [eax + 0x90] + 0x44, 0;
	}
}
