#pragma once
#include<atlstr.h>

// RVA转FOA功能函数
DWORD RVAtoFOA(DWORD RVA, PIMAGE_NT_HEADERS NtHeader);

// 遍历导入表的模块
BOOL AllImportDll(PIMAGE_NT_HEADERS NtHeader, BYTE* FileBase);

// 遍历导出表的模块
BOOL AllExportDll(PIMAGE_NT_HEADERS NtHeader, BYTE* FileBase);

// 遍历导入表模块内的函数
BOOL ImportFunc(PIMAGE_NT_HEADERS NtHeader, BYTE* FileBase);