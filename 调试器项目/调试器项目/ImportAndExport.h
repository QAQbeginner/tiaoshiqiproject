#pragma once
#include<atlstr.h>

// RVAתFOA���ܺ���
DWORD RVAtoFOA(DWORD RVA, PIMAGE_NT_HEADERS NtHeader);

// ����������ģ��
BOOL AllImportDll(PIMAGE_NT_HEADERS NtHeader, BYTE* FileBase);

// �����������ģ��
BOOL AllExportDll(PIMAGE_NT_HEADERS NtHeader, BYTE* FileBase);

// ���������ģ���ڵĺ���
BOOL ImportFunc(PIMAGE_NT_HEADERS NtHeader, BYTE* FileBase);