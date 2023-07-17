#include<Windows.h>
#include"ImportAndExport.h"

// RVAתFOA���ܺ���
DWORD RVAtoFOA(DWORD RVA, PIMAGE_NT_HEADERS NtHeader)
{
	// ��ȡ���ε�����
	WORD nCount = NtHeader->FileHeader.NumberOfSections;
	// ��ȡ���α��λ��
	PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(NtHeader);
	// ѭ�������Ȳ���RVA���ڵ�����
	for (WORD i = 0; i < nCount; i++)
	{
		if (RVA >= Sections[i].VirtualAddress
			&& RVA < Sections[i].VirtualAddress + Sections[i].SizeOfRawData)
		{
			// ��RVAתFOA
			return RVA - Sections[i].VirtualAddress + Sections[i].PointerToRawData;
		}
	}
	return 0;
}

// ����������ģ��
BOOL AllImportDll(PIMAGE_NT_HEADERS NtHeader, BYTE* FileBase)
{
	/*
	 ����������ģ����Ϣ
	*/
	PIMAGE_IMPORT_DESCRIPTOR ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(RVAtoFOA((NtHeader->OptionalHeader.DataDirectory[1].VirtualAddress), NtHeader) + FileBase);
	/*
	 ѭ�����
	*/
	printf("�����ģ�飺\n");
	while (ImportTable->Name != 0)
	{
		CStringA Buffer1;
		CString Buffer;
		CHAR* DllName = (CHAR*)(RVAtoFOA(ImportTable->Name, NtHeader) + FileBase);
		printf("%s :", DllName);
		printf("%08X  ", ImportTable->OriginalFirstThunk);
		printf("%08X\n", ImportTable);
		ImportTable++;
	}
	return TRUE;
}

// �����������ģ��
BOOL AllExportDll(PIMAGE_NT_HEADERS NtHeader, BYTE* FileBase)
{
	// ��ȡ������ĵ�ַ
	PIMAGE_EXPORT_DIRECTORY ExportTable = (PIMAGE_EXPORT_DIRECTORY)(FileBase + RVAtoFOA(NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress, NtHeader));

	// ��ȡ������ַ���������Ʊ��Լ�������ű�ĵ�ַ
	// 1.������ַ��
	DWORD* FunctionsTable = (DWORD*)(FileBase + RVAtoFOA(ExportTable->AddressOfFunctions, NtHeader));
	// 2.�������Ʊ�
	DWORD* NamesTable = (DWORD*)(FileBase + RVAtoFOA(ExportTable->AddressOfNames, NtHeader));
	// 3.������ű�
	WORD* OriginalTable = (WORD*)(FileBase + RVAtoFOA(ExportTable->AddressOfNameOrdinals, NtHeader));
	printf("������\n");
	// ѭ���������������Ϣ
	for (DWORD i = 0; i < ExportTable->NumberOfFunctions; i++)
	{
		CString Buffer;

		// ������������־�������������
		for (DWORD j = 0; j < ExportTable->NumberOfNames; j++)
		{
			if (OriginalTable[j] == i)
			{
				// ��ű�����Ʊ���һһ��Ӧ�ģ�����ű���������õ����Ʊ�Ϳ��Ի�ȡ����Ӧ RVA
				CHAR* FuncName = (CHAR*)(RVAtoFOA(NamesTable[i], NtHeader) + FileBase);
				// ���������ַ���
				printf("%s: ", FuncName);
				// �������
				printf("%08X \n", FunctionsTable[i]);
				i++;
				break;
			}
		}
		// �����������б�(û�к������ֵ�)
		printf("NONE: ");
		printf("%08X \n", FunctionsTable[i]);
	}
	return TRUE;
}

// ���������ģ���ڵĺ���
 BOOL ImportFunc(PIMAGE_NT_HEADERS NtHeader, BYTE* FileBase)
{
	 // 1. ͨ������Ŀ¼���±�Ϊ 1 �����ҵ������ RVA �� SIZE
	 DWORD RVA = NtHeader->OptionalHeader.DataDirectory[1].VirtualAddress;

	 // 2. ����һ����ȡ���� RVA ת������Ӧ�� FOA �õ������
	 auto ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(RVAtoFOA(RVA, NtHeader)+ FileBase);


	/*
	 ͨ����������IAT�����汣�������һ���ṹ���RVA���ҵ�IMAGE_THUNK_DATA�ṹ��ָ����ļ���ַ
	*/
	auto Int = (IMAGE_THUNK_DATA*)(RVAtoFOA(ImportTable->FirstThunk, NtHeader) + FileBase);

	/*
	 ѭ��������ģ��������ĺ���
	*/
	for (int i = 0; Int[i].u1.Function; i++)
	{
		/*
		 ������λֵΪ1����ú�����ͨ����ŵ���ģ�û�к�����
		*/
		if (IMAGE_SNAP_BY_ORDINAL(Int[i].u1.Function) == 1)
		{
			printf("[NONE:] ");
			printf("%04X\n", LOWORD(Int[i].u1.Function));
		}
		/*
		 ��������ͨ�������������
		*/
		else
		{
			auto Name = PIMAGE_IMPORT_BY_NAME(RVAtoFOA(Int[i].u1.Function, NtHeader) + FileBase);
			printf("[%s:] ", Name->Name);
			printf("%04X\n", Name->Hint);
		}
	}
	return TRUE;
}