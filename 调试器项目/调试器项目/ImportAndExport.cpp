#include<Windows.h>
#include"ImportAndExport.h"

// RVA转FOA功能函数
DWORD RVAtoFOA(DWORD RVA, PIMAGE_NT_HEADERS NtHeader)
{
	// 获取区段的数量
	WORD nCount = NtHeader->FileHeader.NumberOfSections;
	// 获取区段表的位置
	PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(NtHeader);
	// 循环遍历先查找RVA所在的区段
	for (WORD i = 0; i < nCount; i++)
	{
		if (RVA >= Sections[i].VirtualAddress
			&& RVA < Sections[i].VirtualAddress + Sections[i].SizeOfRawData)
		{
			// 将RVA转FOA
			return RVA - Sections[i].VirtualAddress + Sections[i].PointerToRawData;
		}
	}
	return 0;
}

// 遍历导入表的模块
BOOL AllImportDll(PIMAGE_NT_HEADERS NtHeader, BYTE* FileBase)
{
	/*
	 遍历导入表的模块信息
	*/
	PIMAGE_IMPORT_DESCRIPTOR ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(RVAtoFOA((NtHeader->OptionalHeader.DataDirectory[1].VirtualAddress), NtHeader) + FileBase);
	/*
	 循环输出
	*/
	printf("导入表模块：\n");
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

// 遍历导出表的模块
BOOL AllExportDll(PIMAGE_NT_HEADERS NtHeader, BYTE* FileBase)
{
	// 获取导出表的地址
	PIMAGE_EXPORT_DIRECTORY ExportTable = (PIMAGE_EXPORT_DIRECTORY)(FileBase + RVAtoFOA(NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress, NtHeader));

	// 获取函数地址表，函数名称表，以及函数序号表的地址
	// 1.函数地址表
	DWORD* FunctionsTable = (DWORD*)(FileBase + RVAtoFOA(ExportTable->AddressOfFunctions, NtHeader));
	// 2.函数名称表
	DWORD* NamesTable = (DWORD*)(FileBase + RVAtoFOA(ExportTable->AddressOfNames, NtHeader));
	// 3.函数序号表
	WORD* OriginalTable = (WORD*)(FileBase + RVAtoFOA(ExportTable->AddressOfNameOrdinals, NtHeader));
	printf("导出表：\n");
	// 循环遍历导出表的信息
	for (DWORD i = 0; i < ExportTable->NumberOfFunctions; i++)
	{
		CString Buffer;

		// 如果函数有名字就在这里面输入
		for (DWORD j = 0; j < ExportTable->NumberOfNames; j++)
		{
			if (OriginalTable[j] == i)
			{
				// 序号表和名称表是一一对应的，将序号表的索引放置到名称表就可以获取到对应 RVA
				CHAR* FuncName = (CHAR*)(RVAtoFOA(NamesTable[i], NtHeader) + FileBase);
				// 插入名字字符串
				printf("%s: ", FuncName);
				// 插入序号
				printf("%08X \n", FunctionsTable[i]);
				i++;
				break;
			}
		}
		// 将序号添加至列表(没有函数名字的)
		printf("NONE: ");
		printf("%08X \n", FunctionsTable[i]);
	}
	return TRUE;
}

// 遍历导入表模块内的函数
 BOOL ImportFunc(PIMAGE_NT_HEADERS NtHeader, BYTE* FileBase)
{
	 // 1. 通过数据目录表下标为 1 的项找到导入表 RVA 和 SIZE
	 DWORD RVA = NtHeader->OptionalHeader.DataDirectory[1].VirtualAddress;

	 // 2. 将第一步获取到的 RVA 转换成相应的 FOA 得到导入表
	 auto ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(RVAtoFOA(RVA, NtHeader)+ FileBase);


	/*
	 通过导入表里的IAT（里面保存的是另一个结构体的RVA）找到IMAGE_THUNK_DATA结构体指针的文件地址
	*/
	auto Int = (IMAGE_THUNK_DATA*)(RVAtoFOA(ImportTable->FirstThunk, NtHeader) + FileBase);

	/*
	 循环遍历该模块所导入的函数
	*/
	for (int i = 0; Int[i].u1.Function; i++)
	{
		/*
		 如果最高位值为1，则该函数是通过序号导入的，没有函数名
		*/
		if (IMAGE_SNAP_BY_ORDINAL(Int[i].u1.Function) == 1)
		{
			printf("[NONE:] ");
			printf("%04X\n", LOWORD(Int[i].u1.Function));
		}
		/*
		 否则，则是通过函数名导入的
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