#pragma once
#include<Windows.h>
#include<vector>
#include<atlstr.h>

// 记录软件断点信息的结构体
typedef struct _BREAK_POINT
{
	LPVOID address;	// 断点地址
	BYTE   data;	// 断点位置的数据
	BOOL   enable;	// 是否启动断点
}BREAK_POINT;


// 记录内存断点信息的结构体
typedef struct MEMORY_POINT {
	PVOID paddress;
	DWORD oldProtect;
	DWORD len;
	DWORD type;
};

// 定义模块结构体
typedef struct PE_Struct {
	WCHAR Name[MAX_PATH];
	WCHAR Path[MAX_PATH];
	DWORD dllBase;
};

class CDebug
{
public:
	//
	std::vector<PE_Struct> ModuleList;
	//进程信息
	PROCESS_INFORMATION ProcessInfo;
	// 程序入口点OEP
	LPVOID OEP;
	// 软件断点列表
	std::vector<_BREAK_POINT> INT3List;
	// 条件断点结构体
	_BREAK_POINT ConBreak;
	// 条件断点条件值
	DWORD ConBreakData;
	// 条件断点标志
	BOOL m_FlagsCon=FALSE;
	// 内存访问断点
	MEMORY_POINT MemoryBreakData;
	//是否接受输入
	BOOL m_isInput;
	// 软件恢复CC用的单步
	BOOL m_FlagsBp = FALSE;
	// 硬件断点恢复用的单步
	INT m_FalgsBa = 0;
	// 是否硬件
	BOOL isBa = FALSE;
	// 是否TF单步
	BOOL m_FlagsTF = FALSE;
	// 是否内存访问断点
	BOOL m_FlagsMemory = FALSE;
	// 异常处理结果
	DWORD IsContinueExcepiton = DBG_EXCEPTION_NOT_HANDLED;
	// 用于还原内存页面属性
	DWORD m_oldProtect;
	// 加载符号标志位
	BOOL SymbolSign = FALSE;
	// 全局变量句柄
	HANDLE g_hProcess;
	// 判断打开进程方式
	INT isAct = -1;
	// 弄两个全局变量
	BYTE* FileBase;
	PIMAGE_NT_HEADERS NtHeader;
public:
	// 创建进程
	BOOL Create_Process(CHAR* szTargetPath);
	// 等待调试事件
	VOID DebugEventLoop();
	// 反汇编转换
	VOID DisAsm(HANDLE hProcess, PVOID address, DWORD len=5);
	// 异常处理
	DWORD Exception_Handler(DEBUG_EVENT* dbg);
	// 设置软件断点
	BOOL SetINT3(HANDLE hProcess, LPVOID pAddress);
	// 软件断点（INT3覆盖的汇编代码显示）
	BOOL INT3Handle(HANDLE hProcess,HANDLE hThread, LPVOID ExceptionAddress);
	// 永久内存断点处理
	BOOL MemoryBreakHandle(HANDLE hProcess, HANDLE hThread, LPVOID ExceptionAddress, EXCEPTION_RECORD Record);
	// 不同断点处理
	VOID BreakHandle(HANDLE hProcess, HANDLE hThread, LPVOID ExceptionAddress, EXCEPTION_RECORD Record);
	// 设置单步断点TF
	BOOL SetTF(HANDLE hThread);
	// 设置内存访问断点
	BOOL SetMemoryBreak(HANDLE hProcess, PVOID address, DWORD type = 0, DWORD len = 1);
	// 接受用户输入
	VOID UserInput(HANDLE hProcess, HANDLE hThread , LPVOID ExceptionAddress);
	// 修改汇编指令
	BOOL ChangeAsmCode(HANDLE hProcess);
	// 修改寄存器的值【没做】
	BOOL ChangeRegister(HANDLE hThread);
	// 设置硬件断点
	BOOL SetHardPoint(HANDLE hThread, PVOID address, DWORD type = 3, DWORD len = 0);
	// 反汇编获取下一跳指令
	LPVOID NextAsm(HANDLE hProcess, PVOID address, DWORD len = 5);
	// 回复硬件断点
	VOID HardBreakReply(HANDLE hThread, HANDLE hProcess,LPVOID ExceptionAddress);
	// 获取当前指令的长度【不对】
	DWORD AsmLen(HANDLE hProcess, PVOID address);
	// 显示内存
	BOOL PrintMemory(HANDLE hProcess, PVOID address);
	// 修改内存
	BOOL ChangeMemory(HANDLE hProcess, PVOID address, BYTE Data);
	// 设置条件断点
	BOOL SetConBreak(HANDLE hProcess, LPVOID pAddress, DWORD Data);
	// 回复条件断点
	VOID ConBreakHandle(HANDLE hThread, HANDLE hProcess, LPVOID ExceptionAddress);
	// 显示模块信息
	VOID AllModule(HANDLE hProcess);
	// hook关键函数
	BOOL HidePEB(DEBUG_EVENT* dbg);
	// 获取函数名
	BOOL GetSymName(HANDLE hProcess, SIZE_T nAddress, CString& strName);
	// 显示栈
	BOOL PrintStack(HANDLE hProcess, HANDLE hThread);
	// 获取文件信息
	BOOL GetPEInfo(WCHAR* szTargetPath);
	// 关键APIHook
	BOOL APIHook(DEBUG_EVENT* dbg);
	// 设置API断点
	SIZE_T FindApiAddress(HANDLE hProcess, const char* pszName);
	// 遍历模块信息并赋值结构体
	BOOL AllMoudlesList(HANDLE hProcess);
	// 遍历指定模块信息
	BOOL ExportFunc();
};

