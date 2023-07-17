#pragma once
#include<Windows.h>
#include<vector>
#include<atlstr.h>

// ��¼����ϵ���Ϣ�Ľṹ��
typedef struct _BREAK_POINT
{
	LPVOID address;	// �ϵ��ַ
	BYTE   data;	// �ϵ�λ�õ�����
	BOOL   enable;	// �Ƿ������ϵ�
}BREAK_POINT;


// ��¼�ڴ�ϵ���Ϣ�Ľṹ��
typedef struct MEMORY_POINT {
	PVOID paddress;
	DWORD oldProtect;
	DWORD len;
	DWORD type;
};

// ����ģ��ṹ��
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
	//������Ϣ
	PROCESS_INFORMATION ProcessInfo;
	// ������ڵ�OEP
	LPVOID OEP;
	// ����ϵ��б�
	std::vector<_BREAK_POINT> INT3List;
	// �����ϵ�ṹ��
	_BREAK_POINT ConBreak;
	// �����ϵ�����ֵ
	DWORD ConBreakData;
	// �����ϵ��־
	BOOL m_FlagsCon=FALSE;
	// �ڴ���ʶϵ�
	MEMORY_POINT MemoryBreakData;
	//�Ƿ��������
	BOOL m_isInput;
	// ����ָ�CC�õĵ���
	BOOL m_FlagsBp = FALSE;
	// Ӳ���ϵ�ָ��õĵ���
	INT m_FalgsBa = 0;
	// �Ƿ�Ӳ��
	BOOL isBa = FALSE;
	// �Ƿ�TF����
	BOOL m_FlagsTF = FALSE;
	// �Ƿ��ڴ���ʶϵ�
	BOOL m_FlagsMemory = FALSE;
	// �쳣������
	DWORD IsContinueExcepiton = DBG_EXCEPTION_NOT_HANDLED;
	// ���ڻ�ԭ�ڴ�ҳ������
	DWORD m_oldProtect;
	// ���ط��ű�־λ
	BOOL SymbolSign = FALSE;
	// ȫ�ֱ������
	HANDLE g_hProcess;
	// �жϴ򿪽��̷�ʽ
	INT isAct = -1;
	// Ū����ȫ�ֱ���
	BYTE* FileBase;
	PIMAGE_NT_HEADERS NtHeader;
public:
	// ��������
	BOOL Create_Process(CHAR* szTargetPath);
	// �ȴ������¼�
	VOID DebugEventLoop();
	// �����ת��
	VOID DisAsm(HANDLE hProcess, PVOID address, DWORD len=5);
	// �쳣����
	DWORD Exception_Handler(DEBUG_EVENT* dbg);
	// ��������ϵ�
	BOOL SetINT3(HANDLE hProcess, LPVOID pAddress);
	// ����ϵ㣨INT3���ǵĻ�������ʾ��
	BOOL INT3Handle(HANDLE hProcess,HANDLE hThread, LPVOID ExceptionAddress);
	// �����ڴ�ϵ㴦��
	BOOL MemoryBreakHandle(HANDLE hProcess, HANDLE hThread, LPVOID ExceptionAddress, EXCEPTION_RECORD Record);
	// ��ͬ�ϵ㴦��
	VOID BreakHandle(HANDLE hProcess, HANDLE hThread, LPVOID ExceptionAddress, EXCEPTION_RECORD Record);
	// ���õ����ϵ�TF
	BOOL SetTF(HANDLE hThread);
	// �����ڴ���ʶϵ�
	BOOL SetMemoryBreak(HANDLE hProcess, PVOID address, DWORD type = 0, DWORD len = 1);
	// �����û�����
	VOID UserInput(HANDLE hProcess, HANDLE hThread , LPVOID ExceptionAddress);
	// �޸Ļ��ָ��
	BOOL ChangeAsmCode(HANDLE hProcess);
	// �޸ļĴ�����ֵ��û����
	BOOL ChangeRegister(HANDLE hThread);
	// ����Ӳ���ϵ�
	BOOL SetHardPoint(HANDLE hThread, PVOID address, DWORD type = 3, DWORD len = 0);
	// ������ȡ��һ��ָ��
	LPVOID NextAsm(HANDLE hProcess, PVOID address, DWORD len = 5);
	// �ظ�Ӳ���ϵ�
	VOID HardBreakReply(HANDLE hThread, HANDLE hProcess,LPVOID ExceptionAddress);
	// ��ȡ��ǰָ��ĳ��ȡ����ԡ�
	DWORD AsmLen(HANDLE hProcess, PVOID address);
	// ��ʾ�ڴ�
	BOOL PrintMemory(HANDLE hProcess, PVOID address);
	// �޸��ڴ�
	BOOL ChangeMemory(HANDLE hProcess, PVOID address, BYTE Data);
	// ���������ϵ�
	BOOL SetConBreak(HANDLE hProcess, LPVOID pAddress, DWORD Data);
	// �ظ������ϵ�
	VOID ConBreakHandle(HANDLE hThread, HANDLE hProcess, LPVOID ExceptionAddress);
	// ��ʾģ����Ϣ
	VOID AllModule(HANDLE hProcess);
	// hook�ؼ�����
	BOOL HidePEB(DEBUG_EVENT* dbg);
	// ��ȡ������
	BOOL GetSymName(HANDLE hProcess, SIZE_T nAddress, CString& strName);
	// ��ʾջ
	BOOL PrintStack(HANDLE hProcess, HANDLE hThread);
	// ��ȡ�ļ���Ϣ
	BOOL GetPEInfo(WCHAR* szTargetPath);
	// �ؼ�APIHook
	BOOL APIHook(DEBUG_EVENT* dbg);
	// ����API�ϵ�
	SIZE_T FindApiAddress(HANDLE hProcess, const char* pszName);
	// ����ģ����Ϣ����ֵ�ṹ��
	BOOL AllMoudlesList(HANDLE hProcess);
	// ����ָ��ģ����Ϣ
	BOOL ExportFunc();
};

