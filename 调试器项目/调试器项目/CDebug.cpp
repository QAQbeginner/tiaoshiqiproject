#include "CDebug.h"
#include "capstone/include/capstone.h"
#include<iostream>
#include"RegStruct.h"
#include"ImportAndExport.h"
#include<Dbghelp.h>
#include<psapi.h>
// #include "RegStruct.h"
//1. ����ͷ�ļ�
#include "keystone/keystone.h"
#include<TlHelp32.h>

#include<DbgHelp.h>
#pragma comment(lib,"Dbghelp.lib")

//2. ������̬��
#pragma comment (lib,"keystone/x86/keystone_x86.lib")
#pragma comment (lib,"Dbghelp.lib")

//1. ����ͷ�ļ�
#ifdef _WIN64 // 64λƽ̨���������Զ����������
#pragma 
comment(lib, "capstone/lib/capstone_x64.lib")
#else
#pragma comment(lib,"capstone/lib/capstone_x86.lib")
#endif // _64

// ��������
BOOL CDebug::Create_Process(CHAR* szTargetPath)
{
    STARTUPINFOA si = { sizeof(si) };
    BOOL bRet;
    if (isAct == 0)
    {
        //1.�Ե��Է�ʽ����Ŀ�����
         bRet = CreateProcessA(
            szTargetPath,        //����·��
            NULL,               //������
            NULL,              //���̰�ȫ����
            NULL,              //�̰߳�ȫ����               
            FALSE,             //�Ƿ�̳о����
            DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,//������־
            NULL,              //��������
            NULL,              //����Ŀ¼
            &si,               //������Ϣ
            &ProcessInfo       //�����������Ϣ
        );
    }
    else if(isAct == 1)
    {
        DWORD Pid = 0;
        sscanf_s(szTargetPath,"%d", &Pid);
       // ���ӷ�ʽ
       bRet = DebugActiveProcess(Pid);
    }

    return  bRet;
}

// �ȴ������¼�
VOID CDebug::DebugEventLoop()
{
    // ������Ҫ����3�����֣�1.�ȴ������¼���2.��������¼���3.�ظ������¼�
    DWORD bRet = 0;
    DEBUG_EVENT dbgEvent = { 0 };
    DWORD dwReCode = DBG_CONTINUE;
    int idex = 0;
    while (TRUE)
    {
        // 1.�ȴ������¼�
        bRet = WaitForDebugEvent(&dbgEvent, -1);
        
        if (bRet == FALSE)return;
        // 2.��������¼�
        switch (dbgEvent.dwDebugEventCode)
        {
            // �쳣�����¼�
        case EXCEPTION_DEBUG_EVENT: 
            dwReCode = Exception_Handler(&dbgEvent);
            break;
            // �����߳��¼�
        case CREATE_THREAD_DEBUG_EVENT:
            printf("�̴߳���\n");
            break;
            // ���������¼�
        case CREATE_PROCESS_DEBUG_EVENT:
            printf("��ѡ���ƽⷽʽ��1.����PEB 2.hook�ؼ�API\n");
            scanf_s("%d", &idex);
            if(idex==1)
            HidePEB(&dbgEvent);
            else if(idex==2)
            APIHook(&dbgEvent);
            dbgEvent.u.CreateProcessInfo;  // ��ȡ���������Ϣ
            printf("���̴����¼� : ���0X%08x\n",
                dbgEvent.u.CreateProcessInfo.lpStartAddress);
            if (isAct==1)
            {
                isAct=-3;
                ProcessInfo.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dbgEvent.dwProcessId);
                ProcessInfo.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
                ProcessInfo.dwProcessId = dbgEvent.dwProcessId;
                ProcessInfo.dwThreadId = dbgEvent.dwThreadId;
                CONTEXT ctx = { CONTEXT_ALL };
                GetThreadContext(ProcessInfo.hThread, &ctx);
                SetINT3(ProcessInfo.hProcess, (PVOID)ctx.Eip);
            }
            else if(isAct==0)
            {
                // ���������ڵ� m_Oep
                OEP = dbgEvent.u.CreateProcessInfo.lpStartAddress;
                // ��OEP����һ������ϵ�
                SetINT3(ProcessInfo.hProcess, OEP);
            }
            break;
            // �˳��߳��¼�
        case EXIT_THREAD_DEBUG_EVENT:
            printf("�߳��˳��¼�\n");
            break;
            // �˳������¼�
        case EXIT_PROCESS_DEBUG_EVENT:
            printf("�����˳�\n");
            return;
            break;
            // ����ģ���¼�
        case LOAD_DLL_DEBUG_EVENT:
            printf("ģ������¼�: DLLBASE: 0X%08x\n",
                dbgEvent.u.LoadDll.lpBaseOfDll);
            break;
            // ж��ģ���¼�
        case UNLOAD_DLL_DEBUG_EVENT:    
            break;
            // ������Ϣ
        case OUTPUT_DEBUG_STRING_EVENT:    
            break;
        case RIP_EVENT:     
            break;
        }
        // 3.�ظ�������ϵͳ
        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, dwReCode);
    }
    // �رս����߳̾��
    CloseHandle(ProcessInfo.hProcess);
    CloseHandle(ProcessInfo.hThread);

    return VOID();
}

// �����ת��
VOID CDebug::DisAsm(HANDLE hProcess, PVOID address, DWORD len)
{
    char opcode[4096] = {};
    DWORD dwSize;
    // 1.��ȡĿ������ڴ�����
    ReadProcessMemory(g_hProcess, address, opcode, sizeof(opcode), &dwSize);
    // 2.���������

    csh handle;   // �����������
    cs_err err;   // ������Ϣ
    cs_insn* pInsn; // ���淴���õ���ָ��Ļ������׵�ַ
    unsigned int count = 0; // ����õ��ķ�����ָ������


    //��ʼ������������,(x86_64�ܹ�,32λģʽ,���)
    err = cs_open(CS_ARCH_X86,  /*x86ָ�*/
        CS_MODE_32, /*ʹ��32λģʽ����opcode*/
        &handle /*����ķ������*/
    );

    if (err != CS_ERR_OK)
    {
        printf("��ʼ������������ʧ��:%s\n", cs_strerror(err));
        return ;
    }

    

    // ��ʼ�����.
    // �����᷵���ܹ��õ��˼������ָ��
    count = cs_disasm(handle,       /*����������,��cs_open�����õ�*/
        (const uint8_t*)opcode,     /*��Ҫ������opcode�Ļ������׵�ַ*/
        sizeof(opcode),             /*opcode���ֽ���*/
        (uint64_t)address,          /*opcode�����ڵ��ڴ��ַ*/
        len,                        /*��Ҫ������ָ������,�����0,�򷴻���ȫ��*/
        &pInsn                      /*��������*/
    );

    for (DWORD i = 0; i < count; ++i)
    {
        printf("%08X\t", (UINT)pInsn[i].address);
        for (uint16_t j = 0; j < 16; ++j)
        {
            if (j < pInsn[i].size)
                printf("%02X", pInsn[i].bytes[j]);
            else
                printf("  ");
        }
        // �����Ӧ�ķ����
        printf("\t%s %s", pInsn[i].mnemonic, pInsn[i].op_str);
        CString funcName;
        if(GetSymName(g_hProcess, pInsn[i].address, funcName))
            printf("   %s", (CStringA)funcName);
        printf("\n");
    }


    printf("\n");

    // �ͷű���ָ��Ŀռ�
    cs_free(pInsn, count);

    // �رվ��
    cs_close(&handle);

}

// �쳣����
DWORD CDebug::Exception_Handler(DEBUG_EVENT* dbg)
{
    // �쳣��Ϣ
    EXCEPTION_RECORD Record = dbg->u.Exception.ExceptionRecord;
    // �쳣�����ĵ�ַ
    LPVOID ExceptionAddress = Record.ExceptionAddress;
    // �쳣����
    DWORD ExceptionCode = Record.ExceptionCode;
    // �򿪽��̾��
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dbg->dwProcessId);
    // ���߳̾��
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbg->dwThreadId);
    
    g_hProcess = hProcess;
    switch (ExceptionCode)
    {
        // ����ϵ㣺
    case EXCEPTION_BREAKPOINT:
    {
        // ϵͳ��һ�λᴥ��һ������쳣��NTDLL�д����ģ�ϵͳ�ϵ�
        static bool isSystemBreakPorint = TRUE;
        // ���ǵ�һ�ν����쳣����ϵͳ�ϵ�
        if (isSystemBreakPorint == TRUE) 
        {
            // ֮������ϵͳ�ϵ���
            isSystemBreakPorint = FALSE; 
            printf("ϵͳ�ϵ� �쳣��ַ�� 0x%08x\n", ExceptionAddress);

            // �쳣�������ǲ�����
            IsContinueExcepiton = DBG_EXCEPTION_NOT_HANDLED;
            // �ϵ㲻�����ǲ����ģ�����Ҫ��������
            m_isInput = FALSE;
            AllMoudlesList(hProcess);
            break;
        }
        if (SymbolSign == FALSE)
        {
            SymbolSign = TRUE;
            BOOL a=SymInitialize(hProcess, 0, TRUE);
        }
        // �����Լ����õ�����INT3����ϵ�Ĵ���
        ConBreakHandle(hThread, hProcess, ExceptionAddress);
        if (m_FlagsCon == TRUE)
            break;
        INT3Handle(hProcess,hThread,ExceptionAddress);
    }break;
    // �����쳣/Ӳ���쳣
    case EXCEPTION_SINGLE_STEP:         
    {
        // ��ͬ�ϵ㴦��
        BreakHandle(hProcess,hThread, ExceptionAddress, Record);
    }break;
    //�ڴ�����쳣
    case EXCEPTION_ACCESS_VIOLATION:   
        MemoryBreakHandle(hProcess, hThread, ExceptionAddress,Record);
        break;
    default:break;
    }

    // �Ƿ�����û�����
    UserInput(hProcess, hThread, ExceptionAddress);
    
    // �رս��̾��
    CloseHandle(hProcess);
    // �ر��߳̾��
    CloseHandle(hThread);


    return IsContinueExcepiton;
}

// ��ͬ�ϵ㴦��
VOID CDebug::BreakHandle(HANDLE hProcess,HANDLE hThread, LPVOID ExceptionAddress, EXCEPTION_RECORD Record)
{
    // 1. �Ƿ�������ϵ�ָ������Եĵ���(INT3)
    if (m_FlagsBp)
    {
        m_FlagsBp = FALSE;
        DWORD dwSize;
        for (auto& bp : INT3List)
        {
            if (bp.enable)
            {
                WriteProcessMemory(hProcess, bp.address, "\xCC", 1, &dwSize);
            }
        }
        m_isInput = FALSE;
        IsContinueExcepiton = DBG_CONTINUE;
    }

    // 2. �Ƿ���ͨ������TF��
    if (m_FlagsTF)
    {
        m_FlagsTF = FALSE;
        // ���������Ϣ
        DisAsm(hProcess, ExceptionAddress);
        //��Ҫ����
        m_isInput = TRUE;
        IsContinueExcepiton = DBG_CONTINUE;
    }
     // 3.�Ƿ����ڴ���ʶϵ�
    if (m_FlagsMemory==TRUE)
    {
        m_FlagsMemory = FALSE;
        // �޸�ҳ������
        VirtualProtectEx(hProcess, MemoryBreakData.paddress, MemoryBreakData.len, PAGE_NOACCESS, &MemoryBreakData.oldProtect);
        //��Ҫ����
        m_isInput = FALSE;
        IsContinueExcepiton = DBG_CONTINUE;
    }
    // 4. �Ƿ���Ӳ���ϵ�
    if (isBa==TRUE)
    {
        isBa = FALSE;
        // ��ȡ�����ԼĴ���
        CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
        GetThreadContext(hThread, &context);

        // ��ȡ���ԼĴ����е� Dr7

        _DBG_REG7* dr7 = (_DBG_REG7*)&context.Dr7;
        switch (m_FalgsBa)
        {
        case 1:dr7->L0 = 1; break;
        case 2:dr7->L1 = 1; break;
        case 3:dr7->L2 = 1; break;
        case 4:dr7->L3 = 1; break;
        }
        SetThreadContext(hThread, &context);
        m_isInput = FALSE;
        IsContinueExcepiton = DBG_CONTINUE;
    }
    HardBreakReply(hThread, hProcess, ExceptionAddress);
    // 5.�Ƿ��������ϵ�
    if (m_FlagsCon)
    {
        m_FlagsCon = FALSE;
        DWORD dwSize;
        WriteProcessMemory(hProcess, ConBreak.address, "\xCC", 1, &dwSize);
        m_isInput = FALSE;
        IsContinueExcepiton = DBG_CONTINUE;
    }
}

// �����û�����
VOID CDebug::UserInput(HANDLE hProcess, HANDLE hThread, LPVOID ExceptionAddress)
{
    // �Ƿ�Ҫ��������
    if (m_isInput)
    {
        char buff[1024];
        while (TRUE)
        {
            printf("<< ");
            gets_s(buff, 1024);

            //��������
            char cmd[100] = {};
            sscanf_s(buff, "%s", cmd, 100);
            // ����ָ��
            if (strcmp("g", cmd) == 0)
            {
                //��������
                break;
            }
            // ����ϵ� 0x4118cb
            if (strcmp("bp", cmd) == 0)
            {
                LPVOID address = 0;
                if (2 == sscanf_s(buff, "%s %x", cmd, 100, &address))
                {
                    SetINT3(hProcess, address);
                    printf("���óɹ�\n");
                }
            }
            // ������
            if (strcmp("t", cmd) == 0)
            {
                SetTF(hThread);
                m_FlagsTF = TRUE;
                break;
            }
            // �ڴ���ʶϵ�
            if (strcmp("bm", cmd) == 0)
            {
                LPVOID address = 0;
                if (2 == sscanf_s(buff, "%s %x", cmd, 100, &address))
                {
                    DWORD bm_Type = 0;
                    scanf_s("%d", &bm_Type);
                    SetMemoryBreak(hProcess, address, bm_Type);
                    printf("���óɹ�\n");
                }
            }
            // �޸��ڴ�
            if (strcmp("ca", cmd) == 0)
            {
                ChangeAsmCode(hProcess);
            }
            if (strcmp("u", cmd) == 0)
            {
                LPVOID address = 0;
                if (2 == sscanf_s(buff, "%s %d", cmd, 100, &address))
                {
                    DisAsm(hProcess, address);
                }
                DisAsm(hProcess, ExceptionAddress);
            }
            // �鿴�Ĵ���
            if (strcmp("r", cmd) == 0)
            {
                CONTEXT Context = { CONTEXT_FULL };
                GetThreadContext(hThread, &Context);
                printf(" Eax:%08X   Ebx:%08X   Ecx:%08X\n ", Context.Eax, Context.Ebx, Context.Ecx);
                printf("Edx:%08X   Edi:%08X   Esi:%08X\n ", Context.Edx, Context.Edi, Context.Esi);
                printf("Eip:%08X   Eflags:%08X   Esp:%08X\n", Context.Eip, Context.EFlags, Context.Esp);
            }
            // ����Ӳ���ϵ�
            if (strcmp("ba", cmd) == 0)
            {
                PVOID address = 0;
                DWORD m_Type = 3;
                if (2 == sscanf_s(buff, "%s %x ", cmd, 100, &address))
                {
                    scanf_s("%d", &m_Type);
                    SetHardPoint(hThread, address, m_Type);
                    printf("����Ӳ���ϵ�ɹ�\n");
                }
            }
            // ��������
            if (strcmp("p", cmd) == 0)
            {
                LPVOID Next= NextAsm(hProcess, ExceptionAddress);
                SetINT3(hProcess, Next);
                break;
            }
            // ��ʾ�ϵ���Ϣ
            if (strcmp("bl", cmd) == 0)
            {
                printf("����ϵ㣺\n");
                for (int i = 0; i < INT3List.size(); i++)
                {
                    printf("[%d]:   %08X\n", i, INT3List[i].address);
                } 
                CONTEXT ctx = { CONTEXT_DEBUG_REGISTERS }; //��ȡ�߳���������Ӳ���Ĵ���
                GetThreadContext(hThread, &ctx);
                printf("Ӳ���ϵ㣺");
                _DBG_REG7* dr7 = (_DBG_REG7*)&ctx.Dr7;
                if (dr7->L0 != 0 || dr7->L1 != 0 || dr7->L2 != 0 || dr7->L3 != 0)
                    printf("Dr7->L%d:%08X\n", (m_FalgsBa - 1), ctx.Dr0);
                else
                    printf("\n");
                printf("�ڴ�ϵ㣺");
                printf("%08X\n", MemoryBreakData.paddress);
            }
            // ɾ���ϵ�
            if (strcmp("bc", cmd) == 0)
            {
                char BreakInfo[1024];
                printf("������Ҫɾ���Ķϵ����ԣ�bm���ڴ�ϵ㣬ba��Ӳ���ϵ㣬bp������ϵ�\n");
                scanf_s("%s", BreakInfo,1024);
                if (strcmp("bm", BreakInfo) == 0)
                {
                    // �޸�ҳ������
                    VirtualProtectEx(hProcess, MemoryBreakData.paddress, MemoryBreakData.len, m_oldProtect, &MemoryBreakData.oldProtect);
                    m_FlagsMemory = FALSE;
                    printf("ɾ���ڴ�ϵ�ɹ�");
                }
                else if (strcmp("bp", BreakInfo) == 0)
                {
                    int idex = 0;
                    printf("��������Ҫɾ���ڼ��\n");
                    scanf_s("%d", &idex);
                    // ��ԭʼ����д�� opcode 
                    DWORD dwSize = 0;
                    WriteProcessMemory(hProcess, INT3List[idex].address,
                        &INT3List[idex].data, 1, &dwSize);
                    // ���ϵ�Ӷϵ��б����Ƴ�
                    INT3List.erase(INT3List.begin() + idex);
                    printf("ȡ���ϵ�ɹ�\n");
          
                }
                else if (strcmp("ba", BreakInfo) == 0)
                {
                    CONTEXT context = { CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL };
                    GetThreadContext(hThread, &context);
                    _DBG_REG7* dr7 = (_DBG_REG7*)&context.Dr7;
                    dr7->L0 = 0;
                    dr7->L1 = 0;
                    dr7->L2 = 0;
                    dr7->L3 = 0;
                    isBa = FALSE;
                    m_FalgsBa = 0;
                    SetThreadContext(hThread, &context);
                    printf("ɾ��Ӳ���ϵ�ɹ�\n");
                }
                
            }
            // ��ʾ�ڴ�
            if (strcmp("d", cmd) == 0)
            {
                PVOID address = 0;
                if (2 == sscanf_s(buff, "%s %x", cmd, 100, &address))
                PrintMemory(hProcess, address);
            }
            // �޸��ڴ�
            if (strcmp("e", cmd) == 0)
            {
                BYTE Data;
                PVOID address = 0;
                if (2 == sscanf_s(buff, "%s %x", cmd, 100, &address))
                {
                    scanf_s("%02X", &Data);
                    if(ChangeMemory(hProcess, address, Data))
                    printf("�޸��ڴ�ɹ�\n");
                }
            }
            // �޸ļĴ���
            if (strcmp("cr", cmd) == 0)
            {
                ChangeRegister(hThread);
            }
            // �����ϵ�
            if (strcmp("co", cmd) == 0)
            {
                PVOID address = 0;
                DWORD Data = 0;
                printf("�������ַ\n");
                scanf_s("%x", &address);
                printf("������ָ����ֵ\n");
                scanf_s("%08X", &Data);
                SetConBreak(hProcess, address, Data);
                printf("���������ϵ�ɹ�\n");
            }
            // ��ʾģ����Ϣ
            if (strcmp("lm", cmd) == 0)
            {
                AllModule(hProcess);
            }
            // ��ʾջ
            if (strcmp("pt", cmd) == 0)
            {
                PrintStack(hProcess, hThread);
            }
            // ��ʾָ�����������Ϣ
            if (strcmp("in", cmd) == 0)
            {
                ExportFunc();
            }
            // API�ϵ�
            if (strcmp("bpa", cmd) == 0)
            {
                char Name[200] = { 0 };
                printf("������API��������\n");
                scanf_s("%s", Name, 200);
                SIZE_T addr=FindApiAddress(hProcess, Name);
                SetINT3(hProcess,(LPVOID)addr);
                printf("���óɹ�\n");
            }
        }
    }
}

// ��������ϵ�
BOOL CDebug::SetINT3(HANDLE hProcess, LPVOID pAddress)
{
    BREAK_POINT bData = {0};
    DWORD dwSize = 0;
    // ��ȡ�����ڴ棬����һ���ֽڵ�����
    ReadProcessMemory(hProcess, pAddress, &bData.data, 1, &dwSize);
    bData.address = pAddress;
    bData.enable = TRUE;
    // ���õ�ַ���0xCC
    if (!WriteProcessMemory(hProcess, pAddress, "\xCC", 1, &dwSize))
        return FALSE;
    INT3List.push_back(bData);
    return TRUE;
}

// INT3����ϵ㴦��������ʾ��ȷ�Ļ����룩
BOOL  CDebug::INT3Handle(HANDLE hProcess, HANDLE hThread, LPVOID ExceptionAddress)
{

    //����ϵ��쳣����
    DWORD dwSize;
    // 1.��ԭʼ����д�ص��ϵ�λ����
    for (auto& bp : INT3List)
    {
        WriteProcessMemory(hProcess, bp.address, &bp.data, 1, &dwSize);
    }
    // 2.��Ҫ��eip -1 �˻ص�ָ������λ��
    CONTEXT ctx = { CONTEXT_FULL }; //��ȡ�߳��������е�ͨ�üĴ���
    GetThreadContext(hThread, &ctx);
    ctx.Eip -= 1;
    //���û��߳�ȥ
    SetThreadContext(hThread, &ctx);

    // �����
    DisAsm(ProcessInfo.hProcess, ExceptionAddress);
    IsContinueExcepiton = DBG_CONTINUE;
    // �ϵ������ǲ����ģ���Ҫ��������
    m_isInput = TRUE;

    // ���������Զϵ㣬����һ���������ڵ����лָ�����ϵ�CC
    SetTF(hThread);
    m_FlagsBp = TRUE;
    return TRUE;
}

// �����ڴ�ϵ㴦��
BOOL CDebug::MemoryBreakHandle(HANDLE hProcess, HANDLE hThread,LPVOID ExceptionAddress, EXCEPTION_RECORD Record)
{
    DWORD A = (DWORD)MemoryBreakData.paddress;
    DWORD Min = A - A%0x1000;
    DWORD Max = Min + 0x1000;
    // �ж��Ƿ��ڸ�ҳ
    if (Record.ExceptionInformation[1] >= Min && Record.ExceptionInformation[1] < Max&& A!=0)
    {
        // �޸�ҳ������
        VirtualProtectEx(hProcess, MemoryBreakData.paddress, MemoryBreakData.len, m_oldProtect, &MemoryBreakData.oldProtect);
        m_FlagsMemory = TRUE;
        // �жϷ��ʵ�ַ
        if ((PVOID)Record.ExceptionInformation[1] == MemoryBreakData.paddress && Record.ExceptionInformation[0] == MemoryBreakData.type)
        {
            // ���������Ϣ
            DisAsm(hProcess, ExceptionAddress);
            //��Ҫ����
            m_isInput = TRUE;
            // ���������Զϵ㣬����һ���������ڵ����лָ�����ϵ�CC
            SetTF(hThread);
        }
        SetTF(hThread);
        IsContinueExcepiton = DBG_CONTINUE;
        return TRUE;
    }
    else
    {
        // ���������Ϣ
        DisAsm(hProcess, ExceptionAddress);
        //��Ҫ����
        m_isInput = TRUE;
        IsContinueExcepiton = DBG_CONTINUE;
    }
}

// ���õ����ϵ�TF
BOOL CDebug::SetTF(HANDLE hThread)
{
    // 1.��ȡ�߳�������
    CONTEXT ctx = { CONTEXT_FULL }; //��ȡ�߳��������е�ͨ�üĴ���
    GetThreadContext(hThread, &ctx);
    // 2.�޸ļĴ���
    ((EFLAGS*)&ctx.EFlags)->TF = 1;
    SetThreadContext(hThread, &ctx);
    return TRUE;
}

// �����ڴ���ʶϵ�
BOOL CDebug::SetMemoryBreak(HANDLE hProcess, PVOID address, DWORD type, DWORD len)
{
    SIZE_T dwSize = 0;
    VirtualProtectEx(hProcess,address, len, PAGE_NOACCESS, &MemoryBreakData.oldProtect);
    m_oldProtect = MemoryBreakData.oldProtect;
    MemoryBreakData.len = len;
    MemoryBreakData.type = type;
    MemoryBreakData.paddress = address;
    return TRUE;
}

// ��ӡ
void printOpcode(const unsigned char* pOpcode, int nSize)
{
    for (int i = 0; i < nSize; ++i) {
        printf("%02X ", pOpcode[i]);
    }
}

// �����ָ��ת���ɻ����벢д��
BOOL CDebug::ChangeAsmCode(HANDLE hProcess)
{
   
    ks_engine* pEngine = NULL;
    // ��ʼ���������
    if (KS_ERR_OK != ks_open(KS_ARCH_X86, KS_MODE_32, &pEngine))
    {
        printf("����������ʼ��ʧ��\n");
        return 0;
    }

    int nRet = 0;					// ���溯���ķ���ֵ�������жϺ����Ƿ�ִ�гɹ�
    unsigned char* opcode = NULL;	// ���õ���opcode�Ļ������׵�ַ
    unsigned int nOpcodeSize = 0;	// ��������opcode���ֽ���
    size_t stat_count = 0;			// ����ɹ�����ָ�������

// ������ָ��
// ����ʹ�÷ֺţ����߻��з���ָ��ָ���
    CHAR szAsmCode[MAX_PATH] = { 0 };
    DWORD dwVirtualAddr = 0;
    printf("����Ҫд��ĵ�ַ:\n");
    scanf_s("%x", &dwVirtualAddr);
    getchar();
    while (TRUE)
    {

        gets_s(szAsmCode, MAX_PATH);
        

        nRet = ks_asm(pEngine, szAsmCode,
            dwVirtualAddr,	/*���ָ�����ڵĵ�ַ*/
            &opcode,		/*�����opcode*/
            &nOpcodeSize,	/*�����opcode���ֽ���*/
            &stat_count		/*����ɹ�����ָ�������*/);

        // ����ֵ����-1ʱ ������
        if (nRet == -1) {
            // ���������Ϣ
            printf("������Ϣ��%s\n", ks_strerror(ks_errno(pEngine)));
            // ����ֽ���
            memset(szAsmCode, 0, MAX_PATH);
        }

        printf("һ��ת����%d��ָ��\n", stat_count);

        // ��ӡ��������opcode
        printOpcode(opcode, nOpcodeSize);

        SIZE_T dwSize = 0;
        WriteProcessMemory(hProcess,(PDWORD)dwVirtualAddr, opcode, nOpcodeSize, &dwSize);
        break;

    }
    // �ͷſռ�
    ks_free(opcode);
    // �رվ��
    ks_close(pEngine);


    return 0;
}

// �޸ļĴ�����ֵ��û����[����]
BOOL CDebug::ChangeRegister(HANDLE hThread)
{
    CONTEXT Context = { CONTEXT_FULL };
    GetThreadContext(hThread, &Context);
    char Buffer[10] = { 0 };
    DWORD Data = 0;
    printf("������Ҫ�޸ĵļĴ���\n");
    scanf_s("%s", Buffer, 10);
    if (strcmp("Eax", Buffer) == 0)
    {
        printf("������Ҫ�޸ĵ�ֵ\n");
        scanf_s("%08x", &Data);
        Context.Eax = Data;
    }
    else if (strcmp("Ebx", Buffer)==0)
    {
        printf("������Ҫ�޸ĵ�ֵ\n");
        scanf_s("%08x", &Data);
        Context.Ebx = Data;
    }
    else if (strcmp("Ecx", Buffer)==0)
    {
        printf("������Ҫ�޸ĵ�ֵ\n");
        scanf_s("%08x", &Data);
        Context.Ecx = Data;
    }
    else if (strcmp("Edx", Buffer)==0)
    {
        printf("������Ҫ�޸ĵ�ֵ\n");
        scanf_s("%08x", &Data);
        Context.Edx = Data;
    }
    else if (strcmp("Edi", Buffer)==0)
    {
        printf("������Ҫ�޸ĵ�ֵ\n");
        scanf_s("%08x", &Data);
        Context.Edi = Data;
    }
    else if (strcmp("Esi", Buffer)==0)
    {
        printf("������Ҫ�޸ĵ�ֵ\n");
        scanf_s("%08x", &Data);
        Context.Esi = Data;
    }
    else if (strcmp("Eip", Buffer)==0)
    {
        printf("������Ҫ�޸ĵ�ֵ\n");
        scanf_s("%08x", &Data);
        Context.Eip = Data;
    }
    else if (strcmp("Esp", Buffer)==0)
    {
        printf("������Ҫ�޸ĵ�ֵ\n");
        scanf_s("%08x", &Data);
        Context.Esp = Data;
    }
    printf("�޸ļĴ���%s�ɹ�\n", Buffer);
    SetThreadContext(hThread, &Context);
    return TRUE;
}

// ����Ӳ���ϵ�
BOOL CDebug::SetHardPoint(HANDLE hThread, PVOID address, DWORD type, DWORD len)
{
    // 1.��ȡ�߳�������
    CONTEXT ctx = { CONTEXT_DEBUG_REGISTERS }; //��ȡ�߳���������Ӳ���Ĵ���
    GetThreadContext(hThread, &ctx);
    isBa = TRUE;
    // ��ȡdr7�Ĵ���
    DBG_REG7* dr7 = (DBG_REG7*)(&ctx.Dr7);
    printf("%d\n", m_FalgsBa);
    // ����Ӳ���ϵ�
    if (dr7->L0 == 0) // ��һ�����ԼĴ����Ƿ�ʹ��
    {
        ctx.Dr0 = (DWORD)address;
        dr7->L0 = 1;    //����dr0Ӳ���ϵ�
        dr7->RW0 = type; // ִ�жϵ� 0 
        dr7->LEN0 = len; // ����Ҳ�� 0
        m_FalgsBa = 1;
    }
    else if (dr7->L1 == 0)
    {
        ctx.Dr1 = (DWORD)address;
        dr7->L1 = 1;    //����dr0Ӳ���ϵ�
        dr7->RW1 = type; // ִ�жϵ� 0 
        dr7->LEN1 = len; // ����Ҳ�� 0
        m_FalgsBa = 2;
    }
    else if (dr7->L2 == 0)
    {
        ctx.Dr2 = (DWORD)address;
        dr7->L2 = 1;    //����dr0Ӳ���ϵ�
        dr7->RW2 = type; // ִ�жϵ� 0 
        dr7->LEN2 = len; // ����Ҳ�� 0
        m_FalgsBa = 3;
    }

    else if (dr7->L3 == 0)
    {
        ctx.Dr3 = (DWORD)address;
        dr7->L3 = 1;    //����dr0Ӳ���ϵ�
        dr7->RW3 = type; // ִ�жϵ� 0 
        dr7->LEN3 = len; // ����Ҳ�� 0
        m_FalgsBa = 4;
    }

    // 3.���û��߳�ȥ
    SetThreadContext(hThread, &ctx);
    return true;
}

// ������ȡ��һ��ָ��
LPVOID CDebug::NextAsm(HANDLE hProcess, PVOID address, DWORD len )
{
    char opcode[4096] = {};
    DWORD dwSize;
    // 1.��ȡĿ������ڴ�����
    ReadProcessMemory(hProcess, address, opcode, sizeof(opcode), &dwSize);
    // 2.���������

    csh handle;   // �����������
    cs_err err;   // ������Ϣ
    cs_insn* pInsn; // ���淴���õ���ָ��Ļ������׵�ַ
    unsigned int count = 0; // ����õ��ķ�����ָ������


    //��ʼ������������,(x86_64�ܹ�,32λģʽ,���)
    err = cs_open(CS_ARCH_X86,  /*x86ָ�*/
        CS_MODE_32, /*ʹ��32λģʽ����opcode*/
        &handle /*����ķ������*/
    );

    if (err != CS_ERR_OK)
    {
        printf("��ʼ������������ʧ��:%s\n", cs_strerror(err));
        return 0;
    }


    // ��ʼ�����.
    // �����᷵���ܹ��õ��˼������ָ��
    count = cs_disasm(handle,       /*����������,��cs_open�����õ�*/
        (const uint8_t*)opcode,     /*��Ҫ������opcode�Ļ������׵�ַ*/
        sizeof(opcode),             /*opcode���ֽ���*/
        (uint64_t)address,          /*opcode�����ڵ��ڴ��ַ*/
        len,                        /*��Ҫ������ָ������,�����0,�򷴻���ȫ��*/
        &pInsn                      /*��������*/
    );


    LPVOID NextInfo;
    NextInfo = (LPVOID)pInsn[1].address;


    // �ͷű���ָ��Ŀռ�
    cs_free(pInsn, count);

    // �رվ��
    cs_close(&handle);

    return NextInfo;
}

// �ظ�Ӳ���ϵ�
VOID CDebug::HardBreakReply(HANDLE hThread,HANDLE hProcess, LPVOID ExceptionAddress)
{
    // ԭ���� Dr7 ���õ�Ӳ���ϵ����ʱ�� Dr6 �Ĵ�����
    //	���4λ��ʶ��ǰ���µ�����һ��Ӳ���ϵ㣬ֻҪ����Ӧ
    //	Dr7.LN ���ó� 0 �Ϳ��Թر���
   
    CONTEXT context = { CONTEXT_DEBUG_REGISTERS| CONTEXT_FULL };
    GetThreadContext(hThread, &context);
    _DBG_REG6* dr6 = (_DBG_REG6*)&context.Dr6;
    _DBG_REG7* dr7 = (_DBG_REG7*)&context.Dr7;
    LPVOID address = 0;
    if (dr6->B0 == 1 || dr6->B1 == 1 || dr6->B2 == 1 || dr6->B3 == 1)
    {
        switch (context.Dr6 & 0x0F)
        {
        case 1:dr7->L0 = 0;  m_FalgsBa = 1; break;
        case 2:dr7->L1 = 0;  m_FalgsBa = 2; break;
        case 4:dr7->L2 = 0;  m_FalgsBa = 3; break;
        case 8:dr7->L3 = 0;  m_FalgsBa = 4; break;
        }
        m_isInput = TRUE;
        IsContinueExcepiton = DBG_CONTINUE;
        // Ӧ������
        SetThreadContext(hThread, &context);
        DisAsm(hProcess, ExceptionAddress);
        SetTF(hThread);
        isBa = TRUE;
    }
}

// ��ȡ��ǰָ��ĳ���[����][û��������]
DWORD CDebug::AsmLen(HANDLE hProcess, PVOID address)
{
    char opcode[4096] = {};
    DWORD dwSize;
    // 1.��ȡĿ������ڴ�����
    ReadProcessMemory(hProcess, address, opcode, sizeof(opcode), &dwSize);
    // 2.���������

    csh handle;   // �����������
    cs_err err;   // ������Ϣ
    cs_insn* pInsn; // ���淴���õ���ָ��Ļ������׵�ַ
    unsigned int count = 0; // ����õ��ķ�����ָ������


    //��ʼ������������,(x86_64�ܹ�,32λģʽ,���)
    err = cs_open(CS_ARCH_X86,  /*x86ָ�*/
        CS_MODE_32, /*ʹ��32λģʽ����opcode*/
        &handle /*����ķ������*/
    );

    if (err != CS_ERR_OK)
    {
        printf("��ʼ������������ʧ��:%s\n", cs_strerror(err));
        return 0;
    }


    // ��ʼ�����.
    // �����᷵���ܹ��õ��˼������ָ��
    count = cs_disasm(handle,       /*����������,��cs_open�����õ�*/
        (const uint8_t*)opcode,     /*��Ҫ������opcode�Ļ������׵�ַ*/
        sizeof(opcode),             /*opcode���ֽ���*/
        (uint64_t)address,          /*opcode�����ڵ��ڴ��ַ*/
        5,                        /*��Ҫ������ָ������,�����0,�򷴻���ȫ��*/
        &pInsn                      /*��������*/
    );
    return pInsn[0].size;
}

// ��ʾ�ڴ�(������)[�Ѹ�]
BOOL CDebug::PrintMemory(HANDLE hProcess, PVOID address)
{
    BYTE opcode[0x100] = {0};
    DWORD dwSize;
    // 1.��ȡĿ������ڴ�����
    ReadProcessMemory(hProcess, address, opcode, sizeof(opcode), &dwSize);
    for (int i = 0; i < 0x10; i++)
    {
        printf("%08X| ", (DWORD)address + i * 0x10);
        for (int j = 0; j < 0x10; j++)
        {
            printf("%02X ",opcode[i * 0x10 + j]);
        }
            printf("\n");
    }
    return TRUE;
}

// �޸��ڴ�
BOOL CDebug::ChangeMemory(HANDLE hProcess, PVOID address,BYTE Data)
{
    DWORD dwSize;
    DWORD oldProtect;
    // ����ҳ������
    VirtualProtectEx(hProcess, address, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    if(!WriteProcessMemory(hProcess, address,&Data,1,&dwSize))
    return FALSE;
    VirtualProtectEx(hProcess, address, 1, oldProtect, &oldProtect);
    return TRUE;
}

// ���������ϵ�
BOOL CDebug::SetConBreak(HANDLE hProcess,LPVOID pAddress,DWORD Data)
{
    DWORD dwSize = 0;
    // ��ȡ�����ڴ棬����һ���ֽڵ�����
    ReadProcessMemory(hProcess, pAddress, &ConBreak.data, 1, &dwSize);
    ConBreak.address = pAddress;
    ConBreak.enable = TRUE;
    ConBreakData = Data;
    // ���ĵ�ַ���0xCC
    if (!WriteProcessMemory(hProcess, pAddress, "\xCC", 1, &dwSize))
        return FALSE;
    return TRUE;
}

// �ظ������ϵ�
VOID CDebug::ConBreakHandle(HANDLE hThread,HANDLE hProcess, LPVOID ExceptionAddress)
{
    if (ConBreak.enable == TRUE)
    {
        //����ϵ��쳣����
        DWORD dwSize;
        // 1.��ԭʼ����д�ص��ϵ�λ����
        WriteProcessMemory(hProcess, ConBreak.address, &ConBreak.data, 1, &dwSize);

        // 2.��Ҫ��eip -1 �˻ص�ָ������λ��
        CONTEXT ctx = { CONTEXT_FULL }; //��ȡ�߳��������е�ͨ�üĴ���
        GetThreadContext(hThread, &ctx);
        ctx.Eip -= 1;
        //���û��߳�ȥ
        SetThreadContext(hThread, &ctx);
        if (ctx.Eax == ConBreakData)
        {
            // �����
            DisAsm(ProcessInfo.hProcess, ExceptionAddress);
            // �ϵ������ǲ����ģ���Ҫ��������
            m_isInput = TRUE;

            // ���������Զϵ㣬����һ���������ڵ����лָ�����ϵ�CC
            SetTF(hThread);
        }
        m_FlagsCon = TRUE;
        SetTF(hThread);

    }
    IsContinueExcepiton = DBG_CONTINUE;
    return ;
}

// ��ʾģ����Ϣ
VOID CDebug::AllModule(HANDLE hProcess)
{
    WCHAR ModulePath[MAX_PATH];
    DWORD ProcessId=GetProcessId(hProcess);
    // 1. ���㵱ǰAPI����ʱ��ģ����գ���������Ҫ����ģ��Ľ���id
    HANDLE SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessId);
    // 2. ������մ���ʧ�ܣ��ͻ᷵�� INVALID_HANDLE_VALUE(-1)
    if (SnapshotHandle != INVALID_HANDLE_VALUE)
    {
        // 3. ����ṹ�壬���ڱ���������Ŀ��յ���Ϣ����Ҫ��ʼ��
        MODULEENTRY32 ModuleInfo = { sizeof(ModuleInfo) };

        // 4. ������ջ�ȡ�ɹ����ͳ��Դӿ����л�ȡ��һ��ģ�����Ϣ
        if (Module32First(SnapshotHandle, &ModuleInfo))
        {
            do {
                /*
                    th32ProcessID;      ӵ�и�ģ��Ľ��̵� id*3
                    modBaseAddr;        ģ���ڽ��������ڴ��еĵ�ַ(���ػ�ַ)
                    modBaseSize;        ģ����ռ�õ��ڴ��С*2
                    hModule;            ģ��ľ����ʵ�ʺͼ��ػ�ַ��һ����
                    szModule			ģ�������*1
                    szExePath			ģ�����ڵ�·��
                */
                printf("%08X: |",ModuleInfo.modBaseAddr);
                wprintf(L"%s ",ModuleInfo.szModule);
                GetModuleFileName(ModuleInfo.hModule, ModulePath, MAX_PATH);
                wprintf(L"%s\n", ModulePath);
                // 6. �����ǰ�����ɹ�����ô�ͼ���������һ��
            } while (Module32Next(SnapshotHandle, &ModuleInfo));
        }
    }

    CloseHandle(SnapshotHandle);

    return ;
}

// ����PEB[������][�Ѹ�]
BOOL CDebug::HidePEB(DEBUG_EVENT* dbg)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dbg->dwProcessId);
    const WCHAR PATH[] = L"C:\\Users\\1\\Desktop\\��������Ŀ\\��������Ŀ\\Debug\\funhook.dll";
    DWORD Size = sizeof(PATH);
    /*
     �����ڴ�ռ�
    */
    LPVOID VirPath = VirtualAllocEx(hProcess, 0, Size, MEM_COMMIT, PAGE_READWRITE);
    /*
     ��·��д���ڴ�ռ�
    */
    SIZE_T realSize = 0;
    WriteProcessMemory(hProcess, VirPath, PATH, Size, &realSize);
    /*
     2.��ָ�����̴����߳�
    */
    HANDLE ThreadHandle = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, VirPath, NULL, NULL);

    // WaitForSingleObject(ThreadHandle, -1);
    CloseHandle(hProcess);
    return TRUE;
}

// ��ȡ������
BOOL CDebug::GetSymName(HANDLE hProcess, SIZE_T nAddress, CString& strName)
{
    DWORD64 dwDisplacement = 0;
    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;
    // ���ݵ�ַ��ȡ������Ϣ
    if (!SymFromAddr(hProcess, nAddress, &dwDisplacement, pSymbol))
        return FALSE;
    strName = pSymbol->Name;
    return TRUE;
}

// ��ʾջ
BOOL CDebug::PrintStack(HANDLE hProcess,HANDLE hThread)
{
    
    CONTEXT ct = { 0 };
    ct.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(hThread, &ct);
    BYTE Buffer[512];
    DWORD dwRead = 0;
    ReadProcessMemory(hProcess, (LPVOID)ct.Esp, Buffer, 512, &dwRead);
    for (int i = 0; i< 10; i++)
    {
        printf("%08X\n", ((DWORD*)Buffer));
    }
    return TRUE;
}

// ��ȡ�ļ���Ϣ
BOOL CDebug::GetPEInfo(WCHAR* szTargetPath)
{
    /*
     1. ����·�����ļ����
    */
    HANDLE FileHandle = CreateFile(szTargetPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    /*
     2.��ȡ�ļ���С������ѿռ�
    */
    DWORD FileSize = GetFileSize(FileHandle, NULL);
    FileBase = new BYTE[FileSize]{ };
    DWORD ReadBytes = 0;
    ReadFile(FileHandle, FileBase, FileSize, &ReadBytes, NULL);

    /*
     3.��ȡDOSͷλ��
    */
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)FileBase;
    /*
     4.����ƫ�ƻ�ȡNTͷλ�ã��������������Ӧ�ı༭����
    */
    CString CBuffer;
    NtHeader = (PIMAGE_NT_HEADERS)(FileBase + DosHeader->e_lfanew);

    return TRUE;
}

// �ؼ�APIHook
BOOL CDebug::APIHook(DEBUG_EVENT* dbg)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dbg->dwProcessId);
    const WCHAR PATH[] = L"C:\\Users\\1\\Desktop\\��������Ŀ\\��������Ŀ\\Debug\\APIHook.dll";
    DWORD Size = sizeof(PATH);
    /*
     �����ڴ�ռ�
    */
    LPVOID VirPath1 = VirtualAllocEx(hProcess, 0, Size, MEM_COMMIT, PAGE_READWRITE);
    /*
     ��·��д���ڴ�ռ�
    */
    SIZE_T realSize = 0;
    WriteProcessMemory(hProcess, VirPath1, PATH, Size, &realSize);
    /*
     2.��ָ�����̴����߳�
    */
    HANDLE ThreadHandle = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, VirPath1, NULL, NULL);

    CloseHandle(hProcess);
    return TRUE;
}

// ����API�ϵ�
SIZE_T CDebug::FindApiAddress(HANDLE hProcess, const char* pszName)
{
    char Buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)Buffer;
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;
    // �������ֲ�ѯ������Ϣ�������pSymbol��
    if (!SymFromName(hProcess, pszName, pSymbol))
        return 0;
    return (SIZE_T)pSymbol->Address;
}

// ����ģ����Ϣ����ֵ�ṹ��
BOOL CDebug::AllMoudlesList(HANDLE hProcess)
{
    PE_Struct Info;
    WCHAR ModulePath[MAX_PATH];
    WCHAR ModuleName[MAX_PATH];
    DWORD ProcessId = GetProcessId(hProcess);
    // 1. ���㵱ǰAPI����ʱ��ģ����գ���������Ҫ����ģ��Ľ���id
    HANDLE SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessId);
    // 2. ������մ���ʧ�ܣ��ͻ᷵�� INVALID_HANDLE_VALUE(-1)
    if (SnapshotHandle != INVALID_HANDLE_VALUE)
    {
        // 3. ����ṹ�壬���ڱ���������Ŀ��յ���Ϣ����Ҫ��ʼ��
        MODULEENTRY32 ModuleInfo = { sizeof(ModuleInfo) };

        // 4. ������ջ�ȡ�ɹ����ͳ��Դӿ����л�ȡ��һ��ģ�����Ϣ
        if (Module32First(SnapshotHandle, &ModuleInfo))
        {
            do {
                /*
                    th32ProcessID;      ӵ�и�ģ��Ľ��̵� id*3
                    modBaseAddr;        ģ���ڽ��������ڴ��еĵ�ַ(���ػ�ַ)
                    modBaseSize;        ģ����ռ�õ��ڴ��С*2
                    hModule;            ģ��ľ����ʵ�ʺͼ��ػ�ַ��һ����
                    szModule			ģ�������*1
                    szExePath			ģ�����ڵ�·��
                */
                GetModuleFileName(ModuleInfo.hModule, ModulePath, MAX_PATH);
                GetModuleBaseName(hProcess, ModuleInfo.hModule, ModuleName, MAX_PATH); //��ȡģ������
                Info.dllBase = (DWORD)ModuleInfo.modBaseAddr;
                wcscpy_s(Info.Name,MAX_PATH,ModuleName);
                wcscpy_s(Info.Path, MAX_PATH, ModulePath);
                ModuleList.push_back(Info);
                // 6. �����ǰ�����ɹ�����ô�ͼ���������һ��
            } while (Module32Next(SnapshotHandle, &ModuleInfo));
        }
    }

    CloseHandle(SnapshotHandle);

    return TRUE;
}

// ����ָ��ģ����Ϣ
BOOL CDebug::ExportFunc()
{
    DWORD ImTable;
    printf("�������ַ\n");
    scanf_s("%08X", &ImTable);
    WCHAR Path[MAX_PATH];
    for (int i = 0; i < ModuleList.size(); i++)
    {
        if (ImTable - ModuleList[i].dllBase == 0)
        {
            wcscpy_s(Path, MAX_PATH, ModuleList[i].Path);
        }
    }
    GetPEInfo(Path);
    /*
     ����ȡ����16����������ת��Ϊ�����ṹ��ָ��
    */
    AllExportDll(NtHeader, FileBase);
    ImportFunc(NtHeader, FileBase);
    return TRUE;
}