#include "CDebug.h"
#include "capstone/include/capstone.h"
#include<iostream>
#include"RegStruct.h"
#include"ImportAndExport.h"
#include<Dbghelp.h>
#include<psapi.h>
// #include "RegStruct.h"
//1. 包含头文件
#include "keystone/keystone.h"
#include<TlHelp32.h>

#include<DbgHelp.h>
#pragma comment(lib,"Dbghelp.lib")

//2. 包含静态库
#pragma comment (lib,"keystone/x86/keystone_x86.lib")
#pragma comment (lib,"Dbghelp.lib")

//1. 包含头文件
#ifdef _WIN64 // 64位平台编译器会自动定义这个宏
#pragma 
comment(lib, "capstone/lib/capstone_x64.lib")
#else
#pragma comment(lib,"capstone/lib/capstone_x86.lib")
#endif // _64

// 创建进程
BOOL CDebug::Create_Process(CHAR* szTargetPath)
{
    STARTUPINFOA si = { sizeof(si) };
    BOOL bRet;
    if (isAct == 0)
    {
        //1.以调试方式创建目标程序
         bRet = CreateProcessA(
            szTargetPath,        //进程路径
            NULL,               //命令行
            NULL,              //进程安全属性
            NULL,              //线程安全属性               
            FALSE,             //是否继承句柄表
            DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,//创建标志
            NULL,              //环境变量
            NULL,              //工作目录
            &si,               //启动信息
            &ProcessInfo       //创建后进程信息
        );
    }
    else if(isAct == 1)
    {
        DWORD Pid = 0;
        sscanf_s(szTargetPath,"%d", &Pid);
       // 附加方式
       bRet = DebugActiveProcess(Pid);
    }

    return  bRet;
}

// 等待调试事件
VOID CDebug::DebugEventLoop()
{
    // 函数主要分有3个部分：1.等待调试事件，2.处理调试事件，3.回复调试事件
    DWORD bRet = 0;
    DEBUG_EVENT dbgEvent = { 0 };
    DWORD dwReCode = DBG_CONTINUE;
    int idex = 0;
    while (TRUE)
    {
        // 1.等待调试事件
        bRet = WaitForDebugEvent(&dbgEvent, -1);
        
        if (bRet == FALSE)return;
        // 2.处理调试事件
        switch (dbgEvent.dwDebugEventCode)
        {
            // 异常调试事件
        case EXCEPTION_DEBUG_EVENT: 
            dwReCode = Exception_Handler(&dbgEvent);
            break;
            // 创建线程事件
        case CREATE_THREAD_DEBUG_EVENT:
            printf("线程创建\n");
            break;
            // 创建进程事件
        case CREATE_PROCESS_DEBUG_EVENT:
            printf("请选择破解方式：1.隐藏PEB 2.hook关键API\n");
            scanf_s("%d", &idex);
            if(idex==1)
            HidePEB(&dbgEvent);
            else if(idex==2)
            APIHook(&dbgEvent);
            dbgEvent.u.CreateProcessInfo;  // 获取进程相关信息
            printf("进程创建事件 : 入口0X%08x\n",
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
                // 保存程序入口点 m_Oep
                OEP = dbgEvent.u.CreateProcessInfo.lpStartAddress;
                // 在OEP设置一个软件断点
                SetINT3(ProcessInfo.hProcess, OEP);
            }
            break;
            // 退出线程事件
        case EXIT_THREAD_DEBUG_EVENT:
            printf("线程退出事件\n");
            break;
            // 退出进程事件
        case EXIT_PROCESS_DEBUG_EVENT:
            printf("进程退出\n");
            return;
            break;
            // 加载模块事件
        case LOAD_DLL_DEBUG_EVENT:
            printf("模块加载事件: DLLBASE: 0X%08x\n",
                dbgEvent.u.LoadDll.lpBaseOfDll);
            break;
            // 卸载模块事件
        case UNLOAD_DLL_DEBUG_EVENT:    
            break;
            // 调试信息
        case OUTPUT_DEBUG_STRING_EVENT:    
            break;
        case RIP_EVENT:     
            break;
        }
        // 3.回复调试子系统
        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, dwReCode);
    }
    // 关闭进程线程句柄
    CloseHandle(ProcessInfo.hProcess);
    CloseHandle(ProcessInfo.hThread);

    return VOID();
}

// 反汇编转换
VOID CDebug::DisAsm(HANDLE hProcess, PVOID address, DWORD len)
{
    char opcode[4096] = {};
    DWORD dwSize;
    // 1.读取目标进程内存数据
    ReadProcessMemory(g_hProcess, address, opcode, sizeof(opcode), &dwSize);
    // 2.反汇编数据

    csh handle;   // 反汇编引擎句柄
    cs_err err;   // 错误信息
    cs_insn* pInsn; // 保存反汇编得到的指令的缓冲区首地址
    unsigned int count = 0; // 保存得到的反汇编的指令条数


    //初始化反汇编器句柄,(x86_64架构,32位模式,句柄)
    err = cs_open(CS_ARCH_X86,  /*x86指令集*/
        CS_MODE_32, /*使用32位模式解析opcode*/
        &handle /*输出的反汇编句柄*/
    );

    if (err != CS_ERR_OK)
    {
        printf("初始化反汇编器句柄失败:%s\n", cs_strerror(err));
        return ;
    }

    

    // 开始反汇编.
    // 函数会返回总共得到了几条汇编指令
    count = cs_disasm(handle,       /*反汇编器句柄,从cs_open函数得到*/
        (const uint8_t*)opcode,     /*需要反汇编的opcode的缓冲区首地址*/
        sizeof(opcode),             /*opcode的字节数*/
        (uint64_t)address,          /*opcode的所在的内存地址*/
        len,                        /*需要反汇编的指令条数,如果是0,则反汇编出全部*/
        &pInsn                      /*反汇编输出*/
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
        // 输出对应的反汇编
        printf("\t%s %s", pInsn[i].mnemonic, pInsn[i].op_str);
        CString funcName;
        if(GetSymName(g_hProcess, pInsn[i].address, funcName))
            printf("   %s", (CStringA)funcName);
        printf("\n");
    }


    printf("\n");

    // 释放保存指令的空间
    cs_free(pInsn, count);

    // 关闭句柄
    cs_close(&handle);

}

// 异常处理
DWORD CDebug::Exception_Handler(DEBUG_EVENT* dbg)
{
    // 异常信息
    EXCEPTION_RECORD Record = dbg->u.Exception.ExceptionRecord;
    // 异常触发的地址
    LPVOID ExceptionAddress = Record.ExceptionAddress;
    // 异常类型
    DWORD ExceptionCode = Record.ExceptionCode;
    // 打开进程句柄
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dbg->dwProcessId);
    // 打开线程句柄
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbg->dwThreadId);
    
    g_hProcess = hProcess;
    switch (ExceptionCode)
    {
        // 软件断点：
    case EXCEPTION_BREAKPOINT:
    {
        // 系统第一次会触发一个软件异常，NTDLL中触发的，系统断点
        static bool isSystemBreakPorint = TRUE;
        // 这是第一次进入异常，是系统断点
        if (isSystemBreakPorint == TRUE) 
        {
            // 之后不在是系统断点了
            isSystemBreakPorint = FALSE; 
            printf("系统断点 异常地址： 0x%08x\n", ExceptionAddress);

            // 异常不是我们产生的
            IsContinueExcepiton = DBG_EXCEPTION_NOT_HANDLED;
            // 断点不是我们产生的，不需要接受输入
            m_isInput = FALSE;
            AllMoudlesList(hProcess);
            break;
        }
        if (SymbolSign == FALSE)
        {
            SymbolSign = TRUE;
            BOOL a=SymInitialize(hProcess, 0, TRUE);
        }
        // 我们自己设置的永久INT3软件断点的处理
        ConBreakHandle(hThread, hProcess, ExceptionAddress);
        if (m_FlagsCon == TRUE)
            break;
        INT3Handle(hProcess,hThread,ExceptionAddress);
    }break;
    // 单步异常/硬件异常
    case EXCEPTION_SINGLE_STEP:         
    {
        // 不同断点处理
        BreakHandle(hProcess,hThread, ExceptionAddress, Record);
    }break;
    //内存访问异常
    case EXCEPTION_ACCESS_VIOLATION:   
        MemoryBreakHandle(hProcess, hThread, ExceptionAddress,Record);
        break;
    default:break;
    }

    // 是否接受用户输入
    UserInput(hProcess, hThread, ExceptionAddress);
    
    // 关闭进程句柄
    CloseHandle(hProcess);
    // 关闭线程句柄
    CloseHandle(hThread);


    return IsContinueExcepiton;
}

// 不同断点处理
VOID CDebug::BreakHandle(HANDLE hProcess,HANDLE hThread, LPVOID ExceptionAddress, EXCEPTION_RECORD Record)
{
    // 1. 是否是软件断点恢复永久性的单步(INT3)
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

    // 2. 是否普通单步（TF）
    if (m_FlagsTF)
    {
        m_FlagsTF = FALSE;
        // 输出单步信息
        DisAsm(hProcess, ExceptionAddress);
        //需要输入
        m_isInput = TRUE;
        IsContinueExcepiton = DBG_CONTINUE;
    }
     // 3.是否是内存访问断点
    if (m_FlagsMemory==TRUE)
    {
        m_FlagsMemory = FALSE;
        // 修改页面属性
        VirtualProtectEx(hProcess, MemoryBreakData.paddress, MemoryBreakData.len, PAGE_NOACCESS, &MemoryBreakData.oldProtect);
        //需要输入
        m_isInput = FALSE;
        IsContinueExcepiton = DBG_CONTINUE;
    }
    // 4. 是否是硬件断点
    if (isBa==TRUE)
    {
        isBa = FALSE;
        // 获取到调试寄存器
        CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
        GetThreadContext(hThread, &context);

        // 获取调试寄存器中的 Dr7

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
    // 5.是否是条件断点
    if (m_FlagsCon)
    {
        m_FlagsCon = FALSE;
        DWORD dwSize;
        WriteProcessMemory(hProcess, ConBreak.address, "\xCC", 1, &dwSize);
        m_isInput = FALSE;
        IsContinueExcepiton = DBG_CONTINUE;
    }
}

// 接受用户输入
VOID CDebug::UserInput(HANDLE hProcess, HANDLE hThread, LPVOID ExceptionAddress)
{
    // 是否要接受输入
    if (m_isInput)
    {
        char buff[1024];
        while (TRUE)
        {
            printf("<< ");
            gets_s(buff, 1024);

            //解析命令
            char cmd[100] = {};
            sscanf_s(buff, "%s", cmd, 100);
            // 运行指令
            if (strcmp("g", cmd) == 0)
            {
                //程序运行
                break;
            }
            // 软件断点 0x4118cb
            if (strcmp("bp", cmd) == 0)
            {
                LPVOID address = 0;
                if (2 == sscanf_s(buff, "%s %x", cmd, 100, &address))
                {
                    SetINT3(hProcess, address);
                    printf("设置成功\n");
                }
            }
            // 单步走
            if (strcmp("t", cmd) == 0)
            {
                SetTF(hThread);
                m_FlagsTF = TRUE;
                break;
            }
            // 内存访问断点
            if (strcmp("bm", cmd) == 0)
            {
                LPVOID address = 0;
                if (2 == sscanf_s(buff, "%s %x", cmd, 100, &address))
                {
                    DWORD bm_Type = 0;
                    scanf_s("%d", &bm_Type);
                    SetMemoryBreak(hProcess, address, bm_Type);
                    printf("设置成功\n");
                }
            }
            // 修改内存
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
            // 查看寄存器
            if (strcmp("r", cmd) == 0)
            {
                CONTEXT Context = { CONTEXT_FULL };
                GetThreadContext(hThread, &Context);
                printf(" Eax:%08X   Ebx:%08X   Ecx:%08X\n ", Context.Eax, Context.Ebx, Context.Ecx);
                printf("Edx:%08X   Edi:%08X   Esi:%08X\n ", Context.Edx, Context.Edi, Context.Esi);
                printf("Eip:%08X   Eflags:%08X   Esp:%08X\n", Context.Eip, Context.EFlags, Context.Esp);
            }
            // 设置硬件断点
            if (strcmp("ba", cmd) == 0)
            {
                PVOID address = 0;
                DWORD m_Type = 3;
                if (2 == sscanf_s(buff, "%s %x ", cmd, 100, &address))
                {
                    scanf_s("%d", &m_Type);
                    SetHardPoint(hThread, address, m_Type);
                    printf("设置硬件断点成功\n");
                }
            }
            // 单步步过
            if (strcmp("p", cmd) == 0)
            {
                LPVOID Next= NextAsm(hProcess, ExceptionAddress);
                SetINT3(hProcess, Next);
                break;
            }
            // 显示断点信息
            if (strcmp("bl", cmd) == 0)
            {
                printf("软件断点：\n");
                for (int i = 0; i < INT3List.size(); i++)
                {
                    printf("[%d]:   %08X\n", i, INT3List[i].address);
                } 
                CONTEXT ctx = { CONTEXT_DEBUG_REGISTERS }; //获取线程上下文中硬件寄存器
                GetThreadContext(hThread, &ctx);
                printf("硬件断点：");
                _DBG_REG7* dr7 = (_DBG_REG7*)&ctx.Dr7;
                if (dr7->L0 != 0 || dr7->L1 != 0 || dr7->L2 != 0 || dr7->L3 != 0)
                    printf("Dr7->L%d:%08X\n", (m_FalgsBa - 1), ctx.Dr0);
                else
                    printf("\n");
                printf("内存断点：");
                printf("%08X\n", MemoryBreakData.paddress);
            }
            // 删除断点
            if (strcmp("bc", cmd) == 0)
            {
                char BreakInfo[1024];
                printf("请输入要删除的断点属性：bm：内存断点，ba：硬件断点，bp：软件断点\n");
                scanf_s("%s", BreakInfo,1024);
                if (strcmp("bm", BreakInfo) == 0)
                {
                    // 修改页面属性
                    VirtualProtectEx(hProcess, MemoryBreakData.paddress, MemoryBreakData.len, m_oldProtect, &MemoryBreakData.oldProtect);
                    m_FlagsMemory = FALSE;
                    printf("删除内存断点成功");
                }
                else if (strcmp("bp", BreakInfo) == 0)
                {
                    int idex = 0;
                    printf("请输入你要删除第几项：\n");
                    scanf_s("%d", &idex);
                    // 将原始数据写回 opcode 
                    DWORD dwSize = 0;
                    WriteProcessMemory(hProcess, INT3List[idex].address,
                        &INT3List[idex].data, 1, &dwSize);
                    // 将断点从断点列表中移除
                    INT3List.erase(INT3List.begin() + idex);
                    printf("取消断点成功\n");
          
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
                    printf("删除硬件断点成功\n");
                }
                
            }
            // 显示内存
            if (strcmp("d", cmd) == 0)
            {
                PVOID address = 0;
                if (2 == sscanf_s(buff, "%s %x", cmd, 100, &address))
                PrintMemory(hProcess, address);
            }
            // 修改内存
            if (strcmp("e", cmd) == 0)
            {
                BYTE Data;
                PVOID address = 0;
                if (2 == sscanf_s(buff, "%s %x", cmd, 100, &address))
                {
                    scanf_s("%02X", &Data);
                    if(ChangeMemory(hProcess, address, Data))
                    printf("修改内存成功\n");
                }
            }
            // 修改寄存器
            if (strcmp("cr", cmd) == 0)
            {
                ChangeRegister(hThread);
            }
            // 条件断点
            if (strcmp("co", cmd) == 0)
            {
                PVOID address = 0;
                DWORD Data = 0;
                printf("请输入地址\n");
                scanf_s("%x", &address);
                printf("请输入指定的值\n");
                scanf_s("%08X", &Data);
                SetConBreak(hProcess, address, Data);
                printf("设置条件断点成功\n");
            }
            // 显示模块信息
            if (strcmp("lm", cmd) == 0)
            {
                AllModule(hProcess);
            }
            // 显示栈
            if (strcmp("pt", cmd) == 0)
            {
                PrintStack(hProcess, hThread);
            }
            // 显示指定导入表函数信息
            if (strcmp("in", cmd) == 0)
            {
                ExportFunc();
            }
            // API断点
            if (strcmp("bpa", cmd) == 0)
            {
                char Name[200] = { 0 };
                printf("请输入API函数名：\n");
                scanf_s("%s", Name, 200);
                SIZE_T addr=FindApiAddress(hProcess, Name);
                SetINT3(hProcess,(LPVOID)addr);
                printf("设置成功\n");
            }
        }
    }
}

// 设置软件断点
BOOL CDebug::SetINT3(HANDLE hProcess, LPVOID pAddress)
{
    BREAK_POINT bData = {0};
    DWORD dwSize = 0;
    // 读取进程内存，保存一个字节的数据
    ReadProcessMemory(hProcess, pAddress, &bData.data, 1, &dwSize);
    bData.address = pAddress;
    bData.enable = TRUE;
    // 往该地址填充0xCC
    if (!WriteProcessMemory(hProcess, pAddress, "\xCC", 1, &dwSize))
        return FALSE;
    INT3List.push_back(bData);
    return TRUE;
}

// INT3软件断点处理（用于显示正确的汇编代码）
BOOL  CDebug::INT3Handle(HANDLE hProcess, HANDLE hThread, LPVOID ExceptionAddress)
{

    //软件断点异常处理
    DWORD dwSize;
    // 1.将原始数据写回到断点位置上
    for (auto& bp : INT3List)
    {
        WriteProcessMemory(hProcess, bp.address, &bp.data, 1, &dwSize);
    }
    // 2.需要将eip -1 退回到指令所在位置
    CONTEXT ctx = { CONTEXT_FULL }; //获取线程上下文中的通用寄存器
    GetThreadContext(hThread, &ctx);
    ctx.Eip -= 1;
    //设置回线程去
    SetThreadContext(hThread, &ctx);

    // 反汇编
    DisAsm(ProcessInfo.hProcess, ExceptionAddress);
    IsContinueExcepiton = DBG_CONTINUE;
    // 断点是我们产生的，需要接受输入
    m_isInput = TRUE;

    // 设置永久性断点，设置一个单步，在单步中恢复软件断点CC
    SetTF(hThread);
    m_FlagsBp = TRUE;
    return TRUE;
}

// 永久内存断点处理
BOOL CDebug::MemoryBreakHandle(HANDLE hProcess, HANDLE hThread,LPVOID ExceptionAddress, EXCEPTION_RECORD Record)
{
    DWORD A = (DWORD)MemoryBreakData.paddress;
    DWORD Min = A - A%0x1000;
    DWORD Max = Min + 0x1000;
    // 判断是否在该页
    if (Record.ExceptionInformation[1] >= Min && Record.ExceptionInformation[1] < Max&& A!=0)
    {
        // 修改页面属性
        VirtualProtectEx(hProcess, MemoryBreakData.paddress, MemoryBreakData.len, m_oldProtect, &MemoryBreakData.oldProtect);
        m_FlagsMemory = TRUE;
        // 判断访问地址
        if ((PVOID)Record.ExceptionInformation[1] == MemoryBreakData.paddress && Record.ExceptionInformation[0] == MemoryBreakData.type)
        {
            // 输出单步信息
            DisAsm(hProcess, ExceptionAddress);
            //需要输入
            m_isInput = TRUE;
            // 设置永久性断点，设置一个单步，在单步中恢复软件断点CC
            SetTF(hThread);
        }
        SetTF(hThread);
        IsContinueExcepiton = DBG_CONTINUE;
        return TRUE;
    }
    else
    {
        // 输出单步信息
        DisAsm(hProcess, ExceptionAddress);
        //需要输入
        m_isInput = TRUE;
        IsContinueExcepiton = DBG_CONTINUE;
    }
}

// 设置单步断点TF
BOOL CDebug::SetTF(HANDLE hThread)
{
    // 1.获取线程上下文
    CONTEXT ctx = { CONTEXT_FULL }; //获取线程上下文中的通用寄存器
    GetThreadContext(hThread, &ctx);
    // 2.修改寄存器
    ((EFLAGS*)&ctx.EFlags)->TF = 1;
    SetThreadContext(hThread, &ctx);
    return TRUE;
}

// 设置内存访问断点
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

// 打印
void printOpcode(const unsigned char* pOpcode, int nSize)
{
    for (int i = 0; i < nSize; ++i) {
        printf("%02X ", pOpcode[i]);
    }
}

// 将汇编指令转换成机器码并写入
BOOL CDebug::ChangeAsmCode(HANDLE hProcess)
{
   
    ks_engine* pEngine = NULL;
    // 初始化汇编引擎
    if (KS_ERR_OK != ks_open(KS_ARCH_X86, KS_MODE_32, &pEngine))
    {
        printf("反汇编引擎初始化失败\n");
        return 0;
    }

    int nRet = 0;					// 保存函数的返回值，用于判断函数是否执行成功
    unsigned char* opcode = NULL;	// 汇编得到的opcode的缓冲区首地址
    unsigned int nOpcodeSize = 0;	// 汇编出来的opcode的字节数
    size_t stat_count = 0;			// 保存成功汇编的指令的条数

// 输入汇编指令
// 可以使用分号，或者换行符将指令分隔开
    CHAR szAsmCode[MAX_PATH] = { 0 };
    DWORD dwVirtualAddr = 0;
    printf("输入要写入的地址:\n");
    scanf_s("%x", &dwVirtualAddr);
    getchar();
    while (TRUE)
    {

        gets_s(szAsmCode, MAX_PATH);
        

        nRet = ks_asm(pEngine, szAsmCode,
            dwVirtualAddr,	/*汇编指令所在的地址*/
            &opcode,		/*输出的opcode*/
            &nOpcodeSize,	/*输出的opcode的字节数*/
            &stat_count		/*输出成功汇编的指令的条数*/);

        // 返回值等于-1时 汇编错误
        if (nRet == -1) {
            // 输出错误信息
            printf("错误信息：%s\n", ks_strerror(ks_errno(pEngine)));
            // 清空字节码
            memset(szAsmCode, 0, MAX_PATH);
        }

        printf("一共转换了%d条指令\n", stat_count);

        // 打印汇编出来的opcode
        printOpcode(opcode, nOpcodeSize);

        SIZE_T dwSize = 0;
        WriteProcessMemory(hProcess,(PDWORD)dwVirtualAddr, opcode, nOpcodeSize, &dwSize);
        break;

    }
    // 释放空间
    ks_free(opcode);
    // 关闭句柄
    ks_close(pEngine);


    return 0;
}

// 修改寄存器的值【没做】[已做]
BOOL CDebug::ChangeRegister(HANDLE hThread)
{
    CONTEXT Context = { CONTEXT_FULL };
    GetThreadContext(hThread, &Context);
    char Buffer[10] = { 0 };
    DWORD Data = 0;
    printf("请输入要修改的寄存器\n");
    scanf_s("%s", Buffer, 10);
    if (strcmp("Eax", Buffer) == 0)
    {
        printf("请输入要修改的值\n");
        scanf_s("%08x", &Data);
        Context.Eax = Data;
    }
    else if (strcmp("Ebx", Buffer)==0)
    {
        printf("请输入要修改的值\n");
        scanf_s("%08x", &Data);
        Context.Ebx = Data;
    }
    else if (strcmp("Ecx", Buffer)==0)
    {
        printf("请输入要修改的值\n");
        scanf_s("%08x", &Data);
        Context.Ecx = Data;
    }
    else if (strcmp("Edx", Buffer)==0)
    {
        printf("请输入要修改的值\n");
        scanf_s("%08x", &Data);
        Context.Edx = Data;
    }
    else if (strcmp("Edi", Buffer)==0)
    {
        printf("请输入要修改的值\n");
        scanf_s("%08x", &Data);
        Context.Edi = Data;
    }
    else if (strcmp("Esi", Buffer)==0)
    {
        printf("请输入要修改的值\n");
        scanf_s("%08x", &Data);
        Context.Esi = Data;
    }
    else if (strcmp("Eip", Buffer)==0)
    {
        printf("请输入要修改的值\n");
        scanf_s("%08x", &Data);
        Context.Eip = Data;
    }
    else if (strcmp("Esp", Buffer)==0)
    {
        printf("请输入要修改的值\n");
        scanf_s("%08x", &Data);
        Context.Esp = Data;
    }
    printf("修改寄存器%s成功\n", Buffer);
    SetThreadContext(hThread, &Context);
    return TRUE;
}

// 设置硬件断点
BOOL CDebug::SetHardPoint(HANDLE hThread, PVOID address, DWORD type, DWORD len)
{
    // 1.获取线程上下文
    CONTEXT ctx = { CONTEXT_DEBUG_REGISTERS }; //获取线程上下文中硬件寄存器
    GetThreadContext(hThread, &ctx);
    isBa = TRUE;
    // 获取dr7寄存器
    DBG_REG7* dr7 = (DBG_REG7*)(&ctx.Dr7);
    printf("%d\n", m_FalgsBa);
    // 设置硬件断点
    if (dr7->L0 == 0) // 第一个调试寄存器是否使用
    {
        ctx.Dr0 = (DWORD)address;
        dr7->L0 = 1;    //开启dr0硬件断点
        dr7->RW0 = type; // 执行断点 0 
        dr7->LEN0 = len; // 长度也是 0
        m_FalgsBa = 1;
    }
    else if (dr7->L1 == 0)
    {
        ctx.Dr1 = (DWORD)address;
        dr7->L1 = 1;    //开启dr0硬件断点
        dr7->RW1 = type; // 执行断点 0 
        dr7->LEN1 = len; // 长度也是 0
        m_FalgsBa = 2;
    }
    else if (dr7->L2 == 0)
    {
        ctx.Dr2 = (DWORD)address;
        dr7->L2 = 1;    //开启dr0硬件断点
        dr7->RW2 = type; // 执行断点 0 
        dr7->LEN2 = len; // 长度也是 0
        m_FalgsBa = 3;
    }

    else if (dr7->L3 == 0)
    {
        ctx.Dr3 = (DWORD)address;
        dr7->L3 = 1;    //开启dr0硬件断点
        dr7->RW3 = type; // 执行断点 0 
        dr7->LEN3 = len; // 长度也是 0
        m_FalgsBa = 4;
    }

    // 3.设置回线程去
    SetThreadContext(hThread, &ctx);
    return true;
}

// 反汇编获取下一跳指令
LPVOID CDebug::NextAsm(HANDLE hProcess, PVOID address, DWORD len )
{
    char opcode[4096] = {};
    DWORD dwSize;
    // 1.读取目标进程内存数据
    ReadProcessMemory(hProcess, address, opcode, sizeof(opcode), &dwSize);
    // 2.反汇编数据

    csh handle;   // 反汇编引擎句柄
    cs_err err;   // 错误信息
    cs_insn* pInsn; // 保存反汇编得到的指令的缓冲区首地址
    unsigned int count = 0; // 保存得到的反汇编的指令条数


    //初始化反汇编器句柄,(x86_64架构,32位模式,句柄)
    err = cs_open(CS_ARCH_X86,  /*x86指令集*/
        CS_MODE_32, /*使用32位模式解析opcode*/
        &handle /*输出的反汇编句柄*/
    );

    if (err != CS_ERR_OK)
    {
        printf("初始化反汇编器句柄失败:%s\n", cs_strerror(err));
        return 0;
    }


    // 开始反汇编.
    // 函数会返回总共得到了几条汇编指令
    count = cs_disasm(handle,       /*反汇编器句柄,从cs_open函数得到*/
        (const uint8_t*)opcode,     /*需要反汇编的opcode的缓冲区首地址*/
        sizeof(opcode),             /*opcode的字节数*/
        (uint64_t)address,          /*opcode的所在的内存地址*/
        len,                        /*需要反汇编的指令条数,如果是0,则反汇编出全部*/
        &pInsn                      /*反汇编输出*/
    );


    LPVOID NextInfo;
    NextInfo = (LPVOID)pInsn[1].address;


    // 释放保存指令的空间
    cs_free(pInsn, count);

    // 关闭句柄
    cs_close(&handle);

    return NextInfo;
}

// 回复硬件断点
VOID CDebug::HardBreakReply(HANDLE hThread,HANDLE hProcess, LPVOID ExceptionAddress)
{
    // 原理：当 Dr7 设置的硬件断点断下时， Dr6 寄存器的
    //	最低4位标识当前断下的是哪一个硬件断点，只要将对应
    //	Dr7.LN 设置成 0 就可以关闭了
   
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
        // 应用设置
        SetThreadContext(hThread, &context);
        DisAsm(hProcess, ExceptionAddress);
        SetTF(hThread);
        isBa = TRUE;
    }
}

// 获取当前指令的长度[不行][没用已弃置]
DWORD CDebug::AsmLen(HANDLE hProcess, PVOID address)
{
    char opcode[4096] = {};
    DWORD dwSize;
    // 1.读取目标进程内存数据
    ReadProcessMemory(hProcess, address, opcode, sizeof(opcode), &dwSize);
    // 2.反汇编数据

    csh handle;   // 反汇编引擎句柄
    cs_err err;   // 错误信息
    cs_insn* pInsn; // 保存反汇编得到的指令的缓冲区首地址
    unsigned int count = 0; // 保存得到的反汇编的指令条数


    //初始化反汇编器句柄,(x86_64架构,32位模式,句柄)
    err = cs_open(CS_ARCH_X86,  /*x86指令集*/
        CS_MODE_32, /*使用32位模式解析opcode*/
        &handle /*输出的反汇编句柄*/
    );

    if (err != CS_ERR_OK)
    {
        printf("初始化反汇编器句柄失败:%s\n", cs_strerror(err));
        return 0;
    }


    // 开始反汇编.
    // 函数会返回总共得到了几条汇编指令
    count = cs_disasm(handle,       /*反汇编器句柄,从cs_open函数得到*/
        (const uint8_t*)opcode,     /*需要反汇编的opcode的缓冲区首地址*/
        sizeof(opcode),             /*opcode的字节数*/
        (uint64_t)address,          /*opcode的所在的内存地址*/
        5,                        /*需要反汇编的指令条数,如果是0,则反汇编出全部*/
        &pInsn                      /*反汇编输出*/
    );
    return pInsn[0].size;
}

// 显示内存(有问题)[已改]
BOOL CDebug::PrintMemory(HANDLE hProcess, PVOID address)
{
    BYTE opcode[0x100] = {0};
    DWORD dwSize;
    // 1.读取目标进程内存数据
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

// 修改内存
BOOL CDebug::ChangeMemory(HANDLE hProcess, PVOID address,BYTE Data)
{
    DWORD dwSize;
    DWORD oldProtect;
    // 更改页面属性
    VirtualProtectEx(hProcess, address, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    if(!WriteProcessMemory(hProcess, address,&Data,1,&dwSize))
    return FALSE;
    VirtualProtectEx(hProcess, address, 1, oldProtect, &oldProtect);
    return TRUE;
}

// 设置条件断点
BOOL CDebug::SetConBreak(HANDLE hProcess,LPVOID pAddress,DWORD Data)
{
    DWORD dwSize = 0;
    // 读取进程内存，保存一个字节的数据
    ReadProcessMemory(hProcess, pAddress, &ConBreak.data, 1, &dwSize);
    ConBreak.address = pAddress;
    ConBreak.enable = TRUE;
    ConBreakData = Data;
    // 往改地址填充0xCC
    if (!WriteProcessMemory(hProcess, pAddress, "\xCC", 1, &dwSize))
        return FALSE;
    return TRUE;
}

// 回复条件断点
VOID CDebug::ConBreakHandle(HANDLE hThread,HANDLE hProcess, LPVOID ExceptionAddress)
{
    if (ConBreak.enable == TRUE)
    {
        //软件断点异常处理
        DWORD dwSize;
        // 1.将原始数据写回到断点位置上
        WriteProcessMemory(hProcess, ConBreak.address, &ConBreak.data, 1, &dwSize);

        // 2.需要将eip -1 退回到指令所在位置
        CONTEXT ctx = { CONTEXT_FULL }; //获取线程上下文中的通用寄存器
        GetThreadContext(hThread, &ctx);
        ctx.Eip -= 1;
        //设置回线程去
        SetThreadContext(hThread, &ctx);
        if (ctx.Eax == ConBreakData)
        {
            // 反汇编
            DisAsm(ProcessInfo.hProcess, ExceptionAddress);
            // 断点是我们产生的，需要接受输入
            m_isInput = TRUE;

            // 设置永久性断点，设置一个单步，在单步中恢复软件断点CC
            SetTF(hThread);
        }
        m_FlagsCon = TRUE;
        SetTF(hThread);

    }
    IsContinueExcepiton = DBG_CONTINUE;
    return ;
}

// 显示模块信息
VOID CDebug::AllModule(HANDLE hProcess)
{
    WCHAR ModulePath[MAX_PATH];
    DWORD ProcessId=GetProcessId(hProcess);
    // 1. 拍摄当前API调用时的模块快照，参数二是要遍历模块的进程id
    HANDLE SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessId);
    // 2. 如果快照创建失败，就会返回 INVALID_HANDLE_VALUE(-1)
    if (SnapshotHandle != INVALID_HANDLE_VALUE)
    {
        // 3. 定义结构体，用于保存遍历到的快照的信息，需要初始化
        MODULEENTRY32 ModuleInfo = { sizeof(ModuleInfo) };

        // 4. 如果快照获取成功，就尝试从快照中获取第一个模块的信息
        if (Module32First(SnapshotHandle, &ModuleInfo))
        {
            do {
                /*
                    th32ProcessID;      拥有该模块的进程的 id*3
                    modBaseAddr;        模块在进程虚拟内存中的地址(加载基址)
                    modBaseSize;        模块所占用的内存大小*2
                    hModule;            模块的句柄，实际和加载基址是一样的
                    szModule			模块的名字*1
                    szExePath			模块所在的路径
                */
                printf("%08X: |",ModuleInfo.modBaseAddr);
                wprintf(L"%s ",ModuleInfo.szModule);
                GetModuleFileName(ModuleInfo.hModule, ModulePath, MAX_PATH);
                wprintf(L"%s\n", ModulePath);
                // 6. 如果当前遍历成功，那么就继续遍历下一个
            } while (Module32Next(SnapshotHandle, &ModuleInfo));
        }
    }

    CloseHandle(SnapshotHandle);

    return ;
}

// 隐藏PEB[有问题][已改]
BOOL CDebug::HidePEB(DEBUG_EVENT* dbg)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dbg->dwProcessId);
    const WCHAR PATH[] = L"C:\\Users\\1\\Desktop\\调试器项目\\调试器项目\\Debug\\funhook.dll";
    DWORD Size = sizeof(PATH);
    /*
     申请内存空间
    */
    LPVOID VirPath = VirtualAllocEx(hProcess, 0, Size, MEM_COMMIT, PAGE_READWRITE);
    /*
     将路径写入内存空间
    */
    SIZE_T realSize = 0;
    WriteProcessMemory(hProcess, VirPath, PATH, Size, &realSize);
    /*
     2.在指定进程创建线程
    */
    HANDLE ThreadHandle = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, VirPath, NULL, NULL);

    // WaitForSingleObject(ThreadHandle, -1);
    CloseHandle(hProcess);
    return TRUE;
}

// 获取函数名
BOOL CDebug::GetSymName(HANDLE hProcess, SIZE_T nAddress, CString& strName)
{
    DWORD64 dwDisplacement = 0;
    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;
    // 根据地址获取符号信息
    if (!SymFromAddr(hProcess, nAddress, &dwDisplacement, pSymbol))
        return FALSE;
    strName = pSymbol->Name;
    return TRUE;
}

// 显示栈
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

// 获取文件信息
BOOL CDebug::GetPEInfo(WCHAR* szTargetPath)
{
    /*
     1. 根据路径找文件句柄
    */
    HANDLE FileHandle = CreateFile(szTargetPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    /*
     2.获取文件大小并申请堆空间
    */
    DWORD FileSize = GetFileSize(FileHandle, NULL);
    FileBase = new BYTE[FileSize]{ };
    DWORD ReadBytes = 0;
    ReadFile(FileHandle, FileBase, FileSize, &ReadBytes, NULL);

    /*
     3.获取DOS头位置
    */
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)FileBase;
    /*
     4.根据偏移获取NT头位置，并将其输出在相应的编辑框内
    */
    CString CBuffer;
    NtHeader = (PIMAGE_NT_HEADERS)(FileBase + DosHeader->e_lfanew);

    return TRUE;
}

// 关键APIHook
BOOL CDebug::APIHook(DEBUG_EVENT* dbg)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dbg->dwProcessId);
    const WCHAR PATH[] = L"C:\\Users\\1\\Desktop\\调试器项目\\调试器项目\\Debug\\APIHook.dll";
    DWORD Size = sizeof(PATH);
    /*
     申请内存空间
    */
    LPVOID VirPath1 = VirtualAllocEx(hProcess, 0, Size, MEM_COMMIT, PAGE_READWRITE);
    /*
     将路径写入内存空间
    */
    SIZE_T realSize = 0;
    WriteProcessMemory(hProcess, VirPath1, PATH, Size, &realSize);
    /*
     2.在指定进程创建线程
    */
    HANDLE ThreadHandle = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, VirPath1, NULL, NULL);

    CloseHandle(hProcess);
    return TRUE;
}

// 设置API断点
SIZE_T CDebug::FindApiAddress(HANDLE hProcess, const char* pszName)
{
    char Buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)Buffer;
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;
    // 根据名字查询符号信息，输出到pSymbol中
    if (!SymFromName(hProcess, pszName, pSymbol))
        return 0;
    return (SIZE_T)pSymbol->Address;
}

// 遍历模块信息并赋值结构体
BOOL CDebug::AllMoudlesList(HANDLE hProcess)
{
    PE_Struct Info;
    WCHAR ModulePath[MAX_PATH];
    WCHAR ModuleName[MAX_PATH];
    DWORD ProcessId = GetProcessId(hProcess);
    // 1. 拍摄当前API调用时的模块快照，参数二是要遍历模块的进程id
    HANDLE SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessId);
    // 2. 如果快照创建失败，就会返回 INVALID_HANDLE_VALUE(-1)
    if (SnapshotHandle != INVALID_HANDLE_VALUE)
    {
        // 3. 定义结构体，用于保存遍历到的快照的信息，需要初始化
        MODULEENTRY32 ModuleInfo = { sizeof(ModuleInfo) };

        // 4. 如果快照获取成功，就尝试从快照中获取第一个模块的信息
        if (Module32First(SnapshotHandle, &ModuleInfo))
        {
            do {
                /*
                    th32ProcessID;      拥有该模块的进程的 id*3
                    modBaseAddr;        模块在进程虚拟内存中的地址(加载基址)
                    modBaseSize;        模块所占用的内存大小*2
                    hModule;            模块的句柄，实际和加载基址是一样的
                    szModule			模块的名字*1
                    szExePath			模块所在的路径
                */
                GetModuleFileName(ModuleInfo.hModule, ModulePath, MAX_PATH);
                GetModuleBaseName(hProcess, ModuleInfo.hModule, ModuleName, MAX_PATH); //获取模块名称
                Info.dllBase = (DWORD)ModuleInfo.modBaseAddr;
                wcscpy_s(Info.Name,MAX_PATH,ModuleName);
                wcscpy_s(Info.Path, MAX_PATH, ModulePath);
                ModuleList.push_back(Info);
                // 6. 如果当前遍历成功，那么就继续遍历下一个
            } while (Module32Next(SnapshotHandle, &ModuleInfo));
        }
    }

    CloseHandle(SnapshotHandle);

    return TRUE;
}

// 遍历指定模块信息
BOOL CDebug::ExportFunc()
{
    DWORD ImTable;
    printf("请输入地址\n");
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
     将获取到的16进制数重新转换为导入表结构体指针
    */
    AllExportDll(NtHeader, FileBase);
    ImportFunc(NtHeader, FileBase);
    return TRUE;
}