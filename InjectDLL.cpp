// InjectDLL.cpp : 定义应用程序的入口点。
//

#include "framework.h"
#include "InjectDLL.h"
#include <windows.h>
#include "resource1.h"
#include <TlHelp32.h>
#include <stdio.h>
#include <direct.h>
#include <string>

#define WECHAT_PROCESS_NAME "WeChat.exe"
#define INJECT_DLL_NAME "WXMessage.dll"

INT_PTR CALLBACK Dlgproc(HWND unnamedParam1, UINT unnamedParam2, WPARAM unnamedParam3, LPARAM unnamedParam4);
VOID button_click(WPARAM unnamedParam3);
DWORD FindPIDByProcessName(LPCSTR ProcessName);
DWORD FindDllBaseAddrByDllName(DWORD PID, LPCSTR DllName);
VOID InjectDLL();
VOID UnDll();

LPVOID dllAddr;
DWORD modelBaseAddr;

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    DialogBox(hInstance, MAKEINTRESOURCE(ID_MAIN), NULL, &Dlgproc);
    return 0;
}


INT_PTR CALLBACK Dlgproc(HWND unnamedParam1, UINT unnamedParam2, WPARAM unnamedParam3, LPARAM unnamedParam4) 
{
    switch (unnamedParam2)
    {
    case WM_INITDIALOG:
        //MessageBox(NULL, "首次加载", "标题", 0);
        break;
    case WM_CLOSE:
        EndDialog(unnamedParam1, NULL);
        break;
    case WM_COMMAND:
        button_click(unnamedParam3);
        break;
    default:
        break;
    }

    return false;
}

/// <summary>
/// 按钮点击事件
/// </summary>
/// <param name="unnamedParam3"></param>
VOID button_click(WPARAM unnamedParam3) {
    if (unnamedParam3 == INJECT_DLL) {
        InjectDLL();
    }
    else if(unnamedParam3 == UN_DLL)
    {
        UnDll();
    }
}

/// <summary>
/// 通过进程名称查找pid
/// </summary>
/// <param name="ProcessName">进程名称</param>
DWORD FindPIDByProcessName(LPCSTR ProcessName) {
    HANDLE ProcessALL = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    PROCESSENTRY32 ProcessInfo = { 0 };
    ProcessInfo.dwSize = sizeof(ProcessInfo);
    do
    {
        if (strcmp(ProcessInfo.szExeFile, ProcessName) == 0)
        {
            modelBaseAddr = ProcessInfo.th32ModuleID;
            return ProcessInfo.th32ProcessID;
        }
    } while (Process32Next(ProcessALL, &ProcessInfo));
    return 0;
}

/// <summary>
/// 取模块dll地址
/// </summary>
/// <param name="ProcessName"></param>
/// <returns></returns>
DWORD FindDllBaseAddrByDllName(DWORD PID, LPCSTR DllName) {
    HANDLE ProcessALL = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
    MODULEENTRY32 DllInfo = {0};
    DllInfo.dwSize = sizeof(MODULEENTRY32);

    do
    {
        if (strcmp(DllInfo.szModule, DllName) == 0)
        {
            return (DWORD)DllInfo.modBaseAddr;
        }
    } while (Module32Next(ProcessALL, &DllInfo));
    return 0;
}

VOID InjectDLL() {
    char* pathStr;
    pathStr = _getcwd(NULL, 0);
    if (NULL == pathStr)
    {
        MessageBox(NULL, "获取运行目录失败", "错误", 0);
        return;
    }
    std::string path = pathStr;
    path = path + "\\" + "WXMessage.dll";
    OutputDebugString(path.c_str());
    // 1.取进程PID
    DWORD PID = FindPIDByProcessName(WECHAT_PROCESS_NAME);
    if (PID == 0)
    {
        MessageBox(NULL, "微信没有开启", "错误", 0);
        return;
    }
    // 2.打开进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (NULL == hProcess)
    {
        MessageBox(NULL, "打开进程失败，权限不足", "错误", 0);
        return;
    }
    // 3.申请内存
    dllAddr = VirtualAllocEx(hProcess, NULL, strlen(pathStr), MEM_COMMIT, PAGE_READWRITE);
    if (NULL == dllAddr)
    {
        MessageBox(NULL, "内存申请失败", "错误", 0);
        return;
    }
    // 4.写入dll路径
    if (!WriteProcessMemory(hProcess, dllAddr, pathStr, strlen(pathStr), NULL))
    {
        MessageBox(NULL, "内存写入失败", "错误", 0);
        return;
    }

    /*CHAR test[0x100] = {0};
    sprintf_s(test, "写入内存地址为 = %p", dllAddr);
    OutputDebugString(test);*/
    HMODULE k32 = GetModuleHandle("Kernel32.dll");
    LPVOID LoadAddr = GetProcAddress(k32, "LoadLibraryA");
    
    HANDLE exec = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadAddr, dllAddr, 0, NULL);
    if (NULL == exec)
    {
        MessageBox(NULL, "远程注入失败", "错误", 0);
        return;
    }
}


VOID UnDll() {
    // 1.1取进程PID
    DWORD PID = FindPIDByProcessName(WECHAT_PROCESS_NAME);
    if (PID == 0)
    {
        MessageBox(NULL, "微信没有开启", "错误", 0);
        return;
    }
    // 1.2取模块地址
    DWORD DllAddr = FindDllBaseAddrByDllName(PID, INJECT_DLL_NAME);
    if (NULL == DllAddr)
    {
        MessageBox(NULL, "模块读取失败", "错误", 0);
        return;
    }
    // 2.打开进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (NULL == hProcess)
    {
        MessageBox(NULL, "打开进程失败，权限不足", "错误", 0);
        return;
    }
    

    HMODULE k32 = GetModuleHandle("Kernel32.dll");
    LPVOID LoadAddr = GetProcAddress(k32, "FreeLibrary");
    HANDLE exec = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadAddr, (LPVOID)DllAddr, 0, NULL);
    if (NULL == exec)
    {
        MessageBox(NULL, "卸载失败", "错误", 0);
        return;
    }
}