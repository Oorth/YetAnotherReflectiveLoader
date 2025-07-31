#include <iostream>
#include <windows.h>


// int main()
// {
//     std::cout << "Attempting to open handle to driver...\n";

//     constexpr ULONG HIDE_MODULE_REQUEST = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

//     HANDLE hDriver = CreateFileW(
//     "\\\\.\\GLOBAL??\\baaaa_bae", // <-- Use the correct global path
//     GENERIC_READ | GENERIC_WRITE,
//     0,
//     NULL,
//     OPEN_EXISTING,
//     FILE_ATTRIBUTE_NORMAL,      // Standard practice for this parameter
//     NULL
//     );
//     if(hDriver == INVALID_HANDLE_VALUE) { std::cout << "[!!!!] Failed to open device -> INVALID_HANDLE_VALUE\n";  return 1; }
//     else std::cout << "Successfully opened device\n";

//     std::cout << "Success! Handle opened: " << hDriver << "\n";
//     std::cout << "Sending IOCTL request...\n";

//     // --- Prepare and send the request ---

//     HIDE_MODULE_RESOURCES request_data;
//     // We'll use fake data for this test.
//     request_data.hTargetPid        = (HANDLE)1234; 
//     request_data.vpInjectedDll_Base = (PVOID)0x7FFFFFFF;

//     DWORD bytes_returned = 0;
//     BOOL success = DeviceIoControl(
//         hDriver,
//         IOCTL_HIDE_MODULE_VALUE,
//         &request_data,
//         sizeof(request_data), // Using the safe, standard sizeof() here
//         NULL,
//         0,
//         &bytes_returned,
//         NULL
//     );

//     if (success)
//     {
//         std::cout << "Success! Driver acknowledged the IOCTL request.\n";
//     }
//     else
//     {
//         std::cout << "Error: DeviceIoControl failed. GetLastError() = " << GetLastError() << "\n";
//     }

//     CloseHandle(hDriver);
//     system("pause");
//     return 0;
// }

struct HIDE_MODULE_RESOURCES
{
    HANDLE hTargetPid;
    PVOID  vpInjectedDll_Base;
};

void main()
{

    constexpr ULONG HIDE_MODULE_REQUEST = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

    static const WCHAR s3[] = L"\\\\.\\baaaa_bae";

    HANDLE hDriver = CreateFileW(s3, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if(hDriver == INVALID_HANDLE_VALUE) { std::cout << "[SHELLCODE] [!!!!] Failed to open device -> INVALID_HANDLE_VALUE\n";  return; }
    else std::cout << "[SHELLCODE] Successfully opened device\n";

    
    HIDE_MODULE_RESOURCES request_data;
    request_data.hTargetPid        = (HANDLE)1234; 
    request_data.vpInjectedDll_Base = (PVOID)0x7FFFFFFF;


    DWORD bytes_returned = 0;
    BOOL success = DeviceIoControl(hDriver, HIDE_MODULE_REQUEST, &request_data, sizeof(request_data), nullptr, 0, &bytes_returned, nullptr);
    if (success) std::cout << "[SHELLCODE] Driver acknowledged the request successfully!\n";
    else std::cout << "[SHELLCODE] [!!!!] Driver returned an error for the request.\n";

    CloseHandle(hDriver);
}