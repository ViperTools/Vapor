#include "process.h"
#include <Psapi.h>
#include <stdio.h>
#include <wchar.h>

uintptr_t getBaseAddress(const HANDLE handle) {
    if (!handle) {
        return 0;
    }

    HMODULE lphModule[1024];
    DWORD lpcbNeeded;

    if (!EnumProcessModules(handle, lphModule, sizeof(lphModule), &lpcbNeeded)) {
        return 0;
    }

    return (uintptr_t)lphModule[0];
}

Process* process_new(DWORD id, DWORD access) {
    if (!id) {
        return 0;
    }

    HANDLE handle = OpenProcess(access, FALSE, id);

    if (!handle) {
        return 0;
    }

    Process* process = malloc(sizeof(Process));
    process->id = id;
    process->handle = handle;
    process->baseAddress = getBaseAddress(handle);

    return process;
}

DWORD findProcessByName(const wchar_t* name) {
    DWORD processes[1024], processCount;

    if (!EnumProcesses(processes, sizeof(processes), &processCount)) {
        return 0;
    }

    processCount = processCount / sizeof(DWORD);

    size_t nameLength = wcslen(name);
    wchar_t* processName = malloc((nameLength + 1) * sizeof(wchar_t));

    if (!processName) {
        return 0;
    }

    for (int i = 0; i < processCount; i++) {
        if (!processes[i]) {
            continue;
        }

        HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
        
        if (handle) {
            HMODULE mod;
            DWORD lpcbNeeded;

            memset(processName, 0, nameLength * sizeof(wchar_t));

            if (EnumProcessModules(handle, &mod, sizeof(mod), &lpcbNeeded)) {
                GetModuleBaseName(handle, mod, processName, nameLength);
            }

            CloseHandle(handle);

            if (!memcmp(name, processName, nameLength)) {
                free(processName);
                return processes[i];
            }
        }
    }

    free(processName);

    return 0;
}

Process* process_from_name(const wchar_t* name, DWORD access) {
    return process_new(findProcessByName(name), access);
}