#include "process.h"
#include "memory.h"
#include "execution.h"
#include "vector.h"
#include <stdio.h>
#include <time.h>
#include "rtti.h"

enum PrintType {
    TEXT,
    INFO,
    WARNING,
    ERR
};

uintptr_t getWorkspace(const Process* process) {
    uintptr_t workspaceVFTable = memory_scan_signature(process, "C7 07 ? ? ? ? C7 47 ? ? ? ? ? C7 87 ? ? ? ? ? ? ? ? C7 87 ? ? ? ? ? ? ? ? C7 87 ? ? ? ? ? ? ? ? C7 87 ? ? ? ? ? ? ? ? C7 87 ? ? ? ? ? ? ? ? 8B 40 ? C7 44 ? ? ? ? ? ? 8B 47 ? 8B 48 ? 8D 81 ? ? ? ? 89 44 ? ? C7 87 ? ? ? ? 00 00 00 00 C7 87 ? ? ? ? 00 00 00 00 C7 87 ? ? ? ? 00 00 00 00 C7 87 ? ? ? ? 00 00 00 00 C7 87 ? ? ? ? 00 00 00 00 C7 87 ? ? ? ? 00 00 00 00 8D 87") + 2;
    ReadProcessMemory(process->handle, workspaceVFTable, &workspaceVFTable, sizeof(uintptr_t), 0);

    if (!workspaceVFTable) {
        printf("Could not find workspace VFTable\n");
        return 1;
    }

    printf("Workspace VTable (scanned): %x\n", workspaceVFTable);

    uintptr_t workspace = memory_scan_vftable(process, workspaceVFTable);

    if (!workspace) {
        printf("Could not find workspace\n");
        return 1;
    }

    return workspace;
}

int print(const Process* process, uintptr_t printAddress, const char* str, enum PrintType type) {
    size_t strSize = (strlen(str) + 1) * sizeof(char);
    void* strAddress = VirtualAllocEx(process->handle, 0, strSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!strAddress) {
        printf("Could not allocate memory for the string\n");
        return 0;
    }

    if (!WriteProcessMemory(process->handle, strAddress, str, strSize, NULL)) {
        printf("Could not write string to memory\n");
        return 0;
    }

    char shellcode[] = {
        0x68, 0x00,	0x00, 0x00, 0x00,			        // push { str_addr }		(push string address to stack)
        0x6A, type,								        // push { type }			(push type to stack)
        0xB8, 0x00, 0x00, 0x00, 0x00,			        // mov eax, { func_addr }	(move function address to eax)
        0xFF, 0xD0,								        // call eax					(call function)
        0x83, 0xC4, sizeof(strAddress) + sizeof(int),	// add esp, n				(clean up stack)
        0xC3									        // ret						(return)
    };

    *(uintptr_t*)(&shellcode[1]) = (uintptr_t)strAddress;
    *(uintptr_t*)(&shellcode[8]) = printAddress;

    execution_execute_shellcode(process, shellcode, sizeof(shellcode));

    VirtualFreeEx(process->handle, strAddress, 0, MEM_RELEASE);

    return 1;
}

size_t readString(const Process* process, uintptr_t addr, char* buf, size_t maxLength) {
    return 0;
}

int main() {
    Process* process = process_from_name(L"RobloxPlayerBeta.exe", PROCESS_ALL_ACCESS);

    if (!process) {
        printf("Could not open process\n");
        return 1;
    }

    printf("Opened process: %d\n", process->id);

    uintptr_t workspace = getWorkspace(process);
    printf("Workspace: %x\n", workspace);

    RTTICompleteObjectLocator* col = rtti_read_complete_object_locator(process, workspace);

    for (int i = 0; i < col->classDescriptor->numBaseClasses; i++) {
        printf("%d: %s\n", i, col->classDescriptor->baseClassArray[i].typeDescriptor.name);
    }

    rtti_free_complete_object_locator(col);

    // Test print with execution
   /* uintptr_t printAddress = memory_scan_signature(process, "55 8B EC 6A FF 68 ? ? ? ? 64 A1 ? ? ? ? 50 64 89 25 ? ? ? ? 83 EC 1C 8B 55 ? 8D 45 ? 50 8D 4D ? E8 ? ? ? ? 83 C4 04 8B 4D ? 8D 55");

    if (!printAddress) {
        printf("Could not find print address\n");
        return 1;
    }

    print(process, printAddress, "Slight is shit", WARNING);*/

    free(process);
    // leak_detector_print_num_addresses();


    return 0;
}