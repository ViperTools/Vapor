#pragma once
#include <Windows.h>
#include <stdint.h>

// LEAK DETECTOR
#include "leak_detector.h"

typedef struct Process {
    DWORD id;
    HANDLE handle;
    uintptr_t baseAddress;
} Process;

extern Process* process_new(DWORD id, DWORD access);
extern Process* process_from_name(const wchar_t* name, DWORD access);