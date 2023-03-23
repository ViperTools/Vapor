#pragma once
#include <windows.h>
#include "process.h"

// LEAK DETECTOR
#include "leak_detector.h"

typedef struct Shellcode {
	const char* shellcode;
	size_t size;
} Shellcode;

extern DWORD execution_execute_shellcode(const Process* process, const char shellcode[], size_t size);
extern Shellcode* execution_compile_asm(const char* asm);
extern DWORD execution_execute_asm(const Process* process, const char* asm);