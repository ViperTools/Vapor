#include "execution.h"
#include "memory.h"
#include "leak_detector.h"
#include <stdio.h>

DWORD execution_execute_shellcode(const Process* process, const char shellcode[], size_t size) {
	void* codeAddress = VirtualAllocEx(process->handle, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!codeAddress || !WriteProcessMemory(process->handle, codeAddress, shellcode, size, NULL)) {
		return 0;
	}

	HANDLE thread = CreateRemoteThread(process->handle, 0, 0, (LPTHREAD_START_ROUTINE)codeAddress, 0, 0, 0);

	if (!thread) {
		VirtualFreeEx(process->handle, codeAddress, 0, MEM_RELEASE);
		return 0;
	}

	WaitForSingleObject(thread, INFINITE);

	DWORD ret;
	GetExitCodeThread(thread, &ret);

	VirtualFreeEx(process->handle, codeAddress, 0, MEM_RELEASE);
	CloseHandle(thread);

	return ret;
}

const wchar_t nasmPath[] = L"./nasm.exe";
const wchar_t* baseArguments = L"./nasm.exe -fbin -o";

const wchar_t* writeASMFile(const char* asm) {
	const wchar_t* name = malloc((L_tmpnam + 1) * sizeof(wchar_t));
	_wtmpnam(name);

	if (!name) {
		return 0;
	}

	FILE* file = _wfopen(name, L"w");
	fprintf(file, "%s", asm);
	fclose(file);

	return name;
}

const Shellcode* readCompiledFile(const wchar_t* path) {
	long fileLength = 0;

	FILE* file = _wfopen(path, L"rb");

	fseek(file, 0, SEEK_END);
	fileLength = ftell(file);
	rewind(file);

	char* buffer = malloc(fileLength * sizeof(char));
	fread(buffer, fileLength, 1, file);
	fclose(file);

	Shellcode* code = malloc(sizeof(Shellcode));
	code->shellcode = buffer;
	code->size = fileLength;

	return code;
}

Shellcode* execution_compile_asm(const char* asm) {
	wchar_t* inputPath = writeASMFile(asm);

	if (!inputPath) {
		return 0;
	}

	wchar_t* outputPath = _wtmpnam(NULL);

	if (!outputPath) {
		return 0;
	}

	// Arguments
	wchar_t* arguments = malloc((wcslen(baseArguments) + wcslen(outputPath) + wcslen(inputPath) + 2) * sizeof(wchar_t));
	wcscpy(arguments, baseArguments);
	wcscat(arguments, outputPath);
	wcscat(arguments, L" ");
	wcscat(arguments, inputPath);

	// Compile
	STARTUPINFO startupInfo;
	memset(&startupInfo, 0, sizeof(STARTUPINFO));
	PROCESS_INFORMATION processInfo;

	BOOL process = CreateProcess(
		nasmPath,
		arguments,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&startupInfo,
		&processInfo
	);

	WaitForSingleObject(processInfo.hProcess, INFINITE);

	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);

	_wremove(inputPath);
	free(inputPath);
	free(arguments);

	Shellcode* code = readCompiledFile(outputPath);
	_wremove(outputPath);

	return code;
}

DWORD execution_execute_asm(const Process* process, const char* asm) {
	Shellcode* shellcode = execution_compile_asm(asm);
	DWORD ret = execution_execute_shellcode(process, shellcode->shellcode, shellcode->size);

	free(shellcode->shellcode);
	free(shellcode);

	return ret;
}