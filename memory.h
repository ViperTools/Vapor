#pragma once
#include "process.h"
#include "vector.h"
#include <stdint.h>

// LEAK DETECTOR
#include "leak_detector.h"

typedef struct ReadResult {
    SIZE_T numBytesRead;
    void* buffer;
} ReadResult;

extern void read_result_free(ReadResult* result);
extern ReadResult* memory_read(const Process* process, LPCVOID address, SIZE_T size);
extern int memory_read_int(const Process* process, LPCVOID address);
extern uintptr_t memory_scan(const Process* process, const Vector* bytes, const Vector* mask, const DWORD pmask);
extern uintptr_t memory_scan_signature(const Process* process, const char* sig);
extern uintptr_t memory_scan_vftable(const Process* process, const uintptr_t vft);