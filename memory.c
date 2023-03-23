#include "memory.h"
#include <stdio.h>

void read_result_free(ReadResult* result) {
    free(result->buffer);
    free(result);
}

ReadResult* memory_read(const Process* process, LPCVOID address, SIZE_T size) {
    ReadResult* result = malloc(sizeof(ReadResult));
    result->buffer = malloc(size);

    if (!result->buffer) {
        return 0;
    }

    ReadProcessMemory(process->handle, address, result->buffer, size, &result->numBytesRead);

    return result;
}

int memory_read_int(const Process* process, LPCVOID address) {
    int result;
    ReadProcessMemory(process->handle, address, &result, sizeof(int), 0);

    return result;
}

int* kmpTable(const Vector* vec) {
	int pos = 1, cnd = 0;
    int* t = calloc(vec->length, sizeof(int));

    if (!t) {
        return 0;
    }

    t[0] = -1;

	while (pos < vec->length) {
        if (vector_get(vec, pos) == vector_get(vec, cnd)) {
            t[pos] = t[cnd];
		}
		else {
            t[pos] = cnd;

            while (cnd >= 0 && vector_get(vec, pos) != vector_get(vec, cnd)) {
                cnd = t[cnd];
			}
		}

		++pos;
		++cnd;
	}

	return t;
}

int kmp(const Vector* region, const Vector* bytes, const Vector* mask) {
    int j = 0, k = 0;
    int* t = kmpTable(bytes);

    if (!t) {
        return -1;
    }

    while (j < region->length) {
        if (vector_get(region, j) == vector_get(bytes, k) || (mask && vector_get(mask, k) == '?')) {
            ++j;
            ++k;

            if (k == bytes->length) {
                free(t);
                return j - k;
            }
        }
        else {
            k = t[k];

            if (k < 0) {
                ++j;
                ++k;
            }
        }
    }

    free(t);
    return -1;
}

const DWORD pmask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

uintptr_t memory_scan(const Process* process, const Vector* bytes, const Vector* mask, const DWORD pmask) {
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t address = process->baseAddress;

    while (VirtualQueryEx(process->handle, (LPVOID)address, &mbi, sizeof(mbi))) {
        if (address <= 0x7FFFFFFF && mbi.State == MEM_COMMIT && (mbi.Protect & pmask) && !(mbi.Protect & PAGE_GUARD)) {
            Vector* region = vector_new_with_capacity(mbi.RegionSize);
            const uintptr_t begin = (uintptr_t)mbi.BaseAddress;
            SIZE_T size;

            if (ReadProcessMemory(process->handle, (PVOID)begin, region->items, mbi.RegionSize, (SIZE_T*)&region->length)) {
                int offset = kmp(region, bytes, mask);

                if (offset > -1) {
                    vector_free(region);
                    return begin + offset;
                }
            }

            vector_free(region);
        }

        address += mbi.RegionSize;
    }

    return 0;
}


uintptr_t memory_scan_signature(const Process* process, const char* sig) {
    char* sigCopy = strdup(sig);
    Vector* signature = vector_new();
    Vector* mask = vector_new();
    char* byte = strtok(sigCopy, " ");

    while (byte) {
        if (!strcmp(byte, "?")) {
            vector_push_back(signature, 0);
            vector_push_back(mask, '?');
        }
        else {
            vector_push_back(signature, strtoul(byte, 0, 16));
            vector_push_back(mask, 'x');
        }

        byte = strtok(NULL, " ");
    }

    uintptr_t res = memory_scan(process, signature, mask, pmask);

    vector_free(signature);
    vector_free(mask);
    free(sigCopy);

    return res;
}

uintptr_t memory_scan_vftable(const Process* process, const uintptr_t vft) {
    BYTE* b = (BYTE*)&vft;
    Vector* vec = vector_new_with_capacity(sizeof(uintptr_t) / sizeof(BYTE));
    vec->length = vec->capacity;

    for (int i = 0; i < vec->length; i++) {
        vector_set(vec, i, b[i]);
    }
    
    uintptr_t res = memory_scan(process, vec, 0, PAGE_READWRITE | PAGE_READONLY);

    vector_free(vec);

    return res;
}