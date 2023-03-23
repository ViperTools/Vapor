#pragma once
#include <stdlib.h>

extern void leak_detector_print_addresses();
extern void leak_detector_print_num_addresses();

extern void* leak_detector_malloc(size_t size, const char* file, int line, const char* func);
extern void* leak_detector_calloc(size_t count, size_t size, const char* file, int line, const char* func);
extern void* leak_detector_realloc(void* p, size_t size, const char* file, int line, const char* func);
extern char* leak_detector_strdup(const char* str, const char* file, int line, const char* func);
extern void leak_detector_free(void* p, const char* file, int line, const char* func);

#define malloc(size) leak_detector_malloc(size, __FILE__, __LINE__, __FUNCTION__)
#define calloc(count, size) leak_detector_calloc(count, size, __FILE__, __LINE__, __FUNCTION__)
#define realloc(p, size) leak_detector_realloc(p, size, __FILE__, __LINE__, __FUNCTION__)
#define strdup(str) leak_detector_strdup(str, __FILE__, __LINE__, __FUNCTION__)
#define free(p) leak_detector_free(p, __FILE__, __LINE__, __FUNCTION__)