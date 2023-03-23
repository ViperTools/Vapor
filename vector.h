#pragma once
#include <stddef.h>

// LEAK DETECTOR
#include "leak_detector.h"

typedef unsigned char byte;

typedef struct Vector {
    byte* items;  
    size_t capacity;
    size_t length;
} Vector;

extern int vector_resize(Vector* vec, size_t capacity);
extern int vector_push_back(Vector* vec, byte item);
extern int vector_set(Vector* vec, int i, byte item);
extern byte vector_get(const Vector* vec, int i);
extern int vector_remove(Vector* vec, int i);
extern void vector_free(Vector* vec);
extern Vector* vector_new_with_capacity(size_t capacity);
extern Vector* vector_new();