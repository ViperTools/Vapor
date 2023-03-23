#include "vector.h"
#include <stdlib.h>

int _vector_check_bounds(const Vector* vec, int i) {
    return i >= 0 && i < vec->length;
}

int vector_resize(Vector* vec, size_t capacity) {
    if (!vec) {
        return 0;
    }

    byte* items = realloc(vec->items, sizeof(byte) * capacity);

    if (!items) {
        return 0;
    }

    vec->items = items;
    vec->capacity = capacity;

    return 1;
}

int vector_push_back(Vector* vec, byte item) {
    if (!vec || (vec->length == vec->capacity && !vector_resize(vec, vec->capacity * 2))) {
        return 0;
    }

    vec->items[vec->length++] = item;

    return 1;
}

int vector_set(Vector* vec, int i, byte item) {
    if (!vec || !_vector_check_bounds(vec, i)) {
        return 0;
    }

    vec->items[i] = item;

    return 1;
}

byte vector_get(const Vector* vec, int i) {
    if (!vec || !_vector_check_bounds(vec, i)) {
        return 0;
    }

    return vec->items[i];
}

int vector_remove(Vector* vec, int i) {
    if (!vec || !_vector_check_bounds(vec, i)) {
        return 0;
    }

    for (int j = i; j < vec->length - 1; j++) {
        vec->items[j] = vec->items[j + 1];
        vec->items[j + 1] = 0;
    }

    vec->length--;

    if (vec->length > 0 && vec->length == vec->capacity / 4) {
        vector_resize(vec, vec->capacity / 2);
    }

    return 1;
}

void vector_free(Vector* vec) {
    if (!vec) {
        return;
    }

    free(vec->items);
    free(vec);
}

Vector* vector_new_with_capacity(size_t capacity) {
    Vector* vec = malloc(sizeof(Vector));
    vec->capacity = capacity;
    vec->length = 0;
    vec->items = malloc(vec->capacity * sizeof(int));

    return vec;
}

Vector* vector_new() {
    return vector_new_with_capacity(6);
}