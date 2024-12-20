#pragma once

#include <stdint.h>

#include "common.h"

typedef uint32_t index_t;

typedef struct buffer_s {
    index_t w;
    index_t r;
    index_t capacity;
    uint8_t *storage;
} buffer_t;

#define MAX(a,b) (a) < (b) ? (b) : (a)

buffer_t *buffer_new(index_t capacity);
void buffer_free(buffer_t *buff);
void buffer_clear(buffer_t *buff);
void buffer_dump(buffer_t *buff);
int buffer_cmp(buffer_t *b1, buffer_t *b2);

index_t buffer_get_roff(buffer_t *buff);
index_t buffer_get_woff(buffer_t *buff);
