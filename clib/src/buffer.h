#pragma once

#include <stdint.h>

typedef uint32_t index_t;

typedef struct buffer_s {
    index_t w;
    index_t r;
    index_t capacity;
    uint8_t *storage;
} buff_t;

#define MAX(a, b) (a) < (b) ? (b) : (a)

buff_t *buff_new(index_t capacity);
void buff_free(buff_t *buff);
void buff_clear(buff_t *buff);
void buff_dump(buff_t *buff);
int buff_cmp(buff_t *b1, buff_t *b2);

index_t buff_get_roff(buff_t *buff);
index_t buff_get_woff(buff_t *buff);
