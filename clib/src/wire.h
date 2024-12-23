#pragma once

#include "buffer.h"

#define DEF_INSERT(name, type)                                \
    int insert_##name(buffer_t *buff, index_t pos, type data) \
    {                                                         \
        BUG(!buff, E_BUG);                                    \
        index_t required = MAX(buff->w, pos) + sizeof(type);  \
        if (required > buff->capacity) {                      \
            int r = buffer_enlarge(buff, required);           \
            if (r != E_OK)                                    \
                return r;                                     \
        }                                                     \
        *((type *)&buff->storage[pos]) = data;                \
        if (pos + sizeof(type) > buff->w)                     \
            buff->w = pos + sizeof(type);                     \
        return E_OK;                                          \
    }

#define DEF_PUT(name, type)                         \
    int put_##name(buffer_t *buff, type data)       \
    {                                               \
        BUG(!buff || !buff->storage, E_BUG);        \
        index_t required = buff->w + sizeof(type);  \
        if (required > buff->capacity) {            \
            int r = buffer_enlarge(buff, required); \
            if (r != E_OK)                          \
                return r;                           \
        }                                           \
        *((type *)&buff->storage[buff->w]) = data;  \
        buff->w += sizeof(type);                    \
        return E_OK;                                \
    }

#define DEF_GET(name, type)                          \
    int get_##name(buffer_t *buff, type *out)        \
    {                                                \
        BUG(!buff || !buff->storage || !out, E_BUG); \
        if (buff->r + sizeof(type) > buff->w)        \
            return E_NOT_ENOUGH_DATA;                \
        *out = *((type *)&buff->storage[buff->r]);   \
        buff->r += sizeof(type);                     \
        return E_OK;                                 \
    }

/* decl */
#define DECL_PUT(name, type) int put_##name(buffer_t *buff, type data)
#define DECL_GET(name, type) int get_##name(buffer_t *buff, type *out)
#define DECL_INSERT(name, type) int insert_##name(buffer_t *buff, index_t pos, type data)

DECL_PUT(u8, uint8_t);
DECL_PUT(u16, uint16_t);
DECL_PUT(u32, uint32_t);
DECL_PUT(u64, uint64_t);

DECL_GET(u8, uint8_t);
DECL_GET(u16, uint16_t);
DECL_GET(u32, uint32_t);
DECL_GET(u64, uint64_t);

DECL_INSERT(u8, uint8_t);
DECL_INSERT(u16, uint16_t);
DECL_INSERT(u32, uint32_t);
DECL_INSERT(u64, uint64_t);

int put_raw(buffer_t *buff, void *data, size_t data_size);
int get_raw(buffer_t *buff, void *data, size_t data_size);
