#pragma once

#include "common.h"
#include <stdint.h>

/* 64K objects should be enough in all cases */
#define MAX_VEC_SIZE UINT16_MAX

/* declare a vector for some type of data.
 * Capacity and len are in number of objects,
 * regardless of their size */
#define DECL_VEC_TYPE(name, type)  \
    typedef struct vector_##name { \
        size_t capacity;           \
        size_t len;                \
        type *data;                \
    } vec_##name;

/* declare and define push methods for vector of some type */
#define DECL_PUSH_VEC(name, type) int vec_push_##name(vec_##name *v, type value)
#define DEF_PUSH_VEC(name, type)                                       \
    DECL_PUSH_VEC(name, type)                                          \
    {                                                                  \
        int r;                                                         \
        if ((r = vec_check_enlarge((vec_t *)v, sizeof(type))) != E_OK) \
            return r;                                                  \
        v->data[v->len] = value;                                       \
        v->len++;                                                      \
        return E_OK;                                                   \
    }

/* same if want pass data as pointer */
#define DEF_PUSH_VEC_PTR(name, type)                                   \
    DECL_PUSH_VEC(name, type *)                                        \
    {                                                                  \
        BUG(!value, E_BUG);                                            \
        int r;                                                         \
        if ((r = vec_check_enlarge((vec_t *)v, sizeof(type))) != E_OK) \
            return r;                                                  \
        v->data[v->len] = *value;                                      \
        v->len++;                                                      \
        return E_OK;                                                   \
    }

/* vector type definitions for system types
 * commonly used. Vectors for custom types
 * can be declared identically. */
DECL_VEC_TYPE(t, void); /* generic vec_t */
DECL_VEC_TYPE(u8, uint8_t);
DECL_VEC_TYPE(u16, uint16_t);
DECL_VEC_TYPE(u32, uint32_t);
DECL_VEC_TYPE(u64, uint64_t);

/* push to typed vectors */
DECL_PUSH_VEC(u8, uint8_t);
DECL_PUSH_VEC(u16, uint16_t);
DECL_PUSH_VEC(u32, uint32_t);
DECL_PUSH_VEC(u64, uint64_t);

int vec_check_enlarge(vec_t *v, size_t type_size);
void vec_dispose(void *v);
