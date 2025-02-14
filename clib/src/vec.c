// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#include <stdlib.h>

#include "common.h"
#include "errors.h"
#include "vec.h"

void vec_dispose(void *v)
{
    vec_t *p = (vec_t *)v;
    if (p) {
        if (p->data)
            free(p->data);
        p->capacity = 0;
        p->len = 0;
        p->data = NULL;
    }
}
int vec_check_enlarge(vec_t *v, size_t type_size)
{
    BUG(!v, E_BUG);
    if (v->len + 1 > MAX_VEC_SIZE)
        return E_VEC_CAPACITY_EXCEEDED;
    if (v->len + 1 >= v->capacity || !v->data) {
        size_t new_capacity = (v->len + 1) * 2;
        void *x = reallocarray(v->data, new_capacity, type_size);
        if (unlikely(!x))
            return E_OOM;
        v->data = x;
        v->capacity = new_capacity;
    }
    return E_OK;
}

/* vector push */
DEF_PUSH_VEC(u8, uint8_t);
DEF_PUSH_VEC(u16, uint16_t);
DEF_PUSH_VEC(u32, uint32_t);
DEF_PUSH_VEC(u64, uint64_t);
