// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "common.h"

#define DEFAULT_BUFFER_CAPACITY 1024

int buffer_enlarge(buff_t *buff, size_t required)
{
    BUG(!buff, E_BUG);

    /* We do not allow buffers larger than UINT16_MAX (64k) since
     * that's the largest message size we want on the wire. */
    if (required > UINT16_MAX)
        return E_TOO_BIG;

    /* Alloc to fit at least max offset, but double the capacity if
     * possible to reduce allocations */
    uint64_t max = MAX(buff->capacity * 2, required);
    if (max >= UINT16_MAX)
        max = UINT16_MAX;

    index_t new_size = (index_t)max;
    assert(new_size >= required);

    uint8_t *x = (uint8_t *)realloc(buff->storage, (size_t)new_size);
    if (!x)
        return E_OOM;

    log_dbg("Resized buffer from  %u to %u octets\n", buff->capacity, new_size);
    buff->storage = x;
    buff->capacity = new_size;
    return E_OK;
}
buff_t *buff_new(index_t capacity)
{
    buff_t *buff = calloc(1, sizeof(buff_t));
    if (!buff)
        return NULL;

    if (!capacity)
        capacity = DEFAULT_BUFFER_CAPACITY;
    if (capacity > UINT16_MAX)
        capacity = UINT16_MAX;

    buff->storage = calloc(capacity, 1);
    if (!buff->storage) {
        buff_free(buff);
        return NULL;
    }
    buff->capacity = capacity;
    return buff;
}
void buff_free(buff_t *buff)
{
    BUG(!buff);
    if (buff->storage)
        free(buff->storage);
    memset(buff, 0, sizeof(buff_t));
    free(buff);
}
void buff_clear(buff_t *buff)
{
    BUG(!buff);
    buff->w = 0;
    buff->r = 0;
#if 0 /* not needed */
    if (buff->storage != NULL)
        memset(buff->storage, 0, buff->capacity); // not needed
#endif
}
void buff_dump(buff_t *buff)
{
    BUG(!buff);

    if (!buff->storage) {
        log_err("Buffer has no storage");
        return;
    }

    fprintf(stderr, "(w: %u r:%u) [", buff->w, buff->r);
    for (register index_t n = 0; n < buff->w; n++) {
        fprintf(stderr, " %u%s", buff->storage[n], n < buff->w - 1 ? "," : "");
        if (n && (n % 64) == 0)
            fprintf(stderr, "\n");
    }
    fprintf(stderr, "]\n");
}
int buff_cmp(buff_t *b1, buff_t *b2)
{
    BUG(!b1 || !b2, E_BUG);

    if (!b1->storage || !b2->storage)
        return 1;

    if (b1->w != b2->w)
        return 1;

    return memcmp(b1->storage, b2->storage, b1->w);
}
index_t buff_get_roff(buff_t *buff)
{
    BUG(!buff, 0);
    return buff->r;
}
index_t buff_get_woff(buff_t *buff)
{
    BUG(!buff, 0);
    return buff->w;
}
