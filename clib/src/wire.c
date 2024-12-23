#include <string.h>

#include "wire.h"

/* internal only */
int buffer_enlarge(buffer_t *buff, size_t required);

/* Buffer basic writers */
DEF_PUT(u8, uint8_t);
DEF_PUT(u16, uint16_t);
DEF_PUT(u32, uint32_t);
DEF_PUT(u64, uint64_t);

/* Buffer basic readers */
DEF_GET(u8, uint8_t);
DEF_GET(u16, uint16_t);
DEF_GET(u32, uint32_t);
DEF_GET(u64, uint64_t);

/* Buffer basic inserters */
DEF_INSERT(u8, uint8_t);
DEF_INSERT(u16, uint16_t);
DEF_INSERT(u32, uint32_t);
DEF_INSERT(u64, uint64_t);

int put_raw(buffer_t *buff, void *data, size_t data_size)
{
    BUG(!buff || !data || !data_size, E_BUG);

    if (buff->w + (index_t)data_size > buff->capacity) {
        int r;
        if ((r = buffer_enlarge(buff, data_size)) != E_OK)
            return r;
    }
    memcpy(&buff->storage[buff->w], data, data_size);
    buff->w += data_size;
    return E_OK;
}

int get_raw(buffer_t *buff, void *data, size_t data_size)
{
    BUG(!buff || !data, E_BUG);

    if (buff->r + (index_t)data_size > buff->w)
        return E_NOT_ENOUGH_DATA;

    memcpy(data, &buff->storage[buff->r], data_size);
    buff->r += data_size;
    return E_OK;
}
