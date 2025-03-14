// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#include <string.h>
#include <stdlib.h>

#include "test_common.h"
#include "../src/wire.h"

int test_buffer_available_data(void)
{
    TEST();

    int r;
    buff_t *buff = buff_new(2);
    if (!buff)
        return EXIT_FAILURE;

    uint8_t val_u8;
    uint16_t val_u16;
    uint32_t val_u32;
    uint64_t val_u64;

    r = get_u8(buff, &val_u8);
    CHECK(r == E_NOT_ENOUGH_DATA);

    put_u8(buff, 1);

    r = get_u16(buff, &val_u16);
    CHECK(r == E_NOT_ENOUGH_DATA);

    put_u8(buff, 2);
    put_u8(buff, 3);

    r = get_u32(buff, &val_u32);
    CHECK(r == E_NOT_ENOUGH_DATA);

    put_u8(buff, 4);
    put_u8(buff, 5);

    r = get_u64(buff, &val_u64);
    CHECK(r == E_NOT_ENOUGH_DATA);

    buff_free(buff);
    return EXIT_SUCCESS;
}
int test_buffer_conds(void)
{
    TEST();

    int r;
    buff_t *buff = buff_new(0);
    if (!buff)
        return EXIT_FAILURE;

    /* Write octets one at a time and read them.
     * Check that we read the value we wrote. We
     * should not be able to write more than UINT16_MAX
     * (64k), as the message length is bounded by that.
     */
    for(index_t n = 1; n <= UINT16_MAX; n++) {
        uint8_t val_write = n;
        uint8_t val_read = 0;
        r = put_u8(buff, val_write);
        if (r != E_OK) {
            buff_dump(buff);
            assert(0);
            return EXIT_FAILURE;
        }
        CHECK(buff->w == n);
        CHECK(get_u8(buff, &val_read) == E_OK);
        CHECK(val_read == val_write);
    }
    CHECK(buff->w == UINT16_MAX);
    CHECK(buff->capacity==UINT16_MAX);

    /* next write attempt should fail */
    CHECK(put_u8(buff, 0) == E_TOO_BIG);

    buff_free(buff);
    return EXIT_SUCCESS;
}
int test_buffer_resize(void)
{
    TEST();
    buff_t *buff = buff_new(1);
    if (!buff)
        return EXIT_FAILURE;

    for(uint16_t i = 1; i <= 100; i++)
        put_u8(buff, 0xFF);
    CHECK(buff->capacity > 100);
    CHECK(buff->w == 100);

    buff_dump(buff);

    buff_free(buff);
    return EXIT_SUCCESS;
}
int test_buffer_write_utils(void)
{
    TEST();
    buff_t *buff = buff_new(100);
    if (!buff)
        return EXIT_FAILURE;

    put_u8(buff, 1);
    put_u8(buff, 2);
    put_u8(buff, 3);
    put_u8(buff, 4);
    CHECK(buff->w == 4);
    buff_dump(buff);

    put_u16(buff, 0x5566);
    CHECK(buff->w == 6);
    buff_dump(buff);

    put_u32(buff, 0xaabbccdd);
    CHECK(buff->w == 10);
    buff_dump(buff);

    put_u64(buff, 0x00FF00FF00FF00FF);
    CHECK(buff->w == 18);
    buff_dump(buff);

    buff_clear(buff);
    buff_dump(buff);
    buff_free(buff);
    return EXIT_SUCCESS;
}
int test_buffer_read_utils(void)
{
    TEST();
    buff_t *b1 = buff_new(0);
    if (!b1)
        return EXIT_FAILURE;

    buff_t *b2 = buff_new(0);
    if (!b2)
        return EXIT_FAILURE;

    /* write stuff to buffer b1 */
    uint8_t n;
    for (n = 1; n <= 4; n++)
        put_u8(b1, n);
    put_u16(b1, 0x5566);
    put_u32(b1, 0xaabbccdd);
    put_u64(b1, 0x00FF00FF00FF00FF);

    /* read stuff from b1 */
    int r;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;

    /* read the 4 u8's and store them in b2 */
    for (n = 1; n <= 4; n++) {
        uint8_t u8 = 0;
        if ((r = get_u8(b1, &u8)) != 0)
            return EXIT_FAILURE;
        else
            put_u8(b2, u8);
    }
    /* read the u16 and store in b2 */
    if ((r = get_u16(b1, &u16)) != 0)
        return EXIT_FAILURE;
    else
        put_u16(b2, u16);

    /* read the u32 and store in b2 */
    if ((r = get_u32(b1, &u32)) != 0)
        return EXIT_FAILURE;
    else
        put_u32(b2, u32);

    /* read the u64 and store in b2 */
    if ((r = get_u64(b1, &u64)) != 0)
        return EXIT_FAILURE;
    else
        put_u64(b2, u64);

    /* the two buffers must be identical */
    if (buff_cmp(b1, b2) != 0) {
        buff_dump(b1);
        buff_dump(b2);
        return EXIT_FAILURE;
    }

    buff_free(b1);
    buff_free(b2);
    return EXIT_SUCCESS;
}
int test_buffer_raw_read_write(void)
{
    TEST();

    buff_t *buff = buff_new(0);
    if (!buff)
        return EXIT_FAILURE;

    int r;
    uint8_t some_data[25] = {0};
    for(int i=0; i <sizeof(some_data); i++)
        some_data[i] = i;

    r = put_raw(buff, some_data, sizeof(some_data));
    CHECK(r == E_OK);
    CHECK(buff->w == sizeof(some_data));
    buff_dump(buff);

    uint8_t recovered[25] = {0};
    r = get_raw(buff, recovered, sizeof(recovered));
    CHECK(r == E_OK);
    CHECK(buff->r == sizeof(recovered));
    buff_dump(buff);

    CHECK(memcmp(recovered, some_data, sizeof(recovered)) == 0);

    buff_free(buff);
    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    if (test_buffer_conds() != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (test_buffer_available_data() != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (test_buffer_write_utils() != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (test_buffer_resize() != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (test_buffer_read_utils() != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (test_buffer_raw_read_write() != EXIT_SUCCESS)
        return EXIT_FAILURE;

    fprintf(stderr, "Success!\n");
    return EXIT_SUCCESS;
}
