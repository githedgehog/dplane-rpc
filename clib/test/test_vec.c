// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "test_common.h"
#include "../src/vec.h"

/* some custom object for which we want a vector */
struct foo {
    int i;
    uint64_t k;
    char *bar;
};
DECL_VEC_TYPE(foo, struct foo);
DEF_PUSH_VEC_PTR(foo, struct foo);

int test_vec_foo_push(void)
{
    TEST();

    vec_foo v = {0};
    struct foo DATA[4];
    memset(DATA, 0, sizeof(DATA));

    DATA[0].i = 1;
    DATA[0].k = 1789;
    DATA[0].bar = "Luke";

    DATA[1].i = 2;
    DATA[1].k = 1492;
    DATA[1].bar = "Leia";

    DATA[2].i = 3;
    DATA[2].k = 476;
    DATA[2].bar = "Darth";

    DATA[3].i = 4;
    DATA[3].k = 1714;
    DATA[3].bar = "r2d2";

    int i;
    for (i = 0; i < 4; i++)
        vec_push_foo(&v, &DATA[i]);

    for (int i = 0; i < v.len; i++) {
        if (memcmp(&DATA[i], &v.data[i], sizeof(struct foo)) != 0)
            return EXIT_FAILURE;
    }

    vec_dispose(&v);
    return EXIT_SUCCESS;
}

int test_vec_u32_push(void)
{
    TEST();
    vec_u32 v = {0};

    int r;
    for(size_t i = 0; i < UINT8_MAX; i++) {
       r = vec_push_u32(&v, i);
       CHECK(r == E_OK);
    }

    assert(v.len == UINT8_MAX);
    for(size_t i = 0; i < v.len ; i++)
        if (v.data[i] != i)
            return EXIT_FAILURE;

    r = vec_push_u32(&v, 123456);

    vec_dispose(&v);
    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    if (test_vec_u32_push() != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (test_vec_foo_push() != EXIT_SUCCESS)
        return EXIT_FAILURE;

    fprintf(stderr, "Success!\n");
    return EXIT_SUCCESS;
}
