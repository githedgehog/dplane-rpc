// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#pragma once

#include "errors.h"

/* A formatting buffer used to format objects as strings
 * for logging. A single instance may be needed per thread
 * and be declared globally in single-threaded apps.
 */
struct fmt_buff {
    char *buff;      /* internal buffer, in heap */
    size_t w;        /* write offset */
    size_t capacity; /* size of buffer, auto adjusted */
};

int init_fmt_buff(struct fmt_buff *fb, size_t capacity);
void fini_fmt_buff(struct fmt_buff *fb);
void clear_fmt_buff(struct fmt_buff *fb);
char *do_write_fmt_buff(struct fmt_buff *fb, const char *restrict format, ...) __attribute__((format(printf, 2, 3)));

/* use this to format stuff */
#define fmt_buff(fb, ...) do_write_fmt_buff(fb, ##__VA_ARGS__)
