#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "fmt_buff.h"

#define DFLT_FMT_BUFF_SIZE 1024

int init_fmt_buff(struct fmt_buff *fb, size_t capacity)
{
    BUG(!fb, E_BUG);

    if (!capacity)
        capacity = DFLT_FMT_BUFF_SIZE;

    memset(fb, 0, sizeof(*fb));
    fb->buff = calloc(1, capacity);
    if (!fb->buff)
        return E_OOM;

    fb->capacity = capacity;
    return 0;
}
void fini_fmt_buff(struct fmt_buff *fb)
{
    BUG(!fb);
    if (fb->buff)
        free(fb->buff);
    memset(fb, 0, sizeof(*fb));
}
void clear_fmt_buff(struct fmt_buff *fb)
{
    BUG(!fb);
    BUG(!fb->buff || !fb->capacity);
    fb->w = 0;
    fb->buff[fb->w] = '\0';
}

static inline int resize_fmt_buff(struct fmt_buff *fb, size_t additional)
{
    BUG(!fb, E_BUG);
    BUG(!additional, E_BUG);

    size_t new_capacity = fb->capacity + additional;
    void *x = realloc(fb->buff, new_capacity);
    if (!x) {
        log_err("Unable to reallocate fmt_buff!!");
        return E_OOM;
    }
    else {
        fb->buff = x;
        fb->capacity = new_capacity;
        return E_OK;
    }
}

char *do_write_fmt_buff(struct fmt_buff *fb, const char *restrict fmt, ...)
{
    BUG(!fb || !fmt, NULL);
    BUG(!fb->buff, NULL);

retry:
    va_list ap;
    va_start(ap, fmt);
    size_t room = (fb->capacity >= fb->w) ? (fb->capacity - fb->w) : 0;
    int w = vsnprintf(fb->buff + fb->w, room, fmt, ap);
    va_end(ap);
    if (w >= room) {
        if (resize_fmt_buff(fb, w + 1) != E_OK)
            return NULL;
        goto retry;
    }
    else if (w < 0) {
        log_err("vsnprintf failed!");
        return NULL;
    }
    fb->w += w;
    /* ensure there's always a trailing \0 */
    if (fb->w <= fb->capacity)
        fb->buff[fb->w] = '\0';

    return fb->buff;
}
