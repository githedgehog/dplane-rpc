// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#pragma once

#include <assert.h>
#include <stdio.h>
#include <syslog.h>

#include "errors.h"

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

extern int loglevel;

/* logging macro */
#define LOG(level, fmt, ...)                                      \
    do {                                                          \
        if (level <= loglevel)                                    \
            fprintf(stderr, fmt "\n" __VA_OPT__(, ) __VA_ARGS__); \
    } while (0)

/* log macros */
#define log_err(fmt, ...) LOG(LOG_ERR, fmt, __VA_ARGS__)
#define log_warn(fmt, ...) LOG(LOG_WARNING, fmt, __VA_ARGS__)
#define log_notice(fmt, ...) LOG(LOG_NOTICE, fmt, __VA_ARGS__)
#define log_info(fmt, ...) LOG(LOG_INFO, fmt, __VA_ARGS__)
#define log_dbg(fmt, ...) LOG(LOG_DEBUG, fmt, __VA_ARGS__)

/* Assert if some condition is not met */
#define BUG(cond, ...)                                        \
    do {                                                      \
        if (unlikely(cond)) {                                 \
            fprintf(stderr, "BUG: '%s' at %s, %s():%d]",      \
                    #cond, __FILE__, __FUNCTION__, __LINE__); \
            assert(0);                                        \
            return __VA_ARGS__;                               \
        }                                                     \
    } while (0)
