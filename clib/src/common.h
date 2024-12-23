#pragma once

#include <assert.h>
#include <stdio.h>
#include <syslog.h>

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

extern int loglevel;

/* return codes */
#define E_OK 0              /* all good */
#define E_BUG 1             /* there is a bug */
#define E_OOM 2             /* ran out of mem */
#define E_NOT_ENOUGH_DATA 3 /* buffer has less octets than needed */
#define E_TOO_BIG 4         /* msg is too big to be encoded */
#define E_INVAL 5           /* invalid data has been provided */
#define E_INVALID_DATA                                                         \
  6 /* invalid data has been received or we're unable to decode it */
#define E_INCONSIST_LEN                                                        \
  7 /* rx msg length does not match available octets to process */
#define E_INVALID_MSG_TYPE 8 /* rx msg has invalid (unknown) type */
#define E_EXCESS_BYTES 9     /* rx msg has bytes that were not decoded */
#define E_TOO_MANY_NHOPS                                                       \
  10 /* the maximum number of nexthops supported has been exceeded */
#define E_TOO_MANY_OBJECTS                                                     \
  11 /* the maximum number of objects has been exceeded */
#define E_TOO_MANY_MATCH_VALUES                                                \
  12 /* the maximum number of match values has been reached */
#define E_VEC_CAPACITY_EXCEEDED                                                \
  13 /* the capacity of a vector has been exceeded */

/* logging macro */
#define LOG(level, fmt, ...)                                                   \
  do {                                                                         \
    if (level <= loglevel)                                                     \
      fprintf(stderr, fmt "\n" __VA_OPT__(, ) __VA_ARGS__);                    \
  } while (0)

/* log macros */
#define log_err(fmt, ...) LOG(LOG_ERR, fmt, __VA_ARGS__)
#define log_warn(fmt, ...) LOG(LOG_WARNING, fmt, __VA_ARGS__)
#define log_notice(fmt, ...) LOG(LOG_NOTICE, fmt, __VA_ARGS__)
#define log_info(fmt, ...) LOG(LOG_INFO, fmt, __VA_ARGS__)
#define log_dbg(fmt, ...) LOG(LOG_DEBUG, fmt, __VA_ARGS__)

/* Assert if some condition is not met */
#define BUG(cond, ...)                                                         \
  do {                                                                         \
    if (unlikely(cond)) {                                                      \
      fprintf(stderr, "BUG: '%s' at %s, %s():%d]", #cond, __FILE__,            \
              __FUNCTION__, __LINE__);                                         \
      assert(0);                                                               \
      return __VA_ARGS__;                                                      \
    }                                                                          \
  } while (0)

const char *err2str(int e);
