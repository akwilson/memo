#pragma once
#include <stdarg.h>

#define log_debug(...) memo_log(LOG_DEBUG, __func__, __VA_ARGS__)
#define log_info(...) memo_log(LOG_INFO, __func__, __VA_ARGS__)
#define log_warn(...) memo_log(LOG_WARN, __func__, __VA_ARGS__)
#define log_error(...) memo_log(LOG_ERROR, __func__, __VA_ARGS__)

/**
 * Message logging level for the memo_log function.
 */
typedef enum log_level
{
    LOG_DEBUG = 1,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} log_level_s;

/**
 * Sends a log message to stdout.
 *
 * @param `level` the message level to be logged at
 * @param `func`  name of the function the call is made from
 * @param `fmt`   vararg message format
 */
void memo_log(log_level_s level, const char *func, const char *fmt, ...);
