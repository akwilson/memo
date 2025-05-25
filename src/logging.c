#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#include "logging.h"

#define COL_CYAN "\x1b[36m"
#define COL_GREEN "\x1b[32m"
#define COL_ORANGE "\x1b[33m"
#define COL_RED "\x1b[31m"
#define COL_RESET "\x1b[0m"

static log_level_s get_env_log_level()
{
    const char* le = getenv("MEMO_LOG_LEVEL");
    if (le != NULL)
    {
        switch (le[0])
        {
        case 'D':
            return LOG_DEBUG;
        case 'I':
            return LOG_INFO;
        case 'W':
            return LOG_WARN;
        case 'E':
            return LOG_ERROR;
        }
    }

    return LOG_INFO;
}

void memo_log(log_level_s level, const char *func, const char *fmt, ...)
{
    static log_level_s display_level = 0;
    if (display_level == 0)
    {
        display_level = get_env_log_level();
    }

    if (level < display_level)
        return;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    
    char timebuf[20];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);

    int use_colour = isatty(STDOUT_FILENO);

    const char *level_str = NULL;
    const char *col_start = "";
    const char *col_end = "";
    
    switch (level)
    {
    case LOG_DEBUG:
        level_str = "DEBUG";
        if (use_colour) col_start = COL_CYAN;
        break;
    case LOG_INFO:
        level_str = "INFO";
        if (use_colour) col_start = COL_GREEN;
        break;
    case LOG_WARN:
        level_str = "WARN";
        if (use_colour) col_start = COL_ORANGE;
        break;
    case LOG_ERROR:
        level_str = "ERROR";
        if (use_colour) col_start = COL_RED;
        break;
    }

    if (use_colour)
        col_end = COL_RESET;

    printf("[%s] [%s%s%s] (%s): ", timebuf, col_start, level_str, col_end, func);

    va_list va;
    va_start(va, fmt);
    vprintf(fmt, va);
    va_end(va);

    putchar('\n');
}

