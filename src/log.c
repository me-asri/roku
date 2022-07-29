#define _POSIX_C_SOURCE 200112L

#include "log.h"

#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>

const char *LEVEL_STR[] = {
    [LOG_INFO] = "INFO",
    [LOG_WARN] = "WARN",
    [LOG_ERROR] = "ERROR",
    [LOG_DEBUG] = "DEBUG",
    [LOG_FATAL] = "FATAL",
};

void _log(log_level_t type, const char *file, int line, const char *format, ...)
{
    time_t timer = time(NULL);
    struct tm time_info = {0};
    localtime_r(&timer, &time_info);

    char time_str[9];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", &time_info);

    // Print meta info
    FILE *out = (type == LOG_INFO) ? stdout : stderr;
    fprintf(out, "%s %s %s:%d: ", time_str, LEVEL_STR[type], file, line);

    // Print user-provided message
    va_list args;
    va_start(args, format);

    vfprintf(out, format, args);

    va_end(args);

    // Print newline and flush stream
    fputc('\n', out);
    fflush(out);

    if (type == LOG_FATAL)
        exit(EXIT_FAILURE);
}