#define _POSIX_C_SOURCE 200112L

#include "log.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <unistd.h>

#define ANSI_RESET "\033[0m"
#define ANSI_FG(color, str) "\033[0;" color "m" str ANSI_RESET

#define ANSI_FG_RED(str) ANSI_FG("31", str)
#define ANSI_FG_GREEN(str) ANSI_FG("32", str)
#define ANSI_FG_YELLOW(str) ANSI_FG("33", str)
#define ANSI_FG_CYAN(str) ANSI_FG("36", str)
#define ANSI_FG_BRIGHT_CYAN(str) ANSI_FG("96", str)
#define ANSI_FG_GREY(str) ANSI_FG("90", str)

#define STRERROR_BUFSIZE 256

log_level_t _log_level = DEFAULT_LOG_LEVEL;
static bool log_colored = false;

static const char* LEVEL_STR[] = {
    [LOG_DEBUG] = "DEBUG",
    [LOG_INFO] = "INFO",
    [LOG_WARN] = "WARN",
    [LOG_ERROR] = "ERROR",
    [LOG_FATAL] = "FATAL",
};
static const char* LEVEL_STR_COLOR[] = {
    [LOG_DEBUG] = ANSI_FG_GREY("DEBUG"),
    [LOG_INFO] = ANSI_FG_GREEN("INFO"),
    [LOG_WARN] = ANSI_FG_YELLOW("WARN"),
    [LOG_ERROR] = ANSI_FG_RED("ERROR"),
    [LOG_FATAL] = ANSI_FG_RED("FATAL"),
};

void log_init(log_level_t level)
{
    _log_level = level;
    log_colored = (isatty(fileno(stderr)) != 0);
}

void _log(log_level_t type, int print_errno, const char* file, int line, const char* format, ...)
{
    time_t timer;
    struct tm time_info;
    char time_str[9];

    int errno_copy = 0;
    char errno_str[STRERROR_BUFSIZE];

    if (print_errno) {
        errno_copy = errno;
    }

    timer = time(NULL);
    localtime_r(&timer, &time_info);
    strftime(time_str, sizeof(time_str), "%H:%M:%S", &time_info);

    flockfile(stderr);

    if (log_colored) {
        fprintf(stderr, ANSI_FG_GREY("%s") " %s " ANSI_FG_CYAN("%s") ":" ANSI_FG_BRIGHT_CYAN("%d") " ",
            time_str, LEVEL_STR_COLOR[type], file, line);
    } else {
        fprintf(stderr, "%s %s %s:%d ", time_str, LEVEL_STR[type], file, line);
    }

    va_list args;
    va_start(args, format);

    vfprintf(stderr, format, args);

    va_end(args);

    if (print_errno && errno_copy != 0) {
        if (strerror_r(errno_copy, errno_str, sizeof(errno_str)) == 0) {
            fprintf(stderr, " (%s)", errno_str);
        } else {
            fputs(" (Unknown error)", stderr);
        }
    }

    fputc('\n', stderr);
    fflush(stderr);

    funlockfile(stderr);

    if (type == LOG_FATAL) {
        exit(EXIT_FAILURE);
    }
}