#ifndef ROKU_LOG_H
#define ROKU_LOG_H

typedef enum
{
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_DEBUG,
    LOG_FATAL
} log_level_t;

void _log(log_level_t type, const char *file, int line, const char *format, ...);

#define log_info(format, args...) _log(LOG_INFO, __FILE__, __LINE__, format, ##args)
#define log_warn(format, args...) _log(LOG_WARN, __FILE__, __LINE__, format, ##args)
#define log_error(format, args...) _log(LOG_ERROR, __FILE__, __LINE__, format, ##args)

#ifdef DEBUG
#define log_debug(format, args...) _log(LOG_DEBUG, __FILE__, __LINE__, format, ##args)
#else
#define log_debug(msg)
#endif

#define die(format, args...) _log(LOG_FATAL, __FILE__, __LINE__, format, ##args)

#endif
