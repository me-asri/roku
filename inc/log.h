#pragma once

typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL
} log_level_t;

#define DEFAULT_LOG_LEVEL LOG_INFO

extern log_level_t _log_level;

void log_init(log_level_t level);
void _log(log_level_t type, int print_errno, const char* file, int line, const char* format, ...);

#define LOG(level, err, format, args...)                          \
    do {                                                          \
        if (level >= _log_level) {                                \
            _log(level, err, __FILE__, __LINE__, format, ##args); \
        }                                                         \
    } while (0)

#define log_i(format, args...) LOG(LOG_INFO, 0, format, ##args)
#define elog_i(format, args...) LOG(LOG_INFO, 1, format, ##args)

#define log_w(format, args...) LOG(LOG_WARN, 0, format, ##args)
#define elog_w(format, args...) LOG(LOG_WARN, 1, format, ##args)

#define log_e(format, args...) LOG(LOG_ERROR, 0, format, ##args)
#define elog_e(format, args...) LOG(LOG_ERROR, 1, format, ##args)

#define log_d(format, args...) LOG(LOG_DEBUG, 0, format, ##args)
#define elog_d(format, args...) LOG(LOG_DEBUG, 1, format, ##args)

#define log_f(format, args...) LOG(LOG_FATAL, 0, format, ##args)
#define elog_f(format, args...) LOG(LOG_FATAL, 1, format, ##args)