#ifndef _SHSC_SHARE_LOG_H_
#define _SHSC_SHARE_LOG_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace shsc {

namespace log {

enum LogLevel {
    NOTICE, TRACE, DEBUG, WARN, FATAL
};

extern LogLevel g_loglevel;

inline LogLevel GetLogLevel() { return g_loglevel; }
inline void SetLogLevel(LogLevel level) { g_loglevel = level; }

} // namespace log


#define LOG_NOTICE(fmt, ...) if (shsc::log::GetLogLevel() <= shsc::log::NOTICE) \
    fprintf(stderr, "[NOTICE][%s:%d]" fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_TRACE(fmt, ...) if (shsc::log::GetLogLevel() <= shsc::log::TRACE) \
    fprintf(stderr, "[TRACE][%s:%d]" fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) if (shsc::log::GetLogLevel() <= shsc::log::DEBUG) \
    fprintf(stderr, "[DEBUG][%s:%d]" fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) if (shsc::log::GetLogLevel() <= shsc::log::WARN) \
    fprintf(stderr, "[WARN][%s:%d]" fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_FATAL(fmt, ...) if (shsc::log::GetLogLevel() <= shsc::log::FATAL) \
    fprintf(stderr, "[FATAL][%s:%d]" fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__);abort();

} // namespace shsc

#endif // _SHSC_SHARE_LOG_H_
