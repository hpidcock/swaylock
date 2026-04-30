#ifndef _SWAYLOCK_LOG_H
#define _SWAYLOCK_LOG_H

#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include "config.h"

enum log_importance {
	LOG_SILENT = 0,
	LOG_ERROR = 1,
	LOG_INFO = 2,
	LOG_DEBUG = 3,
	LOG_IMPORTANCE_LAST,
};

void swaylock_log_init(enum log_importance verbosity);

#ifdef __GNUC__
#define _ATTRIB_PRINTF(start, end) __attribute__((format(printf, start, end)))
#else
#define _ATTRIB_PRINTF(start, end)
#endif

void _swaylock_log(enum log_importance verbosity, const char *format, ...)
	_ATTRIB_PRINTF(2, 3);

const char *_swaylock_strip_path(const char *filepath);

#define swaylock_log(verb, fmt, ...) \
	_swaylock_log(verb, "[%s:%d] " fmt, _swaylock_strip_path(__FILE__), \
			__LINE__, ##__VA_ARGS__)

#define swaylock_log_errno(verb, fmt, ...) \
	swaylock_log(verb, fmt ": %s", ##__VA_ARGS__, strerror(errno))

#if HAVE_DEBUG_OVERLAY

#define LOG_OVERLAY_LINES    24
#define LOG_OVERLAY_LINE_LEN 220

/*
 * Returns the buffered log lines as a pointer to a static array of
 * fixed-width C strings, oldest line first.  *count is set to the
 * number of valid lines (0..LOG_OVERLAY_LINES).  The pointer is to
 * an internal snapshot buffer; callers must not free or write to it.
 * Not thread-safe — only call from the main process.
 */
const char (*swaylock_log_get_overlay(int *count))[LOG_OVERLAY_LINE_LEN];

#endif /* HAVE_DEBUG_OVERLAY */

#include <assert.h>

#if HAVE_DEBUG_OVERLAY
/* In debug builds, assertions log the failure but do not abort,
 * allowing the session to remain unlocked for further debugging. */
#undef assert
#define assert(cond) \
	do { \
		if (!(cond)) { \
			swaylock_log(LOG_ERROR, \
				"assertion failed: %s", #cond); \
		} \
	} while(0)
#endif /* HAVE_DEBUG_OVERLAY */

#endif
