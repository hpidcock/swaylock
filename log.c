#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "log.h"

#if HAVE_DEBUG_OVERLAY
static char overlay_ring[LOG_OVERLAY_LINES][LOG_OVERLAY_LINE_LEN];
static int  overlay_head  = 0;
static int  overlay_count = 0;

/* Snapshot returned by swaylock_log_get_overlay, sorted oldest-first. */
static char overlay_snap[LOG_OVERLAY_LINES][LOG_OVERLAY_LINE_LEN];
#endif

static enum log_importance log_importance = LOG_ERROR;

static const char *verbosity_colors[] = {
	[LOG_SILENT] = "",
	[LOG_ERROR ] = "\x1B[1;31m",
	[LOG_INFO  ] = "\x1B[1;34m",
	[LOG_DEBUG ] = "\x1B[1;90m",
};

void swaylock_log_init(enum log_importance verbosity) {
	if (verbosity < LOG_IMPORTANCE_LAST) {
		log_importance = verbosity;
	}
}

void _swaylock_log(enum log_importance verbosity, const char *fmt, ...) {
	if (verbosity > log_importance) {
		return;
	}

	va_list args;
	va_start(args, fmt);

	// prefix the time to the log message
	struct tm result;
	time_t t = time(NULL);
	struct tm *tm_info = localtime_r(&t, &result);
	char buffer[26];

	// generate time prefix
	strftime(buffer, sizeof(buffer), "%F %T - ", tm_info);
	fprintf(stderr, "%s", buffer);

	unsigned c = (verbosity < LOG_IMPORTANCE_LAST)
		? verbosity : LOG_IMPORTANCE_LAST - 1;

	if (isatty(STDERR_FILENO)) {
		fprintf(stderr, "%s", verbosity_colors[c]);
	}

	vfprintf(stderr, fmt, args);

	if (isatty(STDERR_FILENO)) {
		fprintf(stderr, "\x1B[0m");
	}
	fprintf(stderr, "\n");

	va_end(args);

#if HAVE_DEBUG_OVERLAY
	/* Push only the message text (no timestamp) into the ring buffer.
	 * We need a fresh va_list because the original has been consumed. */
	va_list args2;
	va_start(args2, fmt);
	vsnprintf(overlay_ring[overlay_head], LOG_OVERLAY_LINE_LEN, fmt, args2);
	va_end(args2);

	overlay_head = (overlay_head + 1) % LOG_OVERLAY_LINES;
	if (overlay_count < LOG_OVERLAY_LINES) {
		overlay_count++;
	}
#endif
}

#if HAVE_DEBUG_OVERLAY
const char (*swaylock_log_get_overlay(int *count))[LOG_OVERLAY_LINE_LEN] {
	*count = overlay_count;
	int start = (overlay_head - overlay_count + LOG_OVERLAY_LINES)
		% LOG_OVERLAY_LINES;
	for (int i = 0; i < overlay_count; i++) {
		int idx = (start + i) % LOG_OVERLAY_LINES;
		memcpy(overlay_snap[i], overlay_ring[idx], LOG_OVERLAY_LINE_LEN);
	}
	return (const char (*)[LOG_OVERLAY_LINE_LEN])overlay_snap;
}
#endif

const char *_swaylock_strip_path(const char *filepath) {
	if (*filepath == '.') {
		while (*filepath == '.' || *filepath == '/') {
			++filepath;
		}
	}
	return filepath;
}
