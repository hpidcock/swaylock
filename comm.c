#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "comm.h"
#include "log.h"
#include "password-buffer.h"
#include "swaylock.h"

/* Maximum payload size accepted from the pipe (1 MiB). */
#define COMM_MAX_PAYLOAD (1U << 20)

/*
 * comm[0]: main→child  (main writes [1], child reads [0])
 * comm[1]: child→main  (child writes [1], main reads [0])
 */
static int comm[2][2] = {{-1, -1}, {-1, -1}};

/*
 * Returns the fd the child reads incoming messages from.
 * Not declared in comm.h; pam.c references it via an extern declaration.
 */
int get_comm_child_fd(void) {
	return comm[0][0];
}

static ssize_t read_full(int fd, void *dst, size_t size) {
	char *buf = dst;
	size_t offset = 0;
	while (offset < size) {
		ssize_t n = read(fd, &buf[offset], size - offset);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			swaylock_log_errno(LOG_ERROR, "read() failed");
			return -1;
		} else if (n == 0) {
			if (offset == 0) {
				return 0;
			}
			swaylock_log(LOG_ERROR,
				"read() failed: unexpected EOF");
			return -1;
		}
		offset += n;
	}
	return (ssize_t)offset;
}

static bool write_full(int fd, const void *src, size_t size) {
	const char *buf = src;
	size_t offset = 0;
	while (offset < size) {
		ssize_t n = write(fd, &buf[offset], size - offset);
		if (n <= 0) {
			assert(n != 0);
			if (errno == EINTR) {
				continue;
			}
			swaylock_log_errno(LOG_ERROR, "write() failed");
			return false;
		}
		offset += n;
	}
	return true;
}

/* Read a 4-byte little-endian uint32 from a byte buffer. */
static uint32_t load_le32(const uint8_t *b) {
	return (uint32_t)b[0]
		| ((uint32_t)b[1] << 8)
		| ((uint32_t)b[2] << 16)
		| ((uint32_t)b[3] << 24);
}

/* Write a 4-byte little-endian uint32 into a byte buffer. */
static void store_le32(uint8_t *b, uint32_t v) {
	b[0] = (uint8_t)(v & 0xff);
	b[1] = (uint8_t)((v >> 8)  & 0xff);
	b[2] = (uint8_t)((v >> 16) & 0xff);
	b[3] = (uint8_t)((v >> 24) & 0xff);
}

/*
 * Frame layout: uint8_t type | uint32_t payload_len (LE) | payload[plen]
 *
 * Returns message type (>0) on success, 0 on EOF, -1 on error.
 * On success *payload is malloc'd (caller must free) and *len is set.
 * On EOF/error *payload is set to NULL.
 */
static int comm_read(int fd, char **payload, size_t *len) {
	uint8_t type;
	ssize_t n = read_full(fd, &type, sizeof(type));
	if (n <= 0) {
		*payload = NULL;
		return (int)n;
	}

	uint8_t plen_buf[4];
	n = read_full(fd, plen_buf, sizeof(plen_buf));
	if (n <= 0) {
		*payload = NULL;
		return -1;
	}

	uint32_t plen = load_le32(plen_buf);
	char *buf = NULL;
	if (plen > COMM_MAX_PAYLOAD) {
		swaylock_log(LOG_ERROR,
			"comm_read: payload too large: %u", plen);
		*payload = NULL;
		return -1;
	}
	if (plen > 0) {
		buf = malloc((size_t)plen + 1);
		if (!buf) {
			swaylock_log(LOG_ERROR, "allocation failed");
			*payload = NULL;
			return -1;
		}
		n = read_full(fd, buf, plen);
		if (n <= 0) {
			free(buf);
			*payload = NULL;
			return -1;
		}
		buf[plen] = '\0';
	}

	*payload = buf;
	*len = plen;
	return (int)type;
}

static bool comm_write(
	int fd, uint8_t type, const char *payload, size_t len)
{
	if (!write_full(fd, &type, sizeof(type))) {
		return false;
	}
	uint8_t plen_buf[4];
	store_le32(plen_buf, (uint32_t)len);
	if (!write_full(fd, plen_buf, sizeof(plen_buf))) {
		return false;
	}
	if (len > 0 && payload) {
		if (!write_full(fd, payload, len)) {
			return false;
		}
	}
	return true;
}

int comm_child_read(char **payload, size_t *len) {
	return comm_read(comm[0][0], payload, len);
}

bool comm_child_write(uint8_t type, const char *payload, size_t len) {
	return comm_write(comm[1][1], type, payload, len);
}

int comm_main_read(char **payload, size_t *len) {
	return comm_read(comm[1][0], payload, len);
}

bool comm_main_write(uint8_t type, const char *payload, size_t len) {
	return comm_write(comm[0][1], type, payload, len);
}

int get_comm_reply_fd(void) {
	return comm[1][0];
}

bool write_comm_password(struct swaylock_password *pw) {
	size_t size = pw->len + 1;
	char *copy = password_buffer_create(size);
	if (!copy) {
		clear_password_buffer(pw);
		return false;
	}
	memcpy(copy, pw->buffer, size);
	clear_password_buffer(pw);
	bool ok = comm_main_write(COMM_MSG_PASSWORD, copy, size);
	/* password_buffer_destroy zeros the memory before freeing */
	password_buffer_destroy(copy, size);
	return ok;
}

bool spawn_comm_child(void) {
	if (pipe(comm[0]) != 0) {
		swaylock_log_errno(LOG_ERROR, "failed to create pipe");
		return false;
	}
	if (pipe(comm[1]) != 0) {
		swaylock_log_errno(LOG_ERROR, "failed to create pipe");
		return false;
	}
	pid_t child = fork();
	if (child < 0) {
		swaylock_log_errno(LOG_ERROR, "failed to fork");
		return false;
	} else if (child == 0) {
		struct sigaction sa = {
			.sa_handler = SIG_IGN,
		};
		sigaction(SIGUSR1, &sa, NULL);
		close(comm[0][1]);
		close(comm[1][0]);
		/* Redirect stdin and stdout to /dev/null so the PAM
		 * module cannot fall back to prompting on the terminal
		 * if the main process exits or authd is unavailable. */
		int devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0) {
			dup2(devnull, STDIN_FILENO);
			dup2(devnull, STDOUT_FILENO);
			if (devnull > STDOUT_FILENO) {
				close(devnull);
			}
		}
		run_pw_backend_child();
		/* run_pw_backend_child calls exit(); unreachable */
		abort();
	}
	close(comm[0][0]);
	close(comm[1][1]);
	return true;
}