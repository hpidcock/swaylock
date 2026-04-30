#ifndef _SWAYLOCK_COMM_H
#define _SWAYLOCK_COMM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct swaylock_password;

/*
 * IPC between the main swaylock process and the PAM child process.
 *
 * Each message frame:
 *   uint8_t  type
 *   uint32_t payload_len  (little-endian)
 *   uint8_t  payload[payload_len]
 *
 * The protocol is simplex in each direction: the main process writes to
 * one pipe and the child writes to another.  Either side can send at any
 * time; there is no request/reply pairing enforced at this layer.
 */

/* Messages sent from the main process to the PAM child. */
#define COMM_MSG_PASSWORD       0x01  /* null-terminated password string */
#define COMM_MSG_BROKER_SEL     0x02  /* null-terminated broker ID */
#define COMM_MSG_AUTH_MODE_SEL  0x03  /* null-terminated auth mode ID */
#define COMM_MSG_BUTTON         0x04  /* no payload: optional button press */
#define COMM_MSG_CANCEL         0x05  /* no payload: cancel current auth */

/* Messages sent from the PAM child to the main process. */
#define COMM_MSG_AUTH_RESULT    0x81  /* 1 byte: 0=failure, 1=success */
#define COMM_MSG_BROKERS        0x82  /* JSON: [{id,name},...] */
#define COMM_MSG_AUTH_MODES     0x83  /* JSON: [{id,label},...] */
#define COMM_MSG_UI_LAYOUT      0x84  /* JSON UILayout object */
#define COMM_MSG_STAGE          0x85  /* 1 byte: enum authd_stage value */
#define COMM_MSG_AUTH_EVENT     0x86  /* JSON: {access,msg} */

bool spawn_comm_child(void);

/*
 * Low-level frame I/O.
 *
 * On success, *payload is set to a malloc'd buffer (caller must free) and
 * *len is set to the payload length.  Returns the message type (>0) on
 * success, 0 on EOF, or -1 on error.  *payload is set to NULL on EOF/error.
 */
int  comm_child_read(char **payload, size_t *len);
bool comm_child_write(uint8_t type, const char *payload, size_t len);

int  comm_main_read(char **payload, size_t *len);
bool comm_main_write(uint8_t type, const char *payload, size_t len);

/* FD to poll for messages from the child (for the main process event loop). */
int get_comm_reply_fd(void);

/*
 * Clears and sends the password buffer as a COMM_MSG_PASSWORD frame.
 * The password buffer is always cleared before this function returns,
 * whether or not the send succeeds.
 */
bool write_comm_password(struct swaylock_password *pw);

#endif