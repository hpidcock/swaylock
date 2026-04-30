#include <assert.h>
#include <errno.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xkbcommon/xkbcommon.h>
#include "comm.h"
#include "log.h"
#include "loop.h"
#include "seat.h"
#include "swaylock.h"
#include "unicode.h"

void clear_buffer(char *buf, size_t size) {
	// Use volatile keyword so so compiler can't optimize this out.
	volatile char *buffer = buf;
	volatile char zero = '\0';
	for (size_t i = 0; i < size; ++i) {
		buffer[i] = zero;
	}
}

void clear_password_buffer(struct swaylock_password *pw) {
	clear_buffer(pw->buffer, pw->buffer_len);
	pw->len = 0;
}

static bool backspace(struct swaylock_password *pw) {
	if (pw->len != 0) {
		pw->len -= utf8_last_size(pw->buffer);
		pw->buffer[pw->len] = 0;
		return true;
	}
	return false;
}

static void append_ch(struct swaylock_password *pw, uint32_t codepoint) {
	size_t utf8_size = utf8_chsize(codepoint);
	if (pw->len + utf8_size + 1 >= pw->buffer_len) {
		// TODO: Display error
		return;
	}
	utf8_encode(&pw->buffer[pw->len], codepoint);
	pw->buffer[pw->len + utf8_size] = 0;
	pw->len += utf8_size;
}

static void set_input_idle(void *data) {
	struct swaylock_state *state = data;
	state->input_idle_timer = NULL;
	state->input_state = INPUT_STATE_IDLE;
	damage_state(state);
}

static void set_auth_idle(void *data) {
	struct swaylock_state *state = data;
	state->auth_idle_timer = NULL;
	state->auth_state = AUTH_STATE_IDLE;
	damage_state(state);
}

static void schedule_input_idle(struct swaylock_state *state) {
	if (state->input_idle_timer) {
		loop_remove_timer(state->eventloop, state->input_idle_timer);
	}
	state->input_idle_timer = loop_add_timer(
		state->eventloop, 1500, set_input_idle, state);
}

static void cancel_input_idle(struct swaylock_state *state) {
	if (state->input_idle_timer) {
		loop_remove_timer(state->eventloop, state->input_idle_timer);
		state->input_idle_timer = NULL;
	}
}

void schedule_auth_idle(struct swaylock_state *state) {
	if (state->auth_idle_timer) {
		loop_remove_timer(state->eventloop, state->auth_idle_timer);
	}
	state->auth_idle_timer = loop_add_timer(
		state->eventloop, 3000, set_auth_idle, state);
}

static void clear_password(void *data) {
	struct swaylock_state *state = data;
	state->clear_password_timer = NULL;
	state->input_state = INPUT_STATE_CLEAR;
	schedule_input_idle(state);
	clear_password_buffer(&state->password);
	damage_state(state);
}

static void schedule_password_clear(struct swaylock_state *state) {
	if (state->clear_password_timer) {
		loop_remove_timer(
			state->eventloop, state->clear_password_timer);
	}
	state->clear_password_timer = loop_add_timer(
		state->eventloop, 10000, clear_password, state);
}

static void cancel_password_clear(struct swaylock_state *state) {
	if (state->clear_password_timer) {
		loop_remove_timer(
			state->eventloop, state->clear_password_timer);
		state->clear_password_timer = NULL;
	}
}

static void submit_password(struct swaylock_state *state) {
	if (state->args.ignore_empty && state->password.len == 0) {
		swaylock_log(LOG_DEBUG,
			"submit_password: skipped (ignore_empty)");
		return;
	}
	if (state->auth_state == AUTH_STATE_VALIDATING) {
		swaylock_log(LOG_DEBUG,
			"submit_password: skipped (already validating)");
		return;
	}

	swaylock_log(LOG_DEBUG,
		"submit_password: sending (len=%zu) auth=idle -> validating",
		state->password.len);
	state->input_state = INPUT_STATE_IDLE;
	state->auth_state = AUTH_STATE_VALIDATING;
	cancel_password_clear(state);
	cancel_input_idle(state);

	if (!write_comm_password(&state->password)) {
		swaylock_log(LOG_DEBUG,
			"submit_password: write failed"
			" auth=validating -> invalid");
		state->auth_state = AUTH_STATE_INVALID;
		schedule_auth_idle(state);
	}

	damage_state(state);
}

static void update_highlight(struct swaylock_state *state) {
	// Advance a random amount between 1/4 and 3/4 of a full turn
	state->highlight_start =
		(state->highlight_start + (rand() % 1024) + 512) % 2048;
}

void swaylock_handle_key(struct swaylock_state *state,
		xkb_keysym_t keysym, uint32_t codepoint) {

	/* In broker or auth-mode selection, Up/Down navigate the list and
	 * Enter confirms. Tab presses the optional button. */
	if (state->authd_active) {
		if (state->authd_stage == AUTHD_STAGE_BROKER ||
				state->authd_stage == AUTHD_STAGE_AUTH_MODE) {
			bool is_broker =
				state->authd_stage == AUTHD_STAGE_BROKER;
			if (keysym == XKB_KEY_Up) {
				if (is_broker) {
					if (state->authd_sel_broker > 0) {
						--state->authd_sel_broker;
					}
				} else {
					if (state->authd_sel_auth_mode > 0) {
						--state->authd_sel_auth_mode;
					}
				}
				damage_state(state);
				return;
			} else if (keysym == XKB_KEY_Down) {
				if (is_broker) {
					if (state->authd_sel_broker <
							state->authd_num_brokers - 1) {
						++state->authd_sel_broker;
					}
				} else {
					if (state->authd_sel_auth_mode <
							state->authd_num_auth_modes - 1) {
						++state->authd_sel_auth_mode;
					}
				}
				damage_state(state);
				return;
			} else if (keysym == XKB_KEY_Return ||
					keysym == XKB_KEY_KP_Enter) {
				if (is_broker) {
					int sel = state->authd_sel_broker;
					if (sel >= 0 &&
							sel < state->authd_num_brokers) {
						const char *id =
							state->authd_brokers[sel].id;
						if (id)
							comm_main_write(
								COMM_MSG_BROKER_SEL,
								id, strlen(id) + 1);
					}
				} else {
					int sel = state->authd_sel_auth_mode;
					if (sel >= 0 &&
							sel < state->authd_num_auth_modes) {
						const char *id =
							state->authd_auth_modes[sel].id;
						if (id)
							comm_main_write(
								COMM_MSG_AUTH_MODE_SEL,
								id, strlen(id) + 1);
					}
				}
				return;
			} else if (keysym == XKB_KEY_Escape) {
				comm_main_write(COMM_MSG_CANCEL, NULL, 0);
				return;
			}
		}
		if (state->authd_stage == AUTHD_STAGE_CHALLENGE) {
			if (keysym == XKB_KEY_Tab &&
					state->authd_layout.button != NULL) {
				comm_main_write(COMM_MSG_BUTTON, NULL, 0);
				damage_state(state);
				return;
			}
		}
	}

	switch (keysym) {
	case XKB_KEY_KP_Enter: /* fallthrough */
	case XKB_KEY_Return:
		submit_password(state);
		break;
	case XKB_KEY_Delete:
	case XKB_KEY_BackSpace:
		if (state->xkb.control) {
			clear_password_buffer(&state->password);
			state->input_state = INPUT_STATE_CLEAR;
			cancel_password_clear(state);
		} else {
			if (backspace(&state->password) &&
					state->password.len != 0) {
				state->input_state = INPUT_STATE_BACKSPACE;
				schedule_password_clear(state);
				update_highlight(state);
			} else {
				state->input_state = INPUT_STATE_CLEAR;
				cancel_password_clear(state);
			}
		}
		schedule_input_idle(state);
		damage_state(state);
		break;
	case XKB_KEY_Escape:
		clear_password_buffer(&state->password);
		state->input_state = INPUT_STATE_CLEAR;
		cancel_password_clear(state);
		schedule_input_idle(state);
		damage_state(state);
		break;
	case XKB_KEY_Caps_Lock:
	case XKB_KEY_Shift_L:
	case XKB_KEY_Shift_R:
	case XKB_KEY_Control_L:
	case XKB_KEY_Control_R:
	case XKB_KEY_Meta_L:
	case XKB_KEY_Meta_R:
	case XKB_KEY_Alt_L:
	case XKB_KEY_Alt_R:
	case XKB_KEY_Super_L:
	case XKB_KEY_Super_R:
		state->input_state = INPUT_STATE_NEUTRAL;
		schedule_password_clear(state);
		schedule_input_idle(state);
		damage_state(state);
		break;
	case XKB_KEY_m: /* fallthrough */
	case XKB_KEY_d:
	case XKB_KEY_j:
		if (state->xkb.control) {
			submit_password(state);
			break;
		}
		// fallthrough
	case XKB_KEY_c: /* fallthrough */
	case XKB_KEY_u:
		if (state->xkb.control) {
			clear_password_buffer(&state->password);
			state->input_state = INPUT_STATE_CLEAR;
			cancel_password_clear(state);
			schedule_input_idle(state);
			damage_state(state);
			break;
		}
		// fallthrough
	default:
		if (codepoint) {
			append_ch(&state->password, codepoint);
			state->input_state = INPUT_STATE_LETTER;
			schedule_password_clear(state);
			schedule_input_idle(state);
			update_highlight(state);
			damage_state(state);
		}
		break;
	}
}