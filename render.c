#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wayland-client.h>
#include "cairo.h"
#include "background-image.h"
#include "swaylock.h"
#include "log.h"

#if HAVE_QRENCODE
#include <qrencode.h>
#endif

#define M_PI 3.14159265358979323846
const float TYPE_INDICATOR_RANGE = M_PI / 3.0f;

/* Error text colour (ARGB) for authd error messages. */
static const uint32_t error_text_color = 0xFF4444FF;

static void set_color_for_state(cairo_t *cairo, struct swaylock_state *state,
		struct swaylock_colorset *colorset) {
	if (state->input_state == INPUT_STATE_CLEAR) {
		cairo_set_source_u32(cairo, colorset->cleared);
	} else if (state->auth_state == AUTH_STATE_VALIDATING) {
		cairo_set_source_u32(cairo, colorset->verifying);
	} else if (state->auth_state == AUTH_STATE_INVALID) {
		cairo_set_source_u32(cairo, colorset->wrong);
	} else {
		if (state->xkb.caps_lock && state->args.show_caps_lock_indicator) {
			cairo_set_source_u32(cairo, colorset->caps_lock);
		} else if (state->xkb.caps_lock && !state->args.show_caps_lock_indicator &&
				state->args.show_caps_lock_text) {
			uint32_t inputtextcolor = state->args.colors.text.input;
			state->args.colors.text.input = state->args.colors.text.caps_lock;
			cairo_set_source_u32(cairo, colorset->input);
			state->args.colors.text.input = inputtextcolor;
		} else {
			cairo_set_source_u32(cairo, colorset->input);
		}
	}
}

static void surface_frame_handle_done(void *data, struct wl_callback *callback,
		uint32_t time) {
	struct swaylock_surface *surface = data;

	wl_callback_destroy(callback);
	surface->frame = NULL;

	render(surface);
}

static const struct wl_callback_listener surface_frame_listener = {
	.done = surface_frame_handle_done,
};

static bool render_frame(struct swaylock_surface *surface);

#if HAVE_DEBUG_OVERLAY
static void render_debug_overlay(struct swaylock_surface *surface) {
	struct swaylock_state *state = surface->state;

	if (surface->width == 0 || surface->height == 0) {
		return;
	}

	int count = 0;
	const char (*lines)[LOG_OVERLAY_LINE_LEN] =
		swaylock_log_get_overlay(&count);
	if (count == 0) {
		return;
	}

	/* Measure line height using the test cairo context. */
	double font_size = 12.0 * surface->scale;
	cairo_select_font_face(state->test_cairo, state->args.font,
		CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
	cairo_set_font_size(state->test_cairo, font_size);
	cairo_font_extents_t fe;
	cairo_font_extents(state->test_cairo, &fe);

	double pad = 4.0 * surface->scale;
	int line_h = (int)ceil(fe.height + pad);

	/* Buffer covers the full output so the overlay can be positioned
	 * at (0,0) and lines can be anchored to the bottom edge. */
	int buf_w = surface->width * surface->scale;
	int buf_h = surface->height * surface->scale;

	struct pool_buffer *buf = get_next_buffer(
		state->shm, surface->overlay_buffers, buf_w, buf_h);
	if (!buf) {
		return;
	}

	/* How many lines fit; show the most recent ones. */
	int max_lines = line_h > 0 ? buf_h / line_h : 0;
	if (max_lines <= 0) {
		return;
	}
	int show = count < max_lines ? count : max_lines;
	int start = count - show;

	cairo_t *cr = buf->cairo;
	cairo_identity_matrix(cr);
	cairo_set_antialias(cr, CAIRO_ANTIALIAS_BEST);

	/* Clear to fully transparent so the background shows through
	 * above the log lines. */
	cairo_set_source_rgba(cr, 0.0, 0.0, 0.0, 0.0);
	cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
	cairo_paint(cr);
	cairo_set_operator(cr, CAIRO_OPERATOR_OVER);

	/* Semi-transparent band only behind the visible log lines,
	 * anchored to the bottom of the buffer. */
	int text_h = show * line_h;
	int text_top = buf_h - text_h;
	cairo_set_source_rgba(cr, 0.0, 0.0, 0.0, 0.75);
	cairo_rectangle(cr, 0, text_top, buf_w, text_h);
	cairo_fill(cr);

	cairo_select_font_face(cr, state->args.font,
		CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
	cairo_set_font_size(cr, font_size);
	cairo_font_extents(cr, &fe);
	cairo_set_source_rgba(cr, 1.0, 1.0, 1.0, 1.0);

	double y = text_top + fe.ascent + pad;
	for (int i = start; i < count; i++) {
		cairo_move_to(cr, pad, y);
		cairo_show_text(cr, lines[i]);
		y += line_h;
	}

	/* Overlay sits at (0,0) and covers the full output. */
	wl_subsurface_set_position(surface->overlay_sub, 0, 0);

	wl_surface_set_buffer_scale(surface->overlay, surface->scale);
	wl_surface_attach(surface->overlay, buf->buffer, 0, 0);
	wl_surface_damage_buffer(surface->overlay, 0, 0, INT32_MAX, INT32_MAX);
	wl_surface_commit(surface->overlay);
}
#endif

void render(struct swaylock_surface *surface) {
	struct swaylock_state *state = surface->state;

	int buffer_width = surface->width * surface->scale;
	int buffer_height = surface->height * surface->scale;
	if (buffer_width == 0 || buffer_height == 0) {
		return; // not yet configured
	}

	if (!surface->dirty || surface->frame) {
		// Nothing to do or frame already pending
		return;
	}

	bool need_destroy = false;
	struct pool_buffer buffer;

	if (buffer_width != surface->last_buffer_width ||
			buffer_height != surface->last_buffer_height) {
		need_destroy = true;
		if (!create_buffer(state->shm, &buffer, buffer_width, buffer_height,
				WL_SHM_FORMAT_ARGB8888)) {
			swaylock_log(LOG_ERROR,
				"Failed to create new buffer for frame background.");
			return;
		}

		cairo_t *cairo = buffer.cairo;
		cairo_set_antialias(cairo, CAIRO_ANTIALIAS_BEST);

		cairo_save(cairo);
		cairo_set_operator(cairo, CAIRO_OPERATOR_SOURCE);
		cairo_set_source_u32(cairo, state->args.colors.background);
		cairo_paint(cairo);
		if (surface->image && state->args.mode != BACKGROUND_MODE_SOLID_COLOR) {
			cairo_set_operator(cairo, CAIRO_OPERATOR_OVER);
			render_background_image(cairo, surface->image,
				state->args.mode, buffer_width, buffer_height);
		}
		cairo_restore(cairo);
		cairo_identity_matrix(cairo);

		wl_surface_attach(surface->surface, buffer.buffer, 0, 0);
		wl_surface_damage_buffer(surface->surface, 0, 0, INT32_MAX, INT32_MAX);
		need_destroy = true;

		surface->last_buffer_width = buffer_width;
		surface->last_buffer_height = buffer_height;
	}

	// It is possible for the surface scale to change even if the wl_buffer size hasn't
	wl_surface_set_buffer_scale(surface->surface, surface->scale);

	render_frame(surface);
#if HAVE_DEBUG_OVERLAY
	render_debug_overlay(surface);
#endif
	surface->dirty = false;
	surface->frame = wl_surface_frame(surface->surface);
	wl_callback_add_listener(surface->frame, &surface_frame_listener, surface);
	wl_surface_commit(surface->surface);

	if (need_destroy) {
		destroy_buffer(&buffer);
	}
}

static void configure_font_drawing(cairo_t *cairo, struct swaylock_state *state,
		enum wl_output_subpixel subpixel, int arc_radius) {
	cairo_font_options_t *fo = cairo_font_options_create();
	cairo_font_options_set_hint_style(fo, CAIRO_HINT_STYLE_FULL);
	cairo_font_options_set_antialias(fo, CAIRO_ANTIALIAS_SUBPIXEL);
	cairo_font_options_set_subpixel_order(fo, to_cairo_subpixel_order(subpixel));

	cairo_set_font_options(cairo, fo);
	cairo_select_font_face(cairo, state->args.font,
		CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
	if (state->args.font_size > 0) {
		cairo_set_font_size(cairo, state->args.font_size);
	} else {
		cairo_set_font_size(cairo, arc_radius / 3.0f);
	}
	cairo_font_options_destroy(fo);
}

static bool render_frame(struct swaylock_surface *surface) {
	struct swaylock_state *state = surface->state;
	int scale = surface->scale;
	int arc_radius = state->args.radius * scale;
	int arc_thickness = state->args.thickness * scale;
	int buffer_diameter = (arc_radius + arc_thickness) * 2;

	/*
	 * Broker / auth-mode stage: render a vertical selection list and
	 * return early — no ring is drawn for these stages.
	 */
	if (state->authd_active && (
			state->authd_stage == AUTHD_STAGE_BROKER ||
			state->authd_stage == AUTHD_STAGE_AUTH_MODE)) {
		bool is_broker = state->authd_stage == AUTHD_STAGE_BROKER;
		int count = is_broker
			? state->authd_num_brokers
			: state->authd_num_auth_modes;
		int sel = is_broker
			? state->authd_sel_broker
			: state->authd_sel_auth_mode;

		configure_font_drawing(state->test_cairo, state,
			surface->subpixel, arc_radius);
		cairo_font_extents_t fe;
		cairo_font_extents(state->test_cairo, &fe);

		/* Show at most 8 items, centred around the selection. */
		int max_vis = 8;
		int vis_count = count < max_vis ? count : max_vis;
		int start = 0;
		if (count > max_vis && sel >= 0) {
			start = sel - max_vis / 2;
			if (start < 0) {
				start = 0;
			} else if (start + max_vis > count) {
				start = count - max_vis;
			}
		}

		double box_padding = 4.0 * scale;
		double item_height = fe.height * 1.5;
		double max_text_w = 0;

		for (int i = start; i < start + vis_count; i++) {
			const char *name = is_broker
				? state->authd_brokers[i].name
				: state->authd_auth_modes[i].label;
			if (!name) {
				name = "";
			}
			cairo_text_extents_t ext;
			cairo_text_extents(state->test_cairo, name, &ext);
			if (ext.width > max_text_w) {
				max_text_w = ext.width;
			}
		}

		int buffer_width = (int)(max_text_w + 4.0 * box_padding);
		int buffer_height =
			(int)(vis_count * item_height + 2.0 * box_padding);
		buffer_width += scale - (buffer_width % scale);
		buffer_height += scale - (buffer_height % scale);

		int subsurf_xpos, subsurf_ypos;
		if (state->args.override_indicator_x_position) {
			subsurf_xpos = state->args.indicator_x_position -
				buffer_width / (2 * scale);
		} else {
			subsurf_xpos = surface->width / 2 -
				buffer_width / (2 * scale);
		}
		if (state->args.override_indicator_y_position) {
			subsurf_ypos = state->args.indicator_y_position -
				buffer_height / (2 * scale);
		} else {
			subsurf_ypos = surface->height / 2 -
				buffer_height / (2 * scale);
		}

		struct pool_buffer *buffer = get_next_buffer(state->shm,
			surface->indicator_buffers, buffer_width, buffer_height);
		if (!buffer) {
			swaylock_log(LOG_ERROR, "No buffer");
			return false;
		}

		cairo_t *cairo = buffer->cairo;
		cairo_set_antialias(cairo, CAIRO_ANTIALIAS_BEST);
		cairo_identity_matrix(cairo);

		cairo_save(cairo);
		cairo_set_source_rgba(cairo, 0, 0, 0, 0);
		cairo_set_operator(cairo, CAIRO_OPERATOR_SOURCE);
		cairo_paint(cairo);
		cairo_restore(cairo);

		configure_font_drawing(cairo, state, surface->subpixel, arc_radius);

		for (int vi = 0; vi < vis_count; vi++) {
			int i = start + vi;
			const char *name = is_broker
				? state->authd_brokers[i].name
				: state->authd_auth_modes[i].label;
			if (!name) {
				name = "";
			}
			cairo_text_extents_t ext;
			cairo_text_extents(cairo, name, &ext);

			double iy = box_padding + vi * item_height;

			/* Row background. */
			cairo_rectangle(cairo, 0, iy, buffer_width, item_height);
			if (i == sel) {
				cairo_set_source_u32(cairo,
					state->args.colors.layout_background);
			} else {
				cairo_set_source_u32(cairo,
					state->args.colors.background);
			}
			cairo_fill(cairo);

			/* Text: horizontally centred, vertically centred in row. */
			double tx = (buffer_width - ext.width) / 2.0
				- ext.x_bearing;
			double ty = iy +
				(item_height + fe.height) / 2.0 - fe.descent;
			cairo_move_to(cairo, tx, ty);
			if (i == sel) {
				cairo_set_source_u32(cairo,
					state->args.colors.layout_text);
			} else {
				cairo_set_source_u32(cairo,
					state->args.colors.text.input);
			}
			cairo_show_text(cairo, name);
		}

		wl_subsurface_set_position(
			surface->subsurface, subsurf_xpos, subsurf_ypos);
		wl_surface_set_buffer_scale(surface->child, scale);
		wl_surface_attach(surface->child, buffer->buffer, 0, 0);
		wl_surface_damage_buffer(
			surface->child, 0, 0, INT32_MAX, INT32_MAX);
		wl_surface_commit(surface->child);
		return true;
	}

	// First, compute the text that will be drawn, if any, since this
	// determines the size/positioning of the surface

	char attempts[4]; // like i3lock: count no more than 999
	char *text = NULL;
	const char *layout_text = NULL;

	bool draw_indicator = state->args.show_indicator &&
		(state->auth_state != AUTH_STATE_IDLE ||
			state->input_state != INPUT_STATE_IDLE ||
			state->args.indicator_idle_visible);

	if (draw_indicator) {
		if (state->input_state == INPUT_STATE_CLEAR) {
			// This message has highest priority
			text = "Cleared";
		} else if (state->auth_state == AUTH_STATE_VALIDATING) {
			text = "Verifying";
		} else if (state->auth_state == AUTH_STATE_INVALID) {
			text = "Wrong";
		} else {
			// Caps Lock has higher priority
			if (state->xkb.caps_lock && state->args.show_caps_lock_text) {
				text = "Caps Lock";
			} else if (state->args.show_failed_attempts &&
					state->failed_attempts > 0) {
				if (state->failed_attempts > 999) {
					text = "999+";
				} else {
					snprintf(attempts, sizeof(attempts), "%d", state->failed_attempts);
					text = attempts;
				}
			}

			if (state->xkb.keymap) {
				xkb_layout_index_t num_layout = xkb_keymap_num_layouts(state->xkb.keymap);
				if (!state->args.hide_keyboard_layout &&
						(state->args.show_keyboard_layout || num_layout > 1)) {
					xkb_layout_index_t curr_layout = 0;

					// advance to the first active layout (if any)
					while (curr_layout < num_layout &&
						xkb_state_layout_index_is_active(state->xkb.state,
							curr_layout, XKB_STATE_LAYOUT_EFFECTIVE) != 1) {
						++curr_layout;
					}
					// will handle invalid index if none are active
					layout_text = xkb_keymap_layout_get_name(state->xkb.keymap, curr_layout);
				}
			}
		}
	}

	/* QR code layout replaces the ring entirely. */
	bool is_qrcode = state->authd_active &&
		state->authd_stage == AUTHD_STAGE_CHALLENGE &&
		state->authd_layout.type &&
		strcmp(state->authd_layout.type, "qrcode") == 0;

#if HAVE_QRENCODE
	QRcode *qrcode = NULL;
	if (is_qrcode && state->authd_layout.qr_content) {
		qrcode = QRcode_encodeString(
			state->authd_layout.qr_content,
			0, QR_ECLEVEL_L, QR_MODE_8, 1);
	}
#endif

	// Compute the size of the buffer needed
	int buffer_width = buffer_diameter;
	int buffer_height = buffer_diameter;

	if (is_qrcode) {
		bool have_qr_image = false;
#if HAVE_QRENCODE
		if (qrcode) {
			int qr_px = qrcode->width * 4 * scale;
			buffer_width = qr_px;
			buffer_height = qr_px;
			have_qr_image = true;
		}
#endif
		/* Reserve height for the human-readable fallback code. */
		if (state->authd_layout.qr_code &&
				*state->authd_layout.qr_code) {
			cairo_set_antialias(state->test_cairo, CAIRO_ANTIALIAS_BEST);
			configure_font_drawing(state->test_cairo, state,
				surface->subpixel, arc_radius);
			cairo_text_extents_t ext;
			cairo_font_extents_t fe;
			cairo_text_extents(state->test_cairo,
				state->authd_layout.qr_code, &ext);
			cairo_font_extents(state->test_cairo, &fe);
			double box_padding = 4.0 * scale;
			buffer_height += (int)(fe.height + 2.0 * box_padding);
			if (!have_qr_image &&
					buffer_width <
					(int)(ext.width + 2.0 * box_padding)) {
				buffer_width =
					(int)(ext.width + 2.0 * box_padding);
			}
		}
		/* Suppress the keyboard layout badge alongside a QR code. */
		layout_text = NULL;
	} else {
		if (text || layout_text) {
			cairo_set_antialias(state->test_cairo, CAIRO_ANTIALIAS_BEST);
			configure_font_drawing(state->test_cairo, state,
				surface->subpixel, arc_radius);

			if (text) {
				cairo_text_extents_t extents;
				cairo_text_extents(state->test_cairo, text, &extents);
				if (buffer_width < extents.width) {
					buffer_width = extents.width;
				}
			}
			if (layout_text) {
				cairo_text_extents_t extents;
				cairo_font_extents_t fe;
				double box_padding = 4.0 * surface->scale;
				cairo_text_extents(state->test_cairo, layout_text, &extents);
				cairo_font_extents(state->test_cairo, &fe);
				buffer_height += fe.height + 2 * box_padding;
				if (buffer_width < extents.width + 2 * box_padding) {
					buffer_width = extents.width + 2 * box_padding;
				}
			}
		}
	}

	/*
	 * Extra buffer space for CHALLENGE-stage authd elements:
	 * a label box above the ring, a button box and error text below.
	 */
	double label_box_h = 0, button_box_h = 0, error_h = 0;
	if (state->authd_active &&
			state->authd_stage == AUTHD_STAGE_CHALLENGE) {
		cairo_set_antialias(state->test_cairo, CAIRO_ANTIALIAS_BEST);
		configure_font_drawing(state->test_cairo, state,
			surface->subpixel, arc_radius);
		cairo_font_extents_t fe;
		cairo_font_extents(state->test_cairo, &fe);
		double box_padding = 4.0 * scale;

		if (!is_qrcode && state->authd_layout.label &&
				*state->authd_layout.label) {
			cairo_text_extents_t ext;
			cairo_text_extents(state->test_cairo,
				state->authd_layout.label, &ext);
			label_box_h = fe.height + 2.0 * box_padding;
			buffer_height += (int)label_box_h;
			if (buffer_width <
					(int)(ext.width + 2.0 * box_padding)) {
				buffer_width =
					(int)(ext.width + 2.0 * box_padding);
			}
		}
		if (!is_qrcode && state->authd_layout.button &&
				*state->authd_layout.button) {
			cairo_text_extents_t ext;
			cairo_text_extents(state->test_cairo,
				state->authd_layout.button, &ext);
			button_box_h = fe.height + 2.0 * box_padding;
			buffer_height += (int)button_box_h;
			if (buffer_width <
					(int)(ext.width + 2.0 * box_padding)) {
				buffer_width =
					(int)(ext.width + 2.0 * box_padding);
			}
		}
		if (state->authd_error && *state->authd_error) {
			cairo_text_extents_t ext;
			cairo_text_extents(state->test_cairo,
				state->authd_error, &ext);
			error_h = fe.height + box_padding;
			buffer_height += (int)error_h;
			if (buffer_width < (int)ext.width) {
				buffer_width = (int)ext.width;
			}
		}
	}

	// Ensure buffer size is multiple of buffer scale - required by protocol
	buffer_height += scale - (buffer_height % scale);
	buffer_width += scale - (buffer_width % scale);

	int subsurf_xpos;
	int subsurf_ypos;

	if (is_qrcode) {
		/* Centre the whole QR buffer on the screen. */
		if (state->args.override_indicator_x_position) {
			subsurf_xpos = state->args.indicator_x_position -
				buffer_width / (2 * scale);
		} else {
			subsurf_xpos = surface->width / 2 -
				buffer_width / (2 * scale);
		}
		if (state->args.override_indicator_y_position) {
			subsurf_ypos = state->args.indicator_y_position -
				buffer_height / (2 * scale);
		} else {
			subsurf_ypos = surface->height / 2 -
				buffer_height / (2 * scale);
		}
	} else {
		// Center the indicator unless overridden by the user
		if (state->args.override_indicator_x_position) {
			subsurf_xpos = state->args.indicator_x_position -
				buffer_width / (2 * scale) + 2 / scale;
		} else {
			subsurf_xpos = surface->width / 2 -
				buffer_width / (2 * scale) + 2 / scale;
		}

		if (state->args.override_indicator_y_position) {
			subsurf_ypos = state->args.indicator_y_position -
				(state->args.radius + state->args.thickness);
		} else {
			subsurf_ypos = surface->height / 2 -
				(state->args.radius + state->args.thickness);
		}
		/*
		 * Shift up so the ring stays vertically centred on screen
		 * when a label box occupies space above it in the buffer.
		 */
		subsurf_ypos -= (int)(label_box_h / scale);
	}

	struct pool_buffer *buffer = get_next_buffer(state->shm,
			surface->indicator_buffers, buffer_width, buffer_height);
	if (buffer == NULL) {
		swaylock_log(LOG_ERROR, "No buffer");
#if HAVE_QRENCODE
		QRcode_free(qrcode);
#endif
		return false;
	}

	// Render the buffer
	cairo_t *cairo = buffer->cairo;
	cairo_set_antialias(cairo, CAIRO_ANTIALIAS_BEST);

	cairo_identity_matrix(cairo);

	// Clear
	cairo_save(cairo);
	cairo_set_source_rgba(cairo, 0, 0, 0, 0);
	cairo_set_operator(cairo, CAIRO_OPERATOR_SOURCE);
	cairo_paint(cairo);
	cairo_restore(cairo);

	if (is_qrcode) {
		configure_font_drawing(cairo, state, surface->subpixel, arc_radius);
		cairo_font_extents_t fe;
		cairo_font_extents(cairo, &fe);
		double box_padding = 4.0 * scale;

		double qr_y = 0;
		bool drew_qr = false;

#if HAVE_QRENCODE
		if (qrcode) {
			int mod_size = 4 * scale;
			int qr_px = qrcode->width * mod_size;
			int qr_x = (buffer_width - qr_px) / 2;

			/* White background behind QR modules. */
			cairo_rectangle(cairo, qr_x, 0, qr_px, qr_px);
			cairo_set_source_rgb(cairo, 1, 1, 1);
			cairo_fill(cairo);

			/* Collect all dark modules, then fill in one pass. */
			cairo_set_source_rgb(cairo, 0, 0, 0);
			for (int row = 0; row < qrcode->width; row++) {
				for (int col = 0; col < qrcode->width; col++) {
					unsigned char px = qrcode->data[
						row * qrcode->width + col];
					if (!(px & 1)) {
						continue;
					}
					cairo_rectangle(cairo,
						qr_x + col * mod_size,
						row * mod_size,
						mod_size, mod_size);
				}
			}
			cairo_fill(cairo);

			qr_y = qr_px;
			drew_qr = true;
		}
#endif

		if (state->authd_layout.qr_code &&
				*state->authd_layout.qr_code) {
			cairo_text_extents_t ext;
			cairo_text_extents(cairo,
				state->authd_layout.qr_code, &ext);
			double tx = (buffer_width - ext.width) / 2.0
				- ext.x_bearing;
			double ty;
			if (drew_qr) {
				ty = qr_y + (fe.height - fe.descent) + box_padding;
				qr_y += fe.height + 2.0 * box_padding;
			} else {
				/* No QR image: centre text in available height. */
				ty = (buffer_height - error_h) / 2.0
					+ (fe.height / 2.0 - fe.descent);
				qr_y = buffer_height - error_h;
			}
			cairo_move_to(cairo, tx, ty);
			cairo_set_source_u32(cairo,
				state->args.colors.layout_text);
			cairo_show_text(cairo, state->authd_layout.qr_code);
		}

		/* Error text below QR content. */
		if (error_h > 0) {
			cairo_text_extents_t ext;
			cairo_text_extents(cairo, state->authd_error, &ext);
			double tx = (buffer_width - ext.width) / 2.0
				- ext.x_bearing;
			double ty = qr_y + (fe.height - fe.descent)
				+ box_padding / 2.0;
			cairo_move_to(cairo, tx, ty);
			cairo_set_source_u32(cairo, error_text_color);
			cairo_show_text(cairo, state->authd_error);
		}
	} else if (draw_indicator) {
		configure_font_drawing(cairo, state, surface->subpixel, arc_radius);

		/* Label box above the ring (CHALLENGE stage only). */
		if (label_box_h > 0) {
			cairo_font_extents_t fe;
			cairo_text_extents_t ext;
			cairo_font_extents(cairo, &fe);
			cairo_text_extents(cairo,
				state->authd_layout.label, &ext);
			double box_padding = 4.0 * scale;
			double bx = (buffer_width / 2.0)
				- (ext.width / 2.0) - box_padding;
			cairo_rectangle(cairo, bx, 0,
				ext.width + 2.0 * box_padding,
				fe.height + 2.0 * box_padding);
			cairo_set_source_u32(cairo,
				state->args.colors.layout_background);
			cairo_fill_preserve(cairo);
			cairo_set_source_u32(cairo,
				state->args.colors.layout_border);
			cairo_stroke(cairo);
			cairo_move_to(cairo,
				bx - ext.x_bearing + box_padding,
				(fe.height - fe.descent) + box_padding);
			cairo_set_source_u32(cairo,
				state->args.colors.layout_text);
			cairo_show_text(cairo, state->authd_layout.label);
			cairo_new_sub_path(cairo);
		}

		/*
		 * Ring centre Y is shifted down by the label height so the
		 * ring itself stays visually centred on screen.
		 */
		int ring_cy = (int)label_box_h + buffer_diameter / 2;

		// Fill inner circle
		cairo_set_line_width(cairo, 0);
		cairo_arc(cairo, buffer_width / 2, ring_cy,
				arc_radius - arc_thickness / 2, 0, 2 * M_PI);
		set_color_for_state(cairo, state, &state->args.colors.inside);
		cairo_fill_preserve(cairo);
		cairo_stroke(cairo);

		// Draw ring
		cairo_set_line_width(cairo, arc_thickness);
		cairo_arc(cairo, buffer_width / 2, ring_cy,
				arc_radius, 0, 2 * M_PI);
		set_color_for_state(cairo, state, &state->args.colors.ring);
		cairo_stroke(cairo);

		// Draw a message
		configure_font_drawing(cairo, state, surface->subpixel, arc_radius);
		set_color_for_state(cairo, state, &state->args.colors.text);

		if (text) {
			cairo_text_extents_t extents;
			cairo_font_extents_t fe;
			double x, y;
			cairo_text_extents(cairo, text, &extents);
			cairo_font_extents(cairo, &fe);
			x = (buffer_width / 2) -
				(extents.width / 2 + extents.x_bearing);
			y = ring_cy + (fe.height / 2 - fe.descent);

			cairo_move_to(cairo, x, y);
			cairo_show_text(cairo, text);
			cairo_close_path(cairo);
			cairo_new_sub_path(cairo);
		}

		// Typing indicator: Highlight random part on keypress
		if (state->input_state == INPUT_STATE_LETTER ||
				state->input_state == INPUT_STATE_BACKSPACE) {
			double highlight_start = state->highlight_start * (M_PI / 1024.0);
			cairo_arc(cairo, buffer_width / 2, ring_cy,
					arc_radius, highlight_start,
					highlight_start + TYPE_INDICATOR_RANGE);
			if (state->input_state == INPUT_STATE_LETTER) {
				if (state->xkb.caps_lock && state->args.show_caps_lock_indicator) {
					cairo_set_source_u32(cairo, state->args.colors.caps_lock_key_highlight);
				} else {
					cairo_set_source_u32(cairo, state->args.colors.key_highlight);
				}
			} else {
				if (state->xkb.caps_lock && state->args.show_caps_lock_indicator) {
					cairo_set_source_u32(cairo, state->args.colors.caps_lock_bs_highlight);
				} else {
					cairo_set_source_u32(cairo, state->args.colors.bs_highlight);
				}
			}
			cairo_stroke(cairo);

			// Draw borders
			double inner_radius = buffer_diameter / 2.0 - arc_thickness * 1.5;
			double outer_radius = buffer_diameter / 2.0 - arc_thickness / 2.0;
			double hs_end = highlight_start + TYPE_INDICATOR_RANGE;

			cairo_set_line_width(cairo, 2.0 * scale);
			cairo_set_source_u32(cairo, state->args.colors.separator);
			cairo_move_to(cairo,
				buffer_width / 2.0 + cos(highlight_start) * inner_radius,
				ring_cy + sin(highlight_start) * inner_radius
			);
			cairo_line_to(cairo,
				buffer_width / 2.0 + cos(highlight_start) * outer_radius,
				ring_cy + sin(highlight_start) * outer_radius
			);
			cairo_stroke(cairo);

			cairo_move_to(cairo,
				buffer_width / 2.0 + cos(hs_end) * inner_radius,
				ring_cy + sin(hs_end) * inner_radius
			);
			cairo_line_to(cairo,
				buffer_width / 2.0 + cos(hs_end) * outer_radius,
				ring_cy + sin(hs_end) * outer_radius
			);
			cairo_stroke(cairo);
		}

		// Draw inner + outer border of the circle
		set_color_for_state(cairo, state, &state->args.colors.line);
		cairo_set_line_width(cairo, 2.0 * scale);
		cairo_arc(cairo, buffer_width / 2, ring_cy,
				arc_radius - arc_thickness / 2, 0, 2 * M_PI);
		cairo_stroke(cairo);
		cairo_arc(cairo, buffer_width / 2, ring_cy,
				arc_radius + arc_thickness / 2, 0, 2 * M_PI);
		cairo_stroke(cairo);

		// display layout text separately
		if (layout_text) {
			cairo_text_extents_t extents;
			cairo_font_extents_t fe;
			double x, y;
			double box_padding = 4.0 * scale;
			cairo_text_extents(cairo, layout_text, &extents);
			cairo_font_extents(cairo, &fe);
			// upper left coordinates for box
			x = (buffer_width / 2) - (extents.width / 2) - box_padding;
			y = (int)label_box_h + buffer_diameter;

			// background box
			cairo_rectangle(cairo, x, y,
				extents.width + 2.0 * box_padding,
				fe.height + 2.0 * box_padding);
			cairo_set_source_u32(cairo, state->args.colors.layout_background);
			cairo_fill_preserve(cairo);
			// border
			cairo_set_source_u32(cairo, state->args.colors.layout_border);
			cairo_stroke(cairo);

			// take font extents and padding into account
			cairo_move_to(cairo,
				x - extents.x_bearing + box_padding,
				y + (fe.height - fe.descent) + box_padding);
			cairo_set_source_u32(cairo, state->args.colors.layout_text);
			cairo_show_text(cairo, layout_text);
			cairo_new_sub_path(cairo);
		}

		/* CHALLENGE: button and/or error text below ring / badge. */
		if (button_box_h > 0 || error_h > 0) {
			cairo_font_extents_t fe;
			cairo_font_extents(cairo, &fe);
			double box_padding = 4.0 * scale;

			/* Start below the ring and the optional layout badge. */
			double y = (int)label_box_h + buffer_diameter;
			if (layout_text) {
				y += fe.height + 2.0 * box_padding;
			}

			if (button_box_h > 0) {
				cairo_text_extents_t ext;
				cairo_text_extents(cairo,
					state->authd_layout.button, &ext);
				double bw = ext.width + 2.0 * box_padding;
				double bh = fe.height + 2.0 * box_padding;
				double bx = (buffer_width - bw) / 2.0;
				double corner = bh / 4.0;

				/* Rounded rectangle for the button. */
				cairo_new_sub_path(cairo);
				cairo_arc(cairo,
					bx + bw - corner, y + corner,
					corner, -M_PI / 2.0, 0);
				cairo_arc(cairo,
					bx + bw - corner, y + bh - corner,
					corner, 0, M_PI / 2.0);
				cairo_arc(cairo,
					bx + corner, y + bh - corner,
					corner, M_PI / 2.0, M_PI);
				cairo_arc(cairo,
					bx + corner, y + corner,
					corner, M_PI, 3.0 * M_PI / 2.0);
				cairo_close_path(cairo);

				cairo_set_source_u32(cairo,
					state->args.colors.layout_background);
				cairo_fill_preserve(cairo);
				cairo_set_line_width(cairo, 2.0 * scale);
				cairo_set_source_u32(cairo,
					state->args.colors.layout_border);
				cairo_stroke(cairo);

				cairo_move_to(cairo,
					bx - ext.x_bearing + box_padding,
					y + (fe.height - fe.descent) + box_padding);
				cairo_set_source_u32(cairo,
					state->args.colors.layout_text);
				cairo_show_text(cairo, state->authd_layout.button);
				cairo_new_sub_path(cairo);

				y += button_box_h;
			}

			if (error_h > 0) {
				cairo_text_extents_t ext;
				cairo_text_extents(cairo, state->authd_error, &ext);
				double tx = (buffer_width - ext.width) / 2.0
					- ext.x_bearing;
				double ty = y + (fe.height - fe.descent)
					+ box_padding / 2.0;
				cairo_move_to(cairo, tx, ty);
				cairo_set_source_u32(cairo, error_text_color);
				cairo_show_text(cairo, state->authd_error);
				cairo_new_sub_path(cairo);
			}
		}
	}

#if HAVE_QRENCODE
	QRcode_free(qrcode);
#endif

	// Send Wayland requests
	wl_subsurface_set_position(surface->subsurface, subsurf_xpos, subsurf_ypos);

	wl_surface_set_buffer_scale(surface->child, surface->scale);
	wl_surface_attach(surface->child, buffer->buffer, 0, 0);
	wl_surface_damage_buffer(surface->child, 0, 0, INT32_MAX, INT32_MAX);
	wl_surface_commit(surface->child);

	return true;
}