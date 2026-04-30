#define _POSIX_C_SOURCE 200809L
/* _DEFAULT_SOURCE exposes htobe32/htole32 (__USE_MISC) and the full
 * putenv declaration required by the GDM PAM extension headers. */
#define _DEFAULT_SOURCE 1
#include <cjson/cJSON.h>
#include <poll.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "gdm/authd-gdm-extension.h"
#include "comm.h"
#include "log.h"
#include "password-buffer.h"
#include "swaylock.h"

/* defined in comm.c; not exported in comm.h */
extern int get_comm_child_fd(void);

void authd_ui_layout_clear(struct authd_ui_layout *layout) {
	free(layout->type);
	free(layout->label);
	free(layout->button);
	free(layout->entry);
	free(layout->qr_content);
	free(layout->qr_code);
	memset(layout, 0, sizeof(*layout));
}

void authd_brokers_free(struct authd_broker *brokers, int count) {
	for (int i = 0; i < count; i++) {
		free(brokers[i].id);
		free(brokers[i].name);
	}
	free(brokers);
}

void authd_auth_modes_free(struct authd_auth_mode *modes, int count) {
	for (int i = 0; i < count; i++) {
		free(modes[i].id);
		free(modes[i].label);
	}
	free(modes);
}

static const char *get_pam_auth_error(int pam_status) {
	switch (pam_status) {
	case PAM_AUTH_ERR:
		return "invalid credentials";
	case PAM_PERM_DENIED:
		return "permission denied; check /etc/pam.d/swaylock"
			" is installed properly";
	case PAM_CRED_INSUFFICIENT:
		return "swaylock cannot authenticate users; check "
			"/etc/pam.d/swaylock has been installed properly";
	case PAM_AUTHINFO_UNAVAIL:
		return "authentication information unavailable";
	case PAM_MAXTRIES:
		return "maximum number of authentication tries exceeded";
	default:;
		static char msg[64];
		snprintf(msg, sizeof(msg), "unknown error (%d)", pam_status);
		return msg;
	}
}

struct conv_state {
	cJSON      *pending[64];
	int         pending_count;
	bool        user_selected_sent;
	const char *username;
};

/* forward declaration */
static char *handle_gdm_json(
	struct conv_state *state, const char *json_in);

static int handle_conversation(
	int num_msg, const struct pam_message **msg,
	struct pam_response **resp, void *data)
{
	struct conv_state *state = data;
	swaylock_log(LOG_DEBUG,
		"handle_conversation: num_msg=%d", num_msg);
	struct pam_response *pam_reply =
		calloc(num_msg, sizeof(struct pam_response));
	if (!pam_reply) {
		swaylock_log(LOG_ERROR, "allocation failed");
		return PAM_ABORT;
	}
	*resp = pam_reply;
	for (int i = 0; i < num_msg; i++) {
		swaylock_log(LOG_DEBUG,
			"handle_conversation: msg[%d] style=%d",
			i, msg[i]->msg_style);
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON: {
			/* Tell the main process we are waiting for a new
			 * credential.  If it was in AUTH_STATE_VALIDATING
			 * this transitions it to AUTH_STATE_INVALID
			 * ("Wrong") and then back to IDLE so the user
			 * can type again. */
			uint8_t stage_byte = AUTHD_STAGE_CHALLENGE;
			comm_child_write(COMM_MSG_STAGE,
				(char *)&stage_byte, sizeof(stage_byte));
			swaylock_log(LOG_DEBUG,
				"handle_conversation: PAM_PROMPT"
				" sent STAGE, waiting for password");
			char *payload = NULL;
			size_t len = 0;
			int type;
			do {
				type = comm_child_read(&payload, &len);
				if (type <= 0) {
					return PAM_ABORT;
				}
				if (type != COMM_MSG_PASSWORD) {
					free(payload);
					payload = NULL;
				}
			} while (type != COMM_MSG_PASSWORD);
			swaylock_log(LOG_DEBUG,
					"handle_conversation: PAM_PROMPT"
					" got password (len=%zu)", len);
				pam_reply[i].resp = strdup(payload);
				clear_buffer(payload, len);
				free(payload);
			if (!pam_reply[i].resp) {
				swaylock_log(LOG_ERROR, "allocation failed");
				return PAM_ABORT;
			}
			break;
		}
#ifdef PAM_BINARY_PROMPT
		case PAM_BINARY_PROMPT: {
			const GdmPamExtensionJSONProtocol *ext =
				(const GdmPamExtensionJSONProtocol *)
				(const void *)msg[i]->msg;
			if (!authd_gdm_message_is_valid(ext)) {
				return PAM_ABORT;
			}
			char *response =
				handle_gdm_json(state, ext->json);
			if (!response) {
				return PAM_ABORT;
			}
			GdmPamExtensionJSONProtocol *reply = calloc(
				1, sizeof(GdmPamExtensionJSONProtocol));
			if (!reply) {
				free(response);
				return PAM_ABORT;
			}
			authd_gdm_request_init(reply, response);
			pam_reply[i].resp = (char *)(void *)reply;
			break;
		}
#endif
		case PAM_TEXT_INFO:
			swaylock_log(LOG_DEBUG,
				"handle_conversation: PAM_TEXT_INFO: %s",
				msg[i]->msg ? msg[i]->msg : "(null)");
			break;
		case PAM_ERROR_MSG:
			swaylock_log(LOG_DEBUG,
				"handle_conversation: PAM_ERROR_MSG: %s",
				msg[i]->msg ? msg[i]->msg : "(null)");
			break;
		default:
			swaylock_log(LOG_DEBUG,
				"handle_conversation: unknown"
				" msg_style=%d", msg[i]->msg_style);
			break;
		}
	}
	swaylock_log(LOG_DEBUG, "handle_conversation: returning PAM_SUCCESS");
	return PAM_SUCCESS;
}

static char *handle_gdm_json(
	struct conv_state *state, const char *json_in)
{
	cJSON *root = cJSON_Parse(json_in);
	if (!root) {
		swaylock_log(LOG_ERROR,
			"cJSON_Parse failed: %.80s", json_in);
		return NULL;
	}

	cJSON *type_item =
		cJSON_GetObjectItemCaseSensitive(root, "type");
	if (!cJSON_IsString(type_item)) {
		cJSON_Delete(root);
		return NULL;
	}
	const char *type = type_item->valuestring;
	swaylock_log(LOG_DEBUG,
		"handle_gdm_json: type=%s", type);

	cJSON *response = NULL;
	if (strcmp(type, "hello") == 0) {
		response = cJSON_CreateObject();
		cJSON_AddStringToObject(response, "type", "hello");
		cJSON *hello = cJSON_CreateObject();
		cJSON_AddNumberToObject(hello, "version", 1);
		cJSON_AddItemToObject(response, "hello", hello);

	} else if (strcmp(type, "request") == 0) {
		cJSON *req = cJSON_GetObjectItemCaseSensitive(
			root, "request");
		cJSON *req_type = cJSON_GetObjectItemCaseSensitive(
			req, "type");
		if (cJSON_IsString(req_type) && strcmp(
				req_type->valuestring,
				"uiLayoutCapabilities") == 0) {
			cJSON *form = cJSON_CreateObject();
			cJSON_AddStringToObject(form, "type", "form");
			cJSON_AddStringToObject(form, "label", "required");
			cJSON_AddStringToObject(form, "entry",
				"optional:chars,chars_password,"
				"digits,digits_password");
			cJSON_AddStringToObject(
				form, "wait", "optional:true,false");
			cJSON_AddStringToObject(form, "button", "optional");

			cJSON *newpw = cJSON_CreateObject();
			cJSON_AddStringToObject(
				newpw, "type", "newpassword");
			cJSON_AddStringToObject(
				newpw, "label", "required");
			cJSON_AddStringToObject(newpw, "entry",
				"optional:chars,chars_password,"
				"digits,digits_password");
			cJSON_AddStringToObject(
				newpw, "button", "optional");

			cJSON *qr = cJSON_CreateObject();
			cJSON_AddStringToObject(qr, "type", "qrcode");
			cJSON_AddStringToObject(qr, "content", "required");
			cJSON_AddStringToObject(qr, "code", "optional");
			cJSON_AddStringToObject(
				qr, "wait", "required:true,false");
			cJSON_AddStringToObject(qr, "label", "optional");
			cJSON_AddStringToObject(qr, "button", "optional");
			cJSON_AddBoolToObject(qr, "rendersQrcode", true);

			cJSON *layouts = cJSON_CreateArray();
			cJSON_AddItemToArray(layouts, form);
			cJSON_AddItemToArray(layouts, newpw);
			cJSON_AddItemToArray(layouts, qr);

			cJSON *caps = cJSON_CreateObject();
			cJSON_AddItemToObject(
				caps, "supportedUiLayouts", layouts);

			cJSON *resp_obj = cJSON_CreateObject();
			cJSON_AddStringToObject(
				resp_obj, "type", "uiLayoutCapabilities");
			cJSON_AddItemToObject(
				resp_obj, "uiLayoutCapabilities", caps);

			response = cJSON_CreateObject();
			cJSON_AddStringToObject(
				response, "type", "response");
			cJSON_AddItemToObject(
				response, "response", resp_obj);
		} else {
			response = cJSON_CreateObject();
			cJSON_AddStringToObject(
				response, "type", "eventAck");
		}

	} else if (strcmp(type, "event") == 0) {
		cJSON *event = cJSON_GetObjectItemCaseSensitive(
			root, "event");
		cJSON *evt_type = cJSON_GetObjectItemCaseSensitive(
			event, "type");
		const char *etype = cJSON_IsString(evt_type)
			? evt_type->valuestring : "";

		swaylock_log(LOG_DEBUG,
			"handle_gdm_json: event type=%s", etype);

		if (strcmp(etype, "brokersReceived") == 0) {
			cJSON *infos = cJSON_GetObjectItemCaseSensitive(
				event, "brokersInfos");
			cJSON *arr = cJSON_CreateArray();
			cJSON *b;
			cJSON_ArrayForEach(b, infos) {
				cJSON *entry = cJSON_CreateObject();
				cJSON *id =
					cJSON_GetObjectItemCaseSensitive(
					b, "id");
				cJSON *nm =
					cJSON_GetObjectItemCaseSensitive(
					b, "name");
				if (cJSON_IsString(id)) {
					cJSON_AddStringToObject(entry,
						"id", id->valuestring);
				}
				if (cJSON_IsString(nm)) {
					cJSON_AddStringToObject(entry,
						"name", nm->valuestring);
				}
				cJSON_AddItemToArray(arr, entry);
			}
			char *json = cJSON_PrintUnformatted(arr);
			cJSON_Delete(arr);
			if (json) {
				comm_child_write(COMM_MSG_BROKERS,
					json, strlen(json));
				free(json);
			}

		} else if (strcmp(etype, "authModesReceived") == 0) {
			cJSON *modes = cJSON_GetObjectItemCaseSensitive(
				event, "authModes");
			cJSON *arr = cJSON_CreateArray();
			cJSON *m;
			cJSON_ArrayForEach(m, modes) {
				cJSON *entry = cJSON_CreateObject();
				cJSON *id =
					cJSON_GetObjectItemCaseSensitive(
					m, "id");
				cJSON *lbl =
					cJSON_GetObjectItemCaseSensitive(
					m, "label");
				if (cJSON_IsString(id)) {
					cJSON_AddStringToObject(entry,
						"id", id->valuestring);
				}
				if (cJSON_IsString(lbl)) {
					cJSON_AddStringToObject(entry,
						"label", lbl->valuestring);
				}
				cJSON_AddItemToArray(arr, entry);
			}
			char *json = cJSON_PrintUnformatted(arr);
			cJSON_Delete(arr);
			if (json) {
				comm_child_write(COMM_MSG_AUTH_MODES,
					json, strlen(json));
				free(json);
			}

		} else if (strcmp(etype, "uiLayoutReceived") == 0) {
			cJSON *layout = cJSON_GetObjectItemCaseSensitive(
				event, "uiLayout");
			char *json = cJSON_PrintUnformatted(layout);
			if (json) {
				comm_child_write(COMM_MSG_UI_LAYOUT,
					json, strlen(json));
				free(json);
			}

		} else if (strcmp(etype, "stageChanged") == 0) {
			cJSON *stage = cJSON_GetObjectItemCaseSensitive(
				event, "stage");
			uint8_t stage_byte = AUTHD_STAGE_NONE;
			if (cJSON_IsString(stage)) {
				const char *s = stage->valuestring;
				if (strcmp(s, "brokerSelection") == 0) {
					stage_byte = AUTHD_STAGE_BROKER;
				} else if (strcmp(s,
						"authModeSelection") == 0) {
					stage_byte = AUTHD_STAGE_AUTH_MODE;
				} else if (strcmp(s, "challenge") == 0) {
					stage_byte = AUTHD_STAGE_CHALLENGE;
				}
				/* "userSelection" → AUTHD_STAGE_NONE */
			}
			comm_child_write(COMM_MSG_STAGE,
				(char *)&stage_byte, sizeof(stage_byte));

		} else if (strcmp(etype, "startAuthentication") == 0) {
			swaylock_log(LOG_DEBUG,
				"handle_gdm_json: startAuthentication"
				" -> sending COMM_MSG_STAGE challenge");
			uint8_t stage_byte = AUTHD_STAGE_CHALLENGE;
			comm_child_write(COMM_MSG_STAGE,
				(char *)&stage_byte, sizeof(stage_byte));

		} else if (strcmp(etype, "authEvent") == 0) {
			cJSON *ev_resp =
				cJSON_GetObjectItemCaseSensitive(
				event, "response");
			if (ev_resp) {
				char *json =
					cJSON_PrintUnformatted(ev_resp);
				if (json) {
					cJSON *access =
						cJSON_GetObjectItemCaseSensitive(
						ev_resp, "access");
					swaylock_log(LOG_DEBUG,
						"handle_gdm_json: authEvent"
						" access=%s -> AUTH_EVENT",
						cJSON_IsString(access)
							? access->valuestring
							: "(none)");
					comm_child_write(
						COMM_MSG_AUTH_EVENT,
						json, strlen(json));
					free(json);
				}
			}
		}
		/* all event subtypes reply with eventAck */
		response = cJSON_CreateObject();
		cJSON_AddStringToObject(response, "type", "eventAck");

	} else if (strcmp(type, "poll") == 0) {
		if (!state->user_selected_sent) {
			cJSON *evt = cJSON_CreateObject();
			cJSON_AddStringToObject(
				evt, "type", "userSelected");
			cJSON *sel = cJSON_CreateObject();
			cJSON_AddStringToObject(
				sel, "userId", state->username);
			cJSON_AddItemToObject(evt, "userSelected", sel);
			state->pending[state->pending_count++] = evt;
			state->user_selected_sent = true;
		}
		swaylock_log(LOG_DEBUG,
			"handle_gdm_json: poll"
			" pending=%d user_sel_sent=%d",
			state->pending_count,
			(int)state->user_selected_sent);
		while (state->pending_count < 64) {
			struct pollfd pfd = {
				.fd     = get_comm_child_fd(),
				.events = POLLIN,
			};
			if (poll(&pfd, 1, 0) <= 0) {
				break;
			}
			char *payload = NULL;
			size_t plen = 0;
			int mtype = comm_child_read(&payload, &plen);
			if (mtype <= 0) {
				free(payload);
				break;
			}
			swaylock_log(LOG_DEBUG,
				"handle_gdm_json: poll"
				" read mtype=0x%02x plen=%zu",
				mtype, plen);
			cJSON *evt = NULL;
			switch (mtype) {
			case COMM_MSG_BROKER_SEL: {
				evt = cJSON_CreateObject();
				cJSON_AddStringToObject(
					evt, "type", "brokerSelected");
				cJSON *inner = cJSON_CreateObject();
				cJSON_AddStringToObject(inner, "brokerId",
					payload ? payload : "");
				cJSON_AddItemToObject(
					evt, "brokerSelected", inner);
				free(payload);
				break;
			}
			case COMM_MSG_AUTH_MODE_SEL: {
				evt = cJSON_CreateObject();
				cJSON_AddStringToObject(
					evt, "type", "authModeSelected");
				cJSON *inner = cJSON_CreateObject();
				cJSON_AddStringToObject(inner, "authModeId",
					payload ? payload : "");
				cJSON_AddItemToObject(
					evt, "authModeSelected", inner);
				free(payload);
				break;
			}
			case COMM_MSG_BUTTON: {
				evt = cJSON_CreateObject();
				cJSON_AddStringToObject(evt, "type",
					"reselectAuthMode");
				cJSON_AddItemToObject(evt,
					"reselectAuthMode",
					cJSON_CreateObject());
				free(payload);
				break;
			}
			case COMM_MSG_CANCEL: {
				evt = cJSON_CreateObject();
				cJSON_AddStringToObject(evt, "type",
					"isAuthenticatedCancelled");
				cJSON_AddItemToObject(evt,
					"isAuthenticatedCancelled",
					cJSON_CreateObject());
				free(payload);
				break;
			}
			case COMM_MSG_PASSWORD: {
				evt = cJSON_CreateObject();
				cJSON_AddStringToObject(evt, "type",
					"isAuthenticatedRequested");
				cJSON *inner = cJSON_CreateObject();
				cJSON *auth_data = cJSON_CreateObject();
				cJSON_AddStringToObject(auth_data,
					"secret", payload ? payload : "");
				cJSON_AddItemToObject(inner,
					"authenticationData", auth_data);
				cJSON_AddItemToObject(evt,
					"isAuthenticatedRequested", inner);
				if (payload) {
					clear_buffer(payload, plen);
					free(payload);
				}
				break;
			}
			default:
				free(payload);
				break;
			}
			if (evt) {
				state->pending[
					state->pending_count++] = evt;
			}
		}
		cJSON *arr = cJSON_CreateArray();
		int nevents = state->pending_count;
		for (int i = 0; i < state->pending_count; i++) {
			cJSON_AddItemToArray(arr, state->pending[i]);
		}
		state->pending_count = 0;
		swaylock_log(LOG_DEBUG,
			"handle_gdm_json: pollResponse"
			" nevents=%d", nevents);
		response = cJSON_CreateObject();
		cJSON_AddStringToObject(
			response, "type", "pollResponse");
		cJSON_AddItemToObject(response, "pollResponse", arr);

	} else {
		response = cJSON_CreateObject();
		cJSON_AddStringToObject(response, "type", "eventAck");
	}

	cJSON_Delete(root);
	if (!response) {
		return NULL;
	}
	char *result = cJSON_PrintUnformatted(response);
	cJSON_Delete(response);
	return result;
}

void initialize_pw_backend(int argc, char **argv) {
	if (!spawn_comm_child()) {
		exit(EXIT_FAILURE);
	}
}

void run_pw_backend_child(void) {
	if (access("/run/authd.sock", F_OK) == 0) {
		authd_gdm_advertise_extensions();
	}
	struct passwd *passwd = getpwuid(getuid());
	if (!passwd) {
		swaylock_log_errno(LOG_ERROR, "getpwuid failed");
		exit(EXIT_FAILURE);
	}
	const char *username = passwd->pw_name;

	struct conv_state state = {
		.username = username,
	};
	const struct pam_conv conv = {
		.conv        = handle_conversation,
		.appdata_ptr = &state,
	};
	pam_handle_t *auth_handle = NULL;
	if (pam_start("swaylock", username,
			&conv, &auth_handle) != PAM_SUCCESS) {
		swaylock_log(LOG_ERROR, "pam_start failed");
		exit(EXIT_FAILURE);
	}
	swaylock_log(LOG_DEBUG,
		"Prepared to authorize user %s", username);

	int pam_status;
	do {
		pam_status = pam_authenticate(auth_handle, 0);
		if (pam_status == PAM_SUCCESS) {
			comm_child_write(COMM_MSG_AUTH_RESULT, "\x01", 1);
		} else {
			swaylock_log(LOG_ERROR,
				"pam_authenticate failed: %s",
				get_pam_auth_error(pam_status));
			comm_child_write(COMM_MSG_AUTH_RESULT, "\x00", 1);
		}
	} while (pam_status == PAM_AUTH_ERR);

	pam_setcred(auth_handle, PAM_REFRESH_CRED);

	if (pam_end(auth_handle, pam_status) != PAM_SUCCESS) {
		swaylock_log(LOG_ERROR, "pam_end failed");
		exit(EXIT_FAILURE);
	}
	exit((pam_status == PAM_SUCCESS)
		? EXIT_SUCCESS : EXIT_FAILURE);
}
