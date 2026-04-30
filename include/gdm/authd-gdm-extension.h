/*
 * Helpers for the authd-specific GDM JSON PAM extension protocol.
 *
 * Based on authd's pam/internal/gdm/extension.h
 * (github.com/canonical/authd, MIT/GPL).
 */

#pragma once

#include <stdlib.h>
#include <string.h>

#include "gdm-custom-json-pam-extension.h"

#define AUTHD_GDM_JSON_PROTO_NAME    "com.ubuntu.authd.gdm"
#define AUTHD_GDM_JSON_PROTO_VERSION 1U

/*
 * pam_extension_environment_block must be a static buffer of at least
 * _POSIX_ARG_MAX bytes so that putenv() does not leak.
 */
static char authd_gdm_pam_ext_env[_POSIX_ARG_MAX];

/*
 * Advertise the authd GDM JSON extension to any PAM module loaded in
 * this process by setting GDM_SUPPORTED_PAM_EXTENSIONS.
 */
static inline void
authd_gdm_advertise_extensions(void)
{
	static const char *exts[] = {
		GDM_PAM_EXTENSION_CUSTOM_JSON,
		NULL,
	};
	GDM_PAM_EXTENSION_ADVERTISE_SUPPORTED_EXTENSIONS(
		authd_gdm_pam_ext_env, exts);
}

/*
 * Initialise a GdmPamExtensionJSONProtocol request with the authd
 * protocol name, version and the given JSON string.  The json pointer
 * is stored as-is; the caller must ensure it remains valid until the
 * request is consumed and must free it separately.
 */
static inline void
authd_gdm_request_init(GdmPamExtensionJSONProtocol *req, char *json)
{
	GDM_PAM_EXTENSION_CUSTOM_JSON_REQUEST_INIT(
		req,
		AUTHD_GDM_JSON_PROTO_NAME,
		AUTHD_GDM_JSON_PROTO_VERSION,
		json);
}

/*
 * Returns true when the message carries the expected authd protocol
 * name and version.
 */
static inline bool
authd_gdm_message_is_valid(const GdmPamExtensionJSONProtocol *msg)
{
	if (msg->version != AUTHD_GDM_JSON_PROTO_VERSION)
		return false;
	return strncmp(msg->protocol_name, AUTHD_GDM_JSON_PROTO_NAME,
		sizeof(msg->protocol_name)) == 0;
}