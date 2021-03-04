#ifndef GEMINI_TOFU_H
#define GEMINI_TOFU_H
#include <bearssl.h>
#include <limits.h>

enum tofu_error {
	TOFU_VALID,
	// Expired, wrong CN, etc.
	TOFU_INVALID_CERT,
	// Cert is valid but we haven't seen it before
	TOFU_UNTRUSTED_CERT,
	// Cert is valid but we already trust another cert for this host
	TOFU_FINGERPRINT_MISMATCH,
};

enum tofu_action {
	TOFU_ASK,
	TOFU_FAIL,
	TOFU_TRUST_ONCE,
	TOFU_TRUST_ALWAYS,
};

struct known_host {
	char *host, *fingerprint;
	int lineno;
	struct known_host *next;
};

// Called when the user needs to be prompted to agree to trust an unknown
// certificate. Return true to trust this certificate.
typedef enum tofu_action (tofu_callback_t)(enum tofu_error error,
	const char *fingerprint, struct known_host *host, void *data);

struct gemini_tofu;

struct x509_tofu_context {
	const br_x509_class *vtable;
	br_x509_decoder_context decoder;
	br_x509_pkey *pkey;
	br_sha512_context sha512;
	unsigned char hash[64];
	struct gemini_tofu *store;
	const char *server_name;
	int err;
};

struct gemini_tofu {
	struct x509_tofu_context x509_ctx;
	br_ssl_client_context sc;
	unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
	char known_hosts_path[PATH_MAX+1];
	struct known_host *known_hosts;
	int lineno;
	tofu_callback_t *callback;
	void *cb_data;
};

void gemini_tofu_init(struct gemini_tofu *tofu, tofu_callback_t *cb, void *data);
void gemini_tofu_finish(struct gemini_tofu *tofu);

#endif
