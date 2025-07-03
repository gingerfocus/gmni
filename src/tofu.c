#include <assert.h>
#include <bearssl.h>
#include <errno.h>
#include <gmni/gmni.h>
#include <gmni/tofu.h>
#include <libgen.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

static void
xt_start_chain(const br_x509_class **ctx, const char *server_name)
{
	struct x509_tofu_context *cc = (struct x509_tofu_context *)(void *)ctx;
	cc->server_name = server_name;
	cc->err = 0;
	cc->pkey = NULL;
}

static void
xt_start_cert(const br_x509_class **ctx, uint32_t length)
{
	struct x509_tofu_context *cc = (struct x509_tofu_context *)(void *)ctx;
	if (cc->err != 0 || cc->pkey) {
		return;
	}
	if (length == 0) {
		cc->err = BR_ERR_X509_TRUNCATED;
		return;
	}
	br_x509_decoder_init(&cc->decoder, NULL, NULL);
	br_sha512_init(&cc->sha512);
}

static void
xt_append(const br_x509_class **ctx, const unsigned char *buf, size_t len)
{
	struct x509_tofu_context *cc = (struct x509_tofu_context *)(void *)ctx;
	if (cc->err != 0 || cc->pkey) {
		return;
	}
	br_x509_decoder_push(&cc->decoder, buf, len);
	int err = br_x509_decoder_last_error(&cc->decoder);
	if (err != 0 && err != BR_ERR_X509_TRUNCATED) {
		cc->err = err;
	}
	br_sha512_update(&cc->sha512, buf, len);
}

static void
xt_end_cert(const br_x509_class **ctx)
{
	struct x509_tofu_context *cc = (struct x509_tofu_context *)(void *)ctx;
	if (cc->err != 0) {
		return;
	}
	int err = br_x509_decoder_last_error(&cc->decoder);
	if (err != 0 && err != BR_ERR_X509_TRUNCATED) {
		cc->err = err;
		return;
	}
	cc->pkey = br_x509_decoder_get_pkey(&cc->decoder);
	br_sha512_out(&cc->sha512, &cc->hash);
}

static unsigned
xt_end_chain(const br_x509_class **ctx)
{
	struct x509_tofu_context *cc = (struct x509_tofu_context *)(void *)ctx;
	if (cc->err != 0) {
		return (unsigned)cc->err;
	}
	if (!cc->pkey) {
		return BR_ERR_X509_EMPTY_CHAIN;
	}

	// char fingerprint[512 / 8 * 3];
	char fingerprint[512 / 8 * 4];
	for (size_t i = 0; i < sizeof(cc->hash); ++i) {
		snprintf(&fingerprint[i * 3], 4, "%02X%s",
			cc->hash[i], i + 1 == sizeof(cc->hash) ? "" : ":");
	}

	enum tofu_error error = TOFU_UNTRUSTED_CERT;
	struct known_host *host = cc->store->known_hosts;
	while (host) {
		if (strcmp(host->host, cc->server_name) != 0) {
			goto next;
		}
		if (strcmp(host->fingerprint, fingerprint) == 0) {
			// Valid match in known hosts
			return 0;
		}
		error = TOFU_FINGERPRINT_MISMATCH;
		break;
next:
		host = host->next;
	}

	switch (cc->store->callback(error, fingerprint,
				host, cc->store->cb_data)) {
	case TOFU_ASK:
		assert(0); // Invariant
	case TOFU_FAIL:
		return BR_ERR_X509_NOT_TRUSTED;
	case TOFU_TRUST_ONCE:
		// No further action necessary
		return 0;
	case TOFU_TRUST_ALWAYS:;
		FILE *f = fopen(cc->store->known_hosts_path, "a");
		if (!f) {
			fprintf(stderr, "Error opening %s for writing: %s\n",
				cc->store->known_hosts_path, strerror(errno));
			break;
		};
		fprintf(f, "%s %s %s\n", cc->server_name,
				"SHA-512", fingerprint);
		fclose(f);

		host = calloc(1, sizeof(struct known_host));
		host->host = strdup(cc->server_name);
		host->fingerprint = strdup(fingerprint);
		host->lineno = ++cc->store->lineno;
		host->next = cc->store->known_hosts;
		cc->store->known_hosts = host;
		return 0;
	}

	assert(0); // Unreachable
}

static const br_x509_pkey *
xt_get_pkey(const br_x509_class *const *ctx, unsigned *usages)
{
	struct x509_tofu_context *cc = (struct x509_tofu_context *)(void *)ctx;
	if (cc->err != 0) {
		return NULL;
	}
	if (usages) {
		// XXX: BearSSL doesn't pull the usages out of the X.509 for us
		*usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN;
	}
	return cc->pkey;
}

const br_x509_class xt_vtable = {
	sizeof(struct x509_tofu_context),
	xt_start_chain,
	xt_start_cert,
	xt_append,
	xt_end_cert,
	xt_end_chain,
	xt_get_pkey,
};

static void
x509_init_tofu(struct x509_tofu_context *ctx, struct gemini_tofu *store)
{
	ctx->vtable = &xt_vtable;
	ctx->store = store;
}

void
gemini_tofu_init(struct gemini_tofu *tofu, tofu_callback_t *cb, void *cb_data)
{
	const struct pathspec paths[] = {
		{.var = "GMNIDATA", .path = "/%s"},
		{.var = "XDG_DATA_HOME", .path = "/gmni/%s"},
		{.var = "HOME", .path = "/.local/share/gmni/%s"}
	};
	char *path_fmt = getpath(paths, sizeof(paths) / sizeof(paths[0]));
	char dname[PATH_MAX+1];
	size_t n = 0;

	n = snprintf(tofu->known_hosts_path,
		sizeof(tofu->known_hosts_path),
		path_fmt, "known_hosts");
	free(path_fmt);
	assert(n < sizeof(tofu->known_hosts_path));

	posix_dirname(tofu->known_hosts_path, dname);
	if (mkdirs(dname, 0755) != 0) {
		fprintf(stderr, "Error creating directory %s: %s\n", dname,
			strerror(errno));
		return;
	}

	tofu->callback = cb;
	tofu->cb_data = cb_data;

	tofu->known_hosts = NULL;

	x509_init_tofu(&tofu->x509_ctx, tofu);

	br_x509_minimal_context _; // Discarded
	br_ssl_client_init_full(&tofu->sc, &_, NULL, 0);
	br_ssl_engine_set_x509(&tofu->sc.eng, &tofu->x509_ctx.vtable);
	br_ssl_engine_set_buffer(&tofu->sc.eng,
			&tofu->iobuf, sizeof(tofu->iobuf), 1);

	FILE *f = fopen(tofu->known_hosts_path, "r");
	if (!f) {
		return;
	}
	n = 0;
	int lineno = 1;
	char *line = NULL;
	while (getline(&line, &n, f) != -1) {
		int ln = strlen(line);
		if (line[ln-1] == '\n') {
			line[ln-1] = 0;
		}

		struct known_host *host = calloc(1, sizeof(struct known_host));
		char *tok = strtok(line, " ");
		assert(tok);
		host->host = strdup(tok);

		tok = strtok(NULL, " ");
		assert(tok);
		if (strcmp(tok, "SHA-512") != 0) {
			free(host->host);
			free(host);
			continue;
		}

		tok = strtok(NULL, " ");
		assert(tok);
		host->fingerprint = strdup(tok);

		host->lineno = lineno++;

		host->next = tofu->known_hosts;
		tofu->known_hosts = host;
	}
	free(line);
	fclose(f);
}

void
gemini_tofu_finish(struct gemini_tofu *tofu)
{
	struct known_host *host = tofu->known_hosts;
	while (host) {
		struct known_host *tmp = host;
		host = host->next;
		free(tmp->host);
		free(tmp->fingerprint);
		free(tmp);
	}
}
