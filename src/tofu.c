#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "tofu.h"
#include "util.h"

static int
verify_callback(X509_STORE_CTX *ctx, void *data)
{
	// Gemini clients handle TLS verification differently from the rest of
	// the internet. We use a TOFU system, so trust is based on two factors:
	//
	// - Is the certificate valid at the time of the request?
	// - Has the user trusted this certificate yet?
	//
	// If the answer to the latter is "no", then we give the user an
	// opportunity to explicitly agree to trust the certificate before
	// rejecting it.
	//
	// If you're reading this code with the intent to re-use it, think
	// twice.
	// 
	// TODO: Check that the subject name is valid for the requested URL.
	struct gemini_tofu *tofu = (struct gemini_tofu *)data;
	X509 *cert = X509_STORE_CTX_get0_cert(ctx);
	struct known_host *host = NULL;

	int rc;
	int day, sec;
	const ASN1_TIME *notBefore = X509_get0_notBefore(cert);
	const ASN1_TIME *notAfter = X509_get0_notAfter(cert);
	if (!ASN1_TIME_diff(&day, &sec, NULL, notBefore)) {
		rc = X509_V_ERR_UNSPECIFIED;
		goto invalid_cert;
	}
	if (day > 0 || sec > 0) {
		rc = X509_V_ERR_CERT_NOT_YET_VALID;
		goto invalid_cert;
	}
	if (!ASN1_TIME_diff(&day, &sec, NULL, notAfter)) {
		rc = X509_V_ERR_UNSPECIFIED;
		goto invalid_cert;
	}
	if (day < 0 || sec < 0) {
		rc = X509_V_ERR_CERT_HAS_EXPIRED;
		goto invalid_cert;
	}

	unsigned char md[256 / 8];
	const EVP_MD *sha512 = EVP_sha512();
	unsigned int len = sizeof(md);
	rc = X509_digest(cert, sha512, md, &len);
	assert(rc == 1);

	char fingerprint[256 / 8 * 3];
	for (size_t i = 0; i < sizeof(md); ++i) {
		snprintf(&fingerprint[i * 3], 4, "%02X%s",
			md[i], i + 1 == sizeof(md) ? "" : ":");
	}

	SSL *ssl = X509_STORE_CTX_get_ex_data(ctx,
		SSL_get_ex_data_X509_STORE_CTX_idx());
	const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!servername) {
		rc = X509_V_ERR_HOSTNAME_MISMATCH;
		goto invalid_cert;
	}

	time_t now;
	time(&now);

	enum tofu_error error = TOFU_UNTRUSTED_CERT;
	host = tofu->known_hosts;
	while (host) {
		if (host->expires < now) {
			goto next;
		}
		if (strcmp(host->host, servername) != 0) {
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

	rc = X509_V_ERR_CERT_UNTRUSTED;
	
callback:
	switch (tofu->callback(error, fingerprint, host, tofu->cb_data)) {
	case TOFU_ASK:
		assert(0); // Invariant
	case TOFU_FAIL:
		X509_STORE_CTX_set_error(ctx, rc);
		break;
	case TOFU_TRUST_ONCE:
		// No further action necessary
		return 0;
	case TOFU_TRUST_ALWAYS:;
		FILE *f = fopen(tofu->known_hosts_path, "a");
		if (!f) {
			fprintf(stderr, "Error opening %s for writing: %s\n",
				tofu->known_hosts_path, strerror(errno));
			break;
		};
		struct tm expires_tm;
		ASN1_TIME_to_tm(notAfter, &expires_tm);
		time_t expires = mktime(&expires_tm);
		fprintf(f, "%s %s %s %ld\n", servername,
			"SHA-512", fingerprint, expires);
		fclose(f);

		host = calloc(1, sizeof(struct known_host));
		host->host = strdup(servername);
		host->fingerprint = strdup(fingerprint);
		host->expires = expires;
		host->lineno = ++tofu->lineno;
		host->next = tofu->known_hosts;
		tofu->known_hosts = host;
		return 0;
	}

	X509_STORE_CTX_set_error(ctx, rc);
	return 0;

invalid_cert:
	error = TOFU_INVALID_CERT;
	goto callback;
}


void
gemini_tofu_init(struct gemini_tofu *tofu,
	SSL_CTX *ssl_ctx, tofu_callback_t *cb, void *cb_data)
{
	const struct pathspec paths[] = {
		{.var = "GMNIDATA", .path = "/%s"},
		{.var = "XDG_DATA_HOME", .path = "/gmni/%s"},
		{.var = "HOME", .path = "/.local/share/gmni/%s"}
	};
	char *path_fmt = getpath(paths, sizeof(paths) / sizeof(paths[0]));
	snprintf(tofu->known_hosts_path, sizeof(tofu->known_hosts_path),
			path_fmt, "known_hosts");

	if (mkdirs(dirname(tofu->known_hosts_path), 0755) != 0) {
		snprintf(tofu->known_hosts_path, sizeof(tofu->known_hosts_path),
				path_fmt, "known_hosts");
		fprintf(stderr, "Error creating directory %s: %s\n",
				dirname(tofu->known_hosts_path), strerror(errno));
		return;
	}

	snprintf(tofu->known_hosts_path, sizeof(tofu->known_hosts_path),
			path_fmt, "known_hosts");
	free(path_fmt);

	tofu->callback = cb;
	tofu->cb_data = cb_data;
	SSL_CTX_set_cert_verify_callback(ssl_ctx, verify_callback, tofu);

	FILE *f = fopen(tofu->known_hosts_path, "r");
	if (!f) {
		return;
	}
	size_t n = 0;
	char *line = NULL;
	tofu->known_hosts = NULL;
	while (getline(&line, &n, f) != -1) {
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

		tok = strtok(NULL, " ");
		assert(tok);
		host->expires = strtoul(tok, NULL, 10);

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
