#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <gmni/gmni.h>
#include <gmni/url.h>

static enum gemini_result
gemini_get_addrinfo(struct Curl_URL *uri, struct gemini_options *options, 
	struct gemini_response *resp, struct addrinfo **addr)
{
	int port = 1965;
	char *uport;
	if (curl_url_get(uri, CURLUPART_PORT, &uport, 0) == CURLUE_OK) {
		port = (int)strtol(uport, NULL, 10);
		free(uport);
	}

	if (options && options->addr && options->addr->ai_family != AF_UNSPEC) {
		*addr = options->addr;
	} else {
		struct addrinfo hints = {0};
		if (options && options->hints) {
			hints = *options->hints;
		} else {
			hints.ai_family = AF_UNSPEC;
		}
		hints.ai_socktype = SOCK_STREAM;

		char pbuf[7];
		snprintf(pbuf, sizeof(pbuf), "%d", port);

		char *domain;
		CURLUcode uc = curl_url_get(uri, CURLUPART_HOST, &domain, 0);
		assert(uc == CURLUE_OK);

		int r = getaddrinfo(domain, pbuf, &hints, addr);
		free(domain);
		if (r != 0) {
			resp->status = r;
			return GEMINI_ERR_RESOLVE;
		}
	}

	return GEMINI_OK;
}

static enum gemini_result
gemini_connect(struct Curl_URL *uri, struct gemini_options *options,
		struct gemini_response *resp, int *sfd)
{
	struct addrinfo *addr;
	enum gemini_result res = gemini_get_addrinfo(uri, options, resp, &addr);
	if (res != GEMINI_OK) {
		return res;
	}

	struct addrinfo *rp;
	for (rp = addr; rp != NULL; rp = rp->ai_next) {
		*sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (*sfd == -1) {
			continue;
		}
		if (connect(*sfd, rp->ai_addr, rp->ai_addrlen) != -1) {
			break;
		}
		close(*sfd);
	}
	if (rp == NULL) {
		resp->status = errno;
		res = GEMINI_ERR_CONNECT;
		return res;
	}

	if (!options || !options->addr) {
		freeaddrinfo(addr);
	}
	return res;
}

#define GEMINI_META_MAXLEN 1024
#define GEMINI_STATUS_MAXLEN 2

enum gemini_result
gemini_request(const char *url, struct gemini_options *options,
		struct gemini_response *resp)
{
	assert(url);
	assert(resp);
	memset(resp, 0, sizeof(*resp));
	if (strlen(url) > 1024) {
		return GEMINI_ERR_INVALID_URL;
	}

	struct Curl_URL *uri = curl_url();
	if (!uri) {
		return GEMINI_ERR_OOM;
	}

	enum gemini_result res = GEMINI_OK;
	if (curl_url_set(uri, CURLUPART_URL, url, 0) != CURLUE_OK) {
		res = GEMINI_ERR_INVALID_URL;
		goto cleanup;
	}

	char *scheme, *host;
	if (curl_url_get(uri, CURLUPART_SCHEME, &scheme, 0) != CURLUE_OK) {
		res = GEMINI_ERR_INVALID_URL;
		goto cleanup;
	} else {
		if (strcmp(scheme, "gemini") != 0) {
			res = GEMINI_ERR_NOT_GEMINI;
			free(scheme);
			goto cleanup;
		}
		free(scheme);
	}
	if (curl_url_get(uri, CURLUPART_HOST, &host, 0) != CURLUE_OK) {
		res = GEMINI_ERR_INVALID_URL;
		free(host);
		goto cleanup;
	}

	if (options && options->ssl_ctx) {
		resp->ssl_ctx = options->ssl_ctx;
		SSL_CTX_up_ref(options->ssl_ctx);
	} else {
		resp->ssl_ctx = SSL_CTX_new(TLS_method());
		assert(resp->ssl_ctx);
		SSL_CTX_set_verify(resp->ssl_ctx, SSL_VERIFY_PEER, NULL);
	}

	int r;
	BIO *sbio = BIO_new(BIO_f_ssl());
	res = gemini_connect(uri, options, resp, &resp->fd);
	if (res != GEMINI_OK) {
		free(host);
		goto cleanup;
	}

	resp->ssl = SSL_new(resp->ssl_ctx);
	assert(resp->ssl);
	SSL_set_connect_state(resp->ssl);
	if ((r = SSL_set1_host(resp->ssl, host)) != 1) {
		free(host);
		goto ssl_error;
	}
	if ((r = SSL_set_tlsext_host_name(resp->ssl, host)) != 1) {
		free(host);
		goto ssl_error;
	}
	free(host);
	if ((r = SSL_set_fd(resp->ssl, resp->fd)) != 1) {
		goto ssl_error;
	}
	if ((r = SSL_connect(resp->ssl)) != 1) {
		goto ssl_error;
	}

	X509 *cert = SSL_get_peer_certificate(resp->ssl);
	if (!cert) {
		resp->status = X509_V_ERR_UNSPECIFIED;
		res = GEMINI_ERR_SSL_VERIFY;
		goto cleanup;
	}
	X509_free(cert);

	long vr = SSL_get_verify_result(resp->ssl);
	if (vr != X509_V_OK) {
		resp->status = vr;
		res = GEMINI_ERR_SSL_VERIFY;
		goto cleanup;
	}

	BIO_set_ssl(sbio, resp->ssl, 0);

	resp->bio = BIO_new(BIO_f_buffer());
	BIO_push(resp->bio, sbio);

	char req[1024 + 3];
	r = snprintf(req, sizeof(req), "%s\r\n", url);
	assert(r > 0);

	r = BIO_puts(sbio, req);
	if (r == -1) {
		res = GEMINI_ERR_IO;
		goto cleanup;
	}
	assert(r == (int)strlen(req));

	char buf[GEMINI_META_MAXLEN
		+ GEMINI_STATUS_MAXLEN
		+ 2 /* CRLF */ + 1 /* NUL */];
	r = BIO_gets(resp->bio, buf, sizeof(buf));
	if (r == -1) {
		res = GEMINI_ERR_IO;
		goto cleanup;
	}

	if (r < 3 || strcmp(&buf[r - 2], "\r\n") != 0) {
		fprintf(stderr, "invalid line %d '%s'\n", r, buf);
		res = GEMINI_ERR_PROTOCOL;
		goto cleanup;
	}

	char *endptr;
	resp->status = (enum gemini_status)strtol(buf, &endptr, 10);
	if (*endptr != ' ' || resp->status < 10 || (int)resp->status >= 70) {
		fprintf(stderr, "invalid status\n");
		res = GEMINI_ERR_PROTOCOL;
		goto cleanup;
	}
	resp->meta = calloc(r - 5 /* 2 digits, space, and CRLF */ + 1 /* NUL */, 1);
	strncpy(resp->meta, &endptr[1], r - 5);
	resp->meta[r - 5] = '\0';

cleanup:
	curl_url_cleanup(uri);
	return res;
ssl_error:
	res = GEMINI_ERR_SSL;
	resp->status = r;
	goto cleanup;
}

void
gemini_response_finish(struct gemini_response *resp)
{
	if (!resp) {
		return;
	}

	if (resp->bio) {
		BIO_free_all(resp->bio);
		resp->bio = NULL;
	}

	if (resp->ssl) {
		SSL_free(resp->ssl);
	}
	if (resp->ssl_ctx) {
		SSL_CTX_free(resp->ssl_ctx);
	}
	free(resp->meta);

	if (resp->fd != -1) {
		close(resp->fd);
		resp->fd = -1;
	}

	resp->ssl = NULL;
	resp->ssl_ctx = NULL;
	resp->meta = NULL;
}

const char *
gemini_strerr(enum gemini_result r, struct gemini_response *resp)
{
	switch (r) {
	case GEMINI_OK:
		return "OK";
	case GEMINI_ERR_OOM:
		return "Out of memory";
	case GEMINI_ERR_INVALID_URL:
		return "Invalid URL";
	case GEMINI_ERR_NOT_GEMINI:
		return "Not a gemini URL";
	case GEMINI_ERR_RESOLVE:
		return gai_strerror(resp->status);
	case GEMINI_ERR_CONNECT:
		return strerror(errno);
	case GEMINI_ERR_SSL:
		return ERR_error_string(
			SSL_get_error(resp->ssl, resp->status),
			NULL);
	case GEMINI_ERR_SSL_VERIFY:
		return X509_verify_cert_error_string(resp->status);
	case GEMINI_ERR_IO:
		return "I/O error";
	case GEMINI_ERR_PROTOCOL:
		return "Protocol error";
	}
	assert(0);
}

char *
gemini_input_url(const char *url, const char *input)
{
	char *new_url = NULL;
	struct Curl_URL *uri = curl_url();
	if (!uri) {
		return NULL;
	}
	if (curl_url_set(uri, CURLUPART_URL, url, 0) != CURLUE_OK) {
		goto cleanup;
	}
	if (curl_url_set(uri, CURLUPART_QUERY, input, CURLU_URLENCODE) != CURLUE_OK) {
		goto cleanup;
	}
	if (curl_url_get(uri, CURLUPART_URL, &new_url, 0) != CURLUE_OK) {
		new_url = NULL;
		goto cleanup;
	}
cleanup:
	curl_url_cleanup(uri);
	return new_url;
}

enum gemini_status_class
gemini_response_class(enum gemini_status status)
{
	return status / 10 * 10;
}
