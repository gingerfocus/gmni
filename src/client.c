#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <bearssl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <gmni/certs.h>
#include <gmni/gmni.h>
#include <gmni/tofu.h>
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

static int
sock_read(void *ctx, unsigned char *buf, size_t len)
{
	for (;;) {
		ssize_t rlen;
		rlen = read(*(int *)ctx, buf, len);
		if (rlen <= 0) {
			if (rlen < 0 && errno == EINTR) {
				continue;
			}
			return -1;
		}
		return (int)rlen;
	}
}

static int
sock_write(void *ctx, const unsigned char *buf, size_t len)
{
	for (;;) {
		ssize_t wlen;
		wlen = write(*(int *)ctx, buf, len);
		if (wlen <= 0) {
			if (wlen < 0 && errno == EINTR) {
				continue;
			}
			return -1;
		}
		return (int)wlen;
	}
}

enum gemini_result
gemini_request(const char *url, struct gemini_options *options,
		struct gemini_tofu *tofu, struct gemini_response *resp)
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

	int r;
	res = gemini_connect(uri, options, resp, &resp->fd);
	if (res != GEMINI_OK) {
		free(host);
		goto cleanup;
	}

	// TODO: session reuse
	resp->sc = &tofu->sc;
	if (options->client_cert) {
		struct gmni_client_certificate *cert = options->client_cert;
		struct gmni_private_key *key = cert->key;
		switch (key->type) {
		case BR_KEYTYPE_RSA:
			br_ssl_client_set_single_rsa(resp->sc,
				cert->chain, cert->nchain, &key->rsa,
				br_rsa_pkcs1_sign_get_default());
			break;
		case BR_KEYTYPE_EC:
			br_ssl_client_set_single_ec(resp->sc,
				cert->chain, cert->nchain, &key->ec,
				BR_KEYTYPE_SIGN, 0,
				br_ec_get_default(),
				br_ecdsa_sign_asn1_get_default());
			break;
		}
	}
	br_ssl_client_reset(resp->sc, host, 0);

	br_sslio_init(&resp->body, &resp->sc->eng,
		sock_read, &resp->fd, sock_write, &resp->fd);

	char req[1024 + 3];
	r = snprintf(req, sizeof(req), "%s\r\n", url);
	assert(r > 0);

	br_sslio_write_all(&resp->body, req, r);
	br_sslio_flush(&resp->body);

	// The SSL engine maintains an internal buffer, so this shouldn't be as
	// inefficient as it looks. It's necessary to do this one byte at a time
	// to avoid consuming any of the response body buffer.
	char buf[GEMINI_META_MAXLEN
		+ GEMINI_STATUS_MAXLEN
		+ 2 /* CRLF */ + 1 /* NUL */];
	memset(buf, 0, sizeof(buf));
	size_t l;
	for (l = 0; l < 2 || memcmp(&buf[l-2], "\r\n", 2) != 0; ++l) {
		r = br_sslio_read(&resp->body, &buf[l], 1);
		if (r < 0) {
			break;
		}
	}

	int err = br_ssl_engine_last_error(&resp->sc->eng);
	if (err != 0) {
		// TODO: Bubble this up properly
		fprintf(stderr, "SSL error %d\n", err);
		goto ssl_error;
	}

	if (l < 3 || strcmp(&buf[l-2], "\r\n") != 0) {
		fprintf(stderr, "invalid line '%s'\n", buf);
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
	resp->meta = calloc(l - 5 /* 2 digits, space, and CRLF */ + 1 /* NUL */, 1);
	strncpy(resp->meta, &endptr[1], l - 5);
	resp->meta[l - 5] = '\0';

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

	if (resp->fd != -1) {
		close(resp->fd);
		resp->fd = -1;
	}

	free(resp->meta);

	if (resp->sc) {
		br_sslio_close(&resp->body);
	}

	resp->sc = NULL;
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
		// TODO: more specific
		return "SSL error";
	case GEMINI_ERR_SSL_VERIFY:
		// TODO: more specific
		return "X.509 certificate not trusted";
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
