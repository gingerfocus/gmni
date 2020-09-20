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
#include "gmni.h"
#include "url.h"

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
		goto cleanup;
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

cleanup:
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
	resp->meta = NULL;
	if (strlen(url) > 1024) {
		return GEMINI_ERR_INVALID_URL;
	}

	struct Curl_URL *uri = curl_url();
	if (!uri) {
		return GEMINI_ERR_OOM;
	}
	if (curl_url_set(uri, CURLUPART_URL, url, 0) != CURLUE_OK) {
		return GEMINI_ERR_INVALID_URL;
	}

	enum gemini_result res = GEMINI_OK;
	if (options && options->ssl_ctx) {
		resp->ssl_ctx = options->ssl_ctx;
		SSL_CTX_up_ref(options->ssl_ctx);
	} else {
		resp->ssl_ctx = SSL_CTX_new(TLS_method());
		assert(resp->ssl_ctx);
	}

	BIO *sbio = BIO_new(BIO_f_ssl());
	if (options && options->ssl) {
		resp->ssl = options->ssl;
		SSL_up_ref(resp->ssl);
		BIO_set_ssl(sbio, resp->ssl, 0);
		resp->fd = -1;
	} else {
		res = gemini_connect(uri, options, resp, &resp->fd);
		if (res != GEMINI_OK) {
			goto cleanup;
		}

		resp->ssl = SSL_new(resp->ssl_ctx);
		assert(resp->ssl);
		int r = SSL_set_fd(resp->ssl, resp->fd);
		if (r != 1) {
			resp->status = r;
			res = GEMINI_ERR_SSL;
			goto cleanup;
		}
		r = SSL_connect(resp->ssl);
		if (r != 1) {
			resp->status = r;
			res = GEMINI_ERR_SSL;
			goto cleanup;
		}
		BIO_set_ssl(sbio, resp->ssl, 0);
	}

	resp->bio = BIO_new(BIO_f_buffer());
	BIO_push(resp->bio, sbio);

	char req[1024 + 3];
	int r = snprintf(req, sizeof(req), "%s\r\n", url);
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
		res = GEMINI_ERR_PROTOCOL;
		goto cleanup;
	}

	char *endptr;
	resp->status = (int)strtol(buf, &endptr, 10);
	if (*endptr != ' ' || resp->status < 10 || resp->status >= 70) {
		res = GEMINI_ERR_PROTOCOL;
		goto cleanup;
	}
	resp->meta = calloc(r - 5 /* 2 digits, space, and CRLF */ + 1 /* NUL */, 1);
	strncpy(resp->meta, &endptr[1], r - 5);
	resp->meta[r - 5] = '\0';

cleanup:
	curl_url_cleanup(uri);
	return res;
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

	if (resp->bio) {
		BIO_free(BIO_pop(resp->bio)); // ssl bio
		BIO_free(resp->bio); // buffered bio
		resp->bio = NULL;
	}

	SSL_free(resp->ssl);
	SSL_CTX_free(resp->ssl_ctx);
	free(resp->meta);

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
	case GEMINI_ERR_RESOLVE:
		return gai_strerror(resp->status);
	case GEMINI_ERR_CONNECT:
		return strerror(errno);
	case GEMINI_ERR_SSL:
		return ERR_error_string(
			SSL_get_error(resp->ssl, resp->status),
			NULL);
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
	return status / 10;
}
