#ifndef GEMINI_CLIENT_H
#define GEMINI_CLIENT_H
#include <netdb.h>
#include <openssl/ssl.h>
#include <sys/socket.h>

struct gemini_response {
	int status;
	char *meta;

	// Response body may be read from here if appropriate:
	BIO *bio;

	// Connection state
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	int fd;
};

struct gemini_options {
	// If NULL, an SSL context will be created. If unset, the ssl field
	// must also be NULL.
	SSL_CTX *ssl_ctx;

	// If NULL, an SSL connection will be established. If set, it is
	// presumed that the caller pre-established the SSL connection.
	SSL *ssl;

	// If ai_family != AF_UNSPEC (the default value on most systems), the
	// client will connect to this address and skip name resolution.
	struct addrinfo *addr;

	// If non-NULL, these hints are provided to getaddrinfo. Useful, for
	// example, to force IPv4/IPv6.
	struct addrinfo *hints;
};

enum gemini_result {
	GEMINI_OK,
	GEMINI_ERR_OOM,
	GEMINI_ERR_INVALID_URL,
	// status is set to the return value from getaddrinfo
	GEMINI_ERR_RESOLVE,
	// status is set to errno
	GEMINI_ERR_CONNECT,
	// use SSL_get_error(resp->ssl, resp->status) to get details
	GEMINI_ERR_SSL,
	GEMINI_ERR_IO,
	GEMINI_ERR_PROTOCOL,
};

// Requests the specified URL via the gemini protocol. If options is non-NULL,
// it may specify some additional configuration to adjust client behavior.
//
// Returns a value indicating the success of the request. If GEMINI_OK is
// returned, the response details shall be written to the gemini_response
// argument.
enum gemini_result gemini_request(const char *url,
		struct gemini_options *options,
		struct gemini_response *resp);

// Must be called after gemini_request in order to free up the resources
// allocated during the request. If you intend to re-use the SSL_CTX provided by
// gemini_options, set the ctx pointer to NULL before calling
// gemini_response_finish.
void gemini_response_finish(struct gemini_response *resp);

// Returns a user-friendly string describing an error.
const char *gemini_strerr(enum gemini_result r, struct gemini_response *resp);

#endif
