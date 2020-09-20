#ifndef GEMINI_CLIENT_H
#define GEMINI_CLIENT_H
#include <netdb.h>
#include <openssl/ssl.h>
#include <sys/socket.h>

enum gemini_result {
	GEMINI_OK,
	GEMINI_ERR_OOM,
	GEMINI_ERR_INVALID_URL,
	GEMINI_ERR_NOT_GEMINI,
	GEMINI_ERR_RESOLVE,
	GEMINI_ERR_CONNECT,
	GEMINI_ERR_SSL,
	GEMINI_ERR_IO,
	GEMINI_ERR_PROTOCOL,
};

enum gemini_status {
	GEMINI_STATUS_INPUT = 10,
	GEMINI_STATUS_SENSITIVE_INPUT = 11,
	GEMINI_STATUS_SUCCESS = 20,
	GEMINI_STATUS_REDIRECT_TEMPORARY = 30,
	GEMINI_STATUS_REDIRECT_PERMANENT = 31,
	GEMINI_STATUS_TEMPORARY_FAILURE = 40,
	GEMINI_STATUS_SERVER_UNAVAILABLE = 41,
	GEMINI_STATUS_CGI_ERROR = 42,
	GEMINI_STATUS_PROXY_ERROR = 43,
	GEMINI_STATUS_SLOW_DOWN = 44,
	GEMINI_STATUS_PERMANENT_FAILURE = 50,
	GEMINI_STATUS_NOT_FOUND = 51,
	GEMINI_STATUS_GONE = 52,
	GEMINI_STATUS_PROXY_REQUEST_REFUSED = 53,
	GEMINI_STATUS_BAD_REQUEST = 59,
	GEMINI_STATUS_CLIENT_CERTIFICATE_REQUIRED = 60,
	GEMINI_STATUS_CERTIFICATE_NOT_AUTHORIZED = 61,
	GEMINI_STATUS_CERTIFICATE_NOT_VALID = 62,
};

enum gemini_status_class {
	GEMINI_STATUS_CLASS_INPUT = 10,
	GEMINI_STATUS_CLASS_SUCCESS = 20,
	GEMINI_STATUS_CLASS_REDIRECT = 30,
	GEMINI_STATUS_CLASS_TEMPORARY_FAILURE = 40,
	GEMINI_STATUS_CLASS_PERMANENT_FAILURE = 50,
	GEMINI_STATUS_CLASS_CLIENT_CERTIFICATE_REQUIRED = 60,
};

struct gemini_response {
	enum gemini_status status;
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

// Requests the specified URL via the gemini protocol. If options is non-NULL,
// it may specify some additional configuration to adjust client behavior.
//
// Returns a value indicating the success of the request.
//
// Caller must call gemini_response_finish afterwards to clean up resources
// before exiting or re-using it for another request.
enum gemini_result gemini_request(const char *url,
		struct gemini_options *options,
		struct gemini_response *resp);

// Must be called after gemini_request in order to free up the resources
// allocated during the request.
void gemini_response_finish(struct gemini_response *resp);

// Returns a user-friendly string describing an error.
const char *gemini_strerr(enum gemini_result r, struct gemini_response *resp);

// Returns the given URL with the input response set to the specified value.
// The caller must free the string.
char *gemini_input_url(const char *url, const char *input);

// Returns the general response class (i.e. with the second digit set to zero)
// of the given Gemini status code.
enum gemini_status_class gemini_response_class(enum gemini_status status);

#endif
