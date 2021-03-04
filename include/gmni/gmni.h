#ifndef GEMINI_CLIENT_H
#define GEMINI_CLIENT_H
#include <bearssl_ssl.h>
#include <netdb.h>
#include <stdbool.h>
#include <sys/socket.h>

enum gemini_result {
	GEMINI_OK,
	GEMINI_ERR_OOM,
	GEMINI_ERR_INVALID_URL,
	GEMINI_ERR_NOT_GEMINI,
	GEMINI_ERR_RESOLVE,
	GEMINI_ERR_CONNECT,
	GEMINI_ERR_SSL,
	GEMINI_ERR_SSL_VERIFY,
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

	// TODO: Make these private
	// Response body may be read from here if appropriate:
	br_sslio_context body;

	// Connection state
	br_ssl_client_context *sc;
	int fd;
};

struct gemini_options {
	// If ai_family != AF_UNSPEC (the default value on most systems), the
	// client will connect to this address and skip name resolution.
	struct addrinfo *addr;

	// If non-NULL, these hints are provided to getaddrinfo. Useful, for
	// example, to force IPv4/IPv6.
	struct addrinfo *hints;
};

struct gemini_tofu;

// Requests the specified URL via the gemini protocol. If options is non-NULL,
// it may specify some additional configuration to adjust client behavior.
//
// Returns a value indicating the success of the request.
//
// Caller must call gemini_response_finish afterwards to clean up resources
// before exiting or re-using it for another request.
enum gemini_result gemini_request(const char *url,
		struct gemini_options *options,
		struct gemini_tofu *tofu,
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

enum gemini_tok {
	GEMINI_TEXT,
	GEMINI_LINK,
	GEMINI_PREFORMATTED_BEGIN,
	GEMINI_PREFORMATTED_END,
	GEMINI_PREFORMATTED_TEXT,
	GEMINI_HEADING,
	GEMINI_LIST_ITEM,
	GEMINI_QUOTE,
};

struct gemini_token {
	enum gemini_tok token;

	// The token field determines which of the union members is valid.
	union {
		char *text;

		struct {
			char *text;
			char *url; // May be NULL
		} link;

		char *preformatted;

		struct {
			char *title;
			int level; // 1, 2, or 3
		} heading;

		char *list_item;
		char *quote_text;
	};
};

struct gemini_parser {
	int (*read)(void *state, void *buf, size_t nbyte);
	void *state;
	char *buf;
	size_t bufsz;
	size_t bufln;
	bool preformatted;
};

// Initializes a text/gemini parser. The provided "read" function will be called
// with the provided "state" value in order to obtain more gemtext data. The
// read function should behave like read(3).
void gemini_parser_init(struct gemini_parser *p,
		int (*read)(void *state, void *buf, size_t nbyte),
		void *state);

// Finishes this text/gemini parser and frees up its resources.
void gemini_parser_finish(struct gemini_parser *p);

// Reads the next token from a text/gemini file.
// 
// Returns 0 on success, 1 on EOF, and -1 on failure.
//
// Caller must call gemini_token_finish before exiting or re-using the token
// parameter.
int gemini_parser_next(struct gemini_parser *p, struct gemini_token *token);

// Must be called after gemini_next to free up resources for the next token.
void gemini_token_finish(struct gemini_token *token);

#endif
