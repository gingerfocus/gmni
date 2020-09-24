#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#include "gmni.h"
#include "tofu.h"

static void
usage(const char *argv_0)
{
	fprintf(stderr,
		"usage: %s [-46lLiIN] [-E cert] [-d input] [-D path] gemini://...\n",
		argv_0);
}

static char *
get_input(const struct gemini_response *resp, FILE *source)
{
	int r = 0;
	struct termios attrs;
	bool tty = fileno(source) != -1 && isatty(fileno(source));
	char *input = NULL;
	if (tty) {
		fprintf(stderr, "%s: ", resp->meta);
		if (resp->status == GEMINI_STATUS_SENSITIVE_INPUT) {
			r = tcgetattr(fileno(source), &attrs);
			struct termios new_attrs;
			r = tcgetattr(fileno(source), &new_attrs);
			if (r != -1) {
				new_attrs.c_lflag &= ~ECHO;
				tcsetattr(fileno(source), TCSANOW, &new_attrs);
			}
		}
	}
	size_t s = 0;
	ssize_t n = getline(&input, &s, source);
	if (n == -1) {
		fprintf(stderr, "Error reading input: %s\n",
			feof(source) ? "EOF" :
			strerror(ferror(source)));
		return NULL;
	}
	input[n - 1] = '\0'; // Drop LF
	if (tty && resp->status == GEMINI_STATUS_SENSITIVE_INPUT && r != -1) {
		attrs.c_lflag &= ~ECHO;
		tcsetattr(fileno(source), TCSANOW, &attrs);
	}
	return input;
}

struct tofu_config {
	struct gemini_tofu tofu;
	enum tofu_action action;
};

static enum tofu_action
tofu_callback(enum tofu_error error, const char *fingerprint,
	struct known_host *host, void *data)
{
	struct tofu_config *cfg = (struct tofu_config *)data;
	enum tofu_action action = cfg->action;
	switch (error) {
	case TOFU_VALID:
		assert(0); // Invariant
	case TOFU_INVALID_CERT:
		fprintf(stderr,
			"The server presented an invalid certificate with fingerprint %s.\n",
			fingerprint);
		if (action == TOFU_TRUST_ALWAYS) {
			action = TOFU_TRUST_ONCE;
		}
		break;
	case TOFU_UNTRUSTED_CERT:
		fprintf(stderr,
			"The certificate offered by this server is of unknown trust. "
			"Its fingerprint is: \n"
			"%s\n\n", fingerprint);
		break;
	case TOFU_FINGERPRINT_MISMATCH:
		fprintf(stderr,
			"The certificate offered by this server DOES NOT MATCH the one we have on file.\n"
			"/!\\ Someone may be eavesdropping on or manipulating this connection. /!\\\n"
			"The unknown certificate's fingerprint is:\n"
			"%s\n\n"
			"The expected fingerprint is:\n"
			"%s\n\n"
			"If you're certain that this is correct, edit %s:%d\n",
			fingerprint, host->fingerprint,
			cfg->tofu.known_hosts_path, host->lineno);
		return TOFU_FAIL;
	}

	if (action == TOFU_ASK) {
		return TOFU_FAIL;
	}

	return action;
}

int
main(int argc, char *argv[])
{
	enum header_mode {
		OMIT_HEADERS,
		SHOW_HEADERS,
		ONLY_HEADERS,
	};
	enum header_mode header_mode = OMIT_HEADERS;

	enum input_mode {
		INPUT_READ,
		INPUT_SUPPRESS,
	};
	enum input_mode input_mode = INPUT_READ;
	FILE *input_source = stdin;

	bool follow_redirects = false, linefeed = true;
	int max_redirect = 5;

	struct addrinfo hints = {0};
	struct gemini_options opts = {
		.hints = &hints,
	};
	struct tofu_config cfg;
	cfg.action = TOFU_ASK;

	int c;
	while ((c = getopt(argc, argv, "46d:D:E:hj:lLiINR:")) != -1) {
		switch (c) {
		case '4':
			hints.ai_family = AF_INET;
			break;
		case '6':
			hints.ai_family = AF_INET6;
			break;
		case 'd':
			input_mode = INPUT_READ;
			input_source = fmemopen(optarg, strlen(optarg), "r");
			break;
		case 'D':
			input_mode = INPUT_READ;
			if (strcmp(optarg, "-") == 0) {
				input_source = stdin;
			} else {
				input_source = fopen(optarg, "r");
				if (!input_source) {
					fprintf(stderr, "Error: open %s: %s",
							optarg, strerror(errno));
					return 1;
				}
			}
			break;
		case 'E':
			assert(0); // TODO: Client certificates
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		case 'j':
			if (strcmp(optarg, "fail") == 0) {
				cfg.action = TOFU_FAIL;
			} else if (strcmp(optarg, "once") == 0) {
				cfg.action = TOFU_TRUST_ONCE;
			} else if (strcmp(optarg, "always") == 0) {
				cfg.action = TOFU_TRUST_ALWAYS;
			} else {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'l':
			linefeed = false;
			break;
		case 'L':
			follow_redirects = true;
			break;
		case 'i':
			header_mode = SHOW_HEADERS;
			break;
		case 'I':
			header_mode = ONLY_HEADERS;
			input_mode = INPUT_SUPPRESS;
			break;
		case 'N':
			input_mode = INPUT_SUPPRESS;
			break;
		case 'R':;
			char *endptr;
			errno = 0;
			max_redirect = strtoul(optarg, &endptr, 10);
			if (*endptr || errno != 0) {
				fprintf(stderr, "Error: -R expects numeric argument\n");
				return 1;
			}
			break;
		default:
			fprintf(stderr, "fatal: unknown flag %c\n", c);
			return 1;
		}
	}

	if (optind != argc - 1) {
		usage(argv[0]);
		return 1;
	}

	SSL_load_error_strings();
	ERR_load_crypto_strings();
	opts.ssl_ctx = SSL_CTX_new(TLS_method());
	gemini_tofu_init(&cfg.tofu, opts.ssl_ctx, &tofu_callback, &cfg);

	bool exit = false;
	char *url = strdup(argv[optind]);

	int ret = 0, nredir = 0;
	while (!exit) {
		struct gemini_response resp;
		enum gemini_result r = gemini_request(url, &opts, &resp);
		if (r != GEMINI_OK) {
			fprintf(stderr, "Error: %s\n", gemini_strerr(r, &resp));
			ret = (int)r;
			exit = true;
			goto next;
		}

		switch (gemini_response_class(resp.status)) {
		case GEMINI_STATUS_CLASS_INPUT:
			if (input_mode == INPUT_SUPPRESS) {
				exit = true;
				break;
			}

			char *input = get_input(&resp, input_source);
			if (!input) {
				r = 1;
				exit = true;
				break;
			}

			char *new_url = gemini_input_url(url, input);
			assert(new_url);

			free(input);
			free(url);
			url = new_url;
			goto next;
		case GEMINI_STATUS_CLASS_REDIRECT:
			if (++nredir >= max_redirect) {
				fprintf(stderr,
					"Error: maximum redirects (%d) exceeded",
					max_redirect);
				exit = true;
				goto next;
			}

			free(url);
			url = strdup(resp.meta);
			if (!follow_redirects) {
				if (header_mode == OMIT_HEADERS) {
					fprintf(stderr, "REDIRECT: %d %s\n",
						resp.status, resp.meta);
				}
				exit = true;
			}
			goto next;
		case GEMINI_STATUS_CLASS_CLIENT_CERTIFICATE_REQUIRED:
			assert(0); // TODO
		case GEMINI_STATUS_CLASS_TEMPORARY_FAILURE:
		case GEMINI_STATUS_CLASS_PERMANENT_FAILURE:
			if (header_mode == OMIT_HEADERS) {
				fprintf(stderr, "%s: %d %s\n",
					resp.status / 10 == 4 ?
					"TEMPORARY FAILURE" : "PERMANENT FALIURE",
					resp.status, resp.meta);
			}
			exit = true;
			break;
		case GEMINI_STATUS_CLASS_SUCCESS:
			exit = true;
			break;
		}

		switch (header_mode) {
		case ONLY_HEADERS:
			printf("%d %s\n", resp.status, resp.meta);
			break;
		case SHOW_HEADERS:
			printf("%d %s\n", resp.status, resp.meta);
			/* fallthrough */
		case OMIT_HEADERS:
			if (gemini_response_class(resp.status) !=
					GEMINI_STATUS_CLASS_SUCCESS) {
				break;
			}

			char last;
			char buf[BUFSIZ];
			for (int n = 1; n > 0;) {
				n = BIO_read(resp.bio, buf, BUFSIZ);
				if (n == -1) {
					fprintf(stderr, "Error: read\n");
					return 1;
				} else if (n != 0) {
					last = buf[n - 1];
				}
				ssize_t w = 0;
				while (w < (ssize_t)n) {
					ssize_t x = fwrite(&buf[w], 1, n - w, stdout);
					if (ferror(stdout)) {
						fprintf(stderr, "Error: write: %s\n",
							strerror(errno));
						return 1;
					}
					w += x;
				}
			}
			if (strncmp(resp.meta, "text/", 5) == 0
					&& linefeed && last != '\n'
					&& isatty(STDOUT_FILENO)) {
				printf("\n");
			}
			break;
		}

next:
		gemini_response_finish(&resp);
	}

	SSL_CTX_free(opts.ssl_ctx);
	free(url);
	gemini_tofu_finish(&cfg.tofu);
	return ret;
}
