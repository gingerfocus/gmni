#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "client.h"

static void
usage(char *argv_0)
{
	fprintf(stderr,
		"usage: %s [-LI] [-C cert] [-d input] gemini://...\n",
		argv_0);
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
	bool linefeed = true;

	int c;
	while ((c = getopt(argc, argv, "46C:d:D:hlLiIN")) != -1) {
		switch (c) {
		case '4':
			assert(0); // TODO
			break;
		case '6':
			assert(0); // TODO
			break;
		case 'C':
			assert(0); // TODO: Client certificates
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
		case 'h':
			usage(argv[0]);
			return 0;
		case 'l':
			linefeed = false;
			break;
		case 'L':
			assert(0); // TODO: Follow redirects
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

	bool exit = false;
	char *url = strdup(argv[optind]);

	int ret = 0;
	while (!exit) {
		struct gemini_response resp;
		enum gemini_result r = gemini_request(url, NULL, &resp);
		if (r != GEMINI_OK) {
			fprintf(stderr, "Error: %s\n", gemini_strerr(r, &resp));
			ret = (int)r;
			exit = true;
			goto next;
		}

		char *new_url, *input = NULL;
		switch (resp.status / 10) {
		case 1: // INPUT
			if (input_mode == INPUT_SUPPRESS) {
				exit = true;
				break;
			}

			if (fileno(input_source) != -1 &&
					isatty(fileno(input_source))) {
				fprintf(stderr, "%s: ", resp.meta);
			}

			size_t s = 0;
			ssize_t n = getline(&input, &s, input_source);
			if (n == -1) {
				fprintf(stderr, "Error reading input: %s\n",
					feof(input_source) ? "EOF" :
					strerror(ferror(input_source)));
				r = 1;
				exit = true;
				break;
			}
			input[n - 1] = '\0'; // Drop LF

			new_url = gemini_input_url(url, input);
			free(url);
			url = new_url;
			goto next;
		case 3: // REDIRECT
			assert(0); // TODO
		case 6: // CLIENT CERTIFICATE REQUIRED
			assert(0); // TODO
		case 4: // TEMPORARY FAILURE
		case 5: // PERMANENT FAILURE
			if (header_mode == OMIT_HEADERS) {
				fprintf(stderr, "%s: %d %s\n",
					resp.status / 10 == 4 ?
					"TEMPORARY FAILURE" : "PERMANENT FALIURE",
					resp.status, resp.meta);
			}
			exit = true;
			break;
		case 2: // SUCCESS
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
			if (resp.status / 10 != 2) {
				break;
			}
			char buf[BUFSIZ];
			int n;
			for (n = 1; n > 0;) {
				n = BIO_read(resp.bio, buf, BUFSIZ);
				if (n == -1) {
					fprintf(stderr, "Error: read\n");
					return 1;
				}
				ssize_t w = 0;
				while (w < (ssize_t)n) {
					ssize_t x = write(STDOUT_FILENO, &buf[w], n - w);
					if (x == -1) {
						fprintf(stderr, "Error: write: %s\n",
							strerror(errno));
						return 1;
					}
					w += x;
				}
			}
			if (strncmp(resp.meta, "text/", 5) == 0
					&& linefeed
					&& buf[n - 1] != '\n') {
				printf("\n");
			}
			break;
		}

next:
		gemini_response_finish(&resp);
	}

	(void)input_mode;
	free(url);
	return ret;
}
