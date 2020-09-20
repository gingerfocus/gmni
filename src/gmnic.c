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
	enum header_mode headers = OMIT_HEADERS;

	int c;
	while ((c = getopt(argc, argv, "46C:d:hLiI")) != -1) {
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
			assert(0); // TODO: Input
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		case 'L':
			assert(0); // TODO: Follow redirects
			break;
		case 'i':
			headers = SHOW_HEADERS;
			break;
		case 'I':
			headers = ONLY_HEADERS;
			break;
		default:
			fprintf(stderr, "fatal: unknown flag %c", c);
			return 1;
		}
	}

	if (optind != argc - 1) {
		usage(argv[0]);
		return 1;
	}

	SSL_load_error_strings();
	ERR_load_crypto_strings();

	struct gemini_response resp;
	enum gemini_result r = gemini_request(argv[optind], NULL, &resp);
	if (r != GEMINI_OK) {
		fprintf(stderr, "Error: %s\n", gemini_strerr(r, &resp));
		gemini_response_finish(&resp);
		return (int)r;
	}

	switch (headers) {
	case ONLY_HEADERS:
		printf("%d %s\n", resp.status, resp.meta);
		break;
	case SHOW_HEADERS:
		printf("%d %s\n", resp.status, resp.meta);
		/* fallthrough */
	case OMIT_HEADERS:
		for (int n = 1; n > 0;) {
			char buf[BUFSIZ];
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
		break;
	}

	gemini_response_finish(&resp);
	return 0;
}
