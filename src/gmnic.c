#include <assert.h>
#include <getopt.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
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
	bool headers = false, follow_redirect = false;
	char *certificate = NULL, *input = NULL;

	int c;
	while ((c = getopt(argc, argv, "46C:d:hLI")) != -1) {
		switch (c) {
		case '4':
			assert(0); // TODO
			break;
		case '6':
			assert(0); // TODO
			break;
		case 'C':
			certificate = optarg;
			break;
		case 'd':
			input = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		case 'L':
			follow_redirect = true;
			break;
		case 'I':
			headers = true;
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
	switch (r) {
	case GEMINI_OK:
		printf("OK\n");
		break;
	case GEMINI_ERR_OOM:
		printf("OOM\n");
		break;
	case GEMINI_ERR_INVALID_URL:
		printf("INVALID_URL\n");
		break;
	case GEMINI_ERR_RESOLVE:
		printf("RESOLVE\n");
		break;
	case GEMINI_ERR_CONNECT:
		printf("CONNECT\n");
		break;
	case GEMINI_ERR_SSL:
		fprintf(stderr, "SSL error: %s\n", ERR_error_string(
			SSL_get_error(resp.ssl, resp.status), NULL));
		break;
	}

	gemini_response_finish(&resp);

	(void)headers;
	(void)follow_redirect;
	(void)certificate;
	(void)input;
	return 0;
}
