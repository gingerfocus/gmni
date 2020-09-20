#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include "gmni.h"
#include "url.h"

struct link {
	char *url;
	struct link *next;
};

static void
usage(const char *argv_0)
{
	fprintf(stderr, "usage: %s [gemini://...]\n", argv_0);
}

static bool
set_url(struct Curl_URL *url, char *new_url)
{
	if (curl_url_set(url, CURLUPART_URL, new_url, 0) != CURLUE_OK) {
		fprintf(stderr, "Error: invalid URL\n");
		return false;
	}
	return true;
}

static char *
trim_ws(char *in)
{
	for (int i = strlen(in) - 1; in[i] && isspace(in[i]); --i) {
		in[i] = 0;
	}
	for (; *in && isspace(*in); ++in);
	return in;
}

static void
display_gemini(FILE *tty, struct gemini_response *resp,
		struct link **next, bool pagination)
{
	int nlinks = 0;
	struct gemini_parser p;
	gemini_parser_init(&p, resp->bio);

	struct winsize ws;
	ioctl(fileno(tty), TIOCGWINSZ, &ws);

	int row = 0, col = 0;
	struct gemini_token tok;
	while (gemini_parser_next(&p, &tok) == 0) {
		switch (tok.token) {
		case GEMINI_TEXT:
			// TODO: word wrap
			col += fprintf(tty, "   %s\n", trim_ws(tok.text));
			break;
		case GEMINI_LINK:
			(void)next; // TODO: Record links
			col += fprintf(tty, "[%d] %s\n", nlinks++, trim_ws(
				tok.link.text ? tok.link.text : tok.link.url));
			break;
		case GEMINI_PREFORMATTED:
			continue; // TODO
		case GEMINI_HEADING:
			for (int n = tok.heading.level; n; --n) {
				col += fprintf(tty, "#");
			}
			col += fprintf(tty, " %s\n", trim_ws(tok.heading.title));
			break;
		case GEMINI_LIST_ITEM:
			// TODO: Option to disable Unicode
			col += fprintf(tty, " • %s\n", trim_ws(tok.list_item));
			break;
		case GEMINI_QUOTE:
			// TODO: Option to disable Unicode
			col += fprintf(tty, " | %s\n", trim_ws(tok.quote_text));
			break;
		}

		while (col >= ws.ws_col) {
			col -= ws.ws_col;
			++row;
		}
		++row;
		col = 0;

		if (pagination && row >= ws.ws_row - 1) {
			fprintf(tty, "[Enter for more, or q to stop] ");

			size_t n = 0;
			char *l = NULL;
			if (getline(&l, &n, tty) == -1) {
				return;
			}
			if (strcmp(l, "q\n") == 0) {
				return;
			}

			free(l);
			row = col = 0;
		}
	}

	gemini_parser_finish(&p);
}

int
main(int argc, char *argv[])
{
	bool pagination = true;

	bool have_url = false;
	struct Curl_URL *url = curl_url();

	FILE *tty = fopen("/dev/tty", "w+");

	int c;
	while ((c = getopt(argc, argv, "hP")) != -1) {
		switch (c) {
		case 'P':
			pagination = false;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			fprintf(stderr, "fatal: unknown flag %c\n", c);
			return 1;
		}
	}

	if (optind == argc - 1) {
		set_url(url, argv[optind]);
		have_url = true;
	} else if (optind < argc - 1) {
		usage(argv[0]);
		return 1;
	}

	SSL_load_error_strings();
	ERR_load_crypto_strings();
	struct gemini_options opts = {
		.ssl_ctx = SSL_CTX_new(TLS_method()),
	};

	bool run = true;
	struct gemini_response resp;
	while (run) {
		assert(have_url); // TODO

		struct link *links;
		static char prompt[4096];

		char *plain_url;
		CURLUcode uc = curl_url_get(url, CURLUPART_URL, &plain_url, 0);
		assert(uc == CURLUE_OK); // Invariant

		snprintf(prompt, sizeof(prompt), "\n\t%s\n"
			"\tWhere to? [n]: follow Nth link; [o <url>]: open URL; [q]: quit\n"
			"=> ", plain_url);

		enum gemini_result res = gemini_request(plain_url, &opts, &resp);
		if (res != GEMINI_OK) {
			fprintf(stderr, "Error: %s\n", gemini_strerr(res, &resp));
			assert(0); // TODO: Prompt
		}

		switch (gemini_response_class(resp.status)) {
		case GEMINI_STATUS_CLASS_INPUT:
			assert(0); // TODO
		case GEMINI_STATUS_CLASS_REDIRECT:
			assert(0); // TODO
		case GEMINI_STATUS_CLASS_CLIENT_CERTIFICATE_REQUIRED:
			assert(0); // TODO
		case GEMINI_STATUS_CLASS_TEMPORARY_FAILURE:
		case GEMINI_STATUS_CLASS_PERMANENT_FAILURE:
			fprintf(stderr, "Server returned %s %d %s\n",
				resp.status / 10 == 4 ?
				"TEMPORARY FAILURE" : "PERMANENT FALIURE",
				resp.status, resp.meta);
			break;
		case GEMINI_STATUS_CLASS_SUCCESS:
			display_gemini(tty, &resp, &links, pagination);
			break;
		}

		gemini_response_finish(&resp);

		fprintf(tty, "%s", prompt);
		size_t l = 0;
		char *in = NULL;
		ssize_t n = getline(&in, &l, tty);
		if (n == -1 && feof(tty)) {
			break;
		}

		if (strcmp(in, "q\n") == 0) {
			run = false;
		}

		free(in);
	}

	SSL_CTX_free(opts.ssl_ctx);
	curl_url_cleanup(url);
	return 0;
}
