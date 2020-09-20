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

struct history {
	char *url;
	struct history *prev, *next;
};

struct browser {
	bool pagination;
	struct gemini_options opts;

	FILE *tty;
	struct Curl_URL *url;
	struct link *links;
	struct history *history;
};

static void
usage(const char *argv_0)
{
	fprintf(stderr, "usage: %s [gemini://...]\n", argv_0);
}

static void
history_free(struct history *history)
{
	if (!history) {
		return;
	}
	history_free(history->next);
	free(history);
}

static bool
set_url(struct browser *browser, char *new_url, struct history **history)
{
	if (history) {
		struct history *next = calloc(1, sizeof(struct history));
		next->url = strdup(new_url);
		next->prev = *history;
		if (*history) {
			if ((*history)->next) {
				history_free((*history)->next);
			}
			(*history)->next = next;
		}
		*history = next;
	}
	if (curl_url_set(browser->url, CURLUPART_URL, new_url, 0) != CURLUE_OK) {
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
display_gemini(struct browser *browser, struct gemini_response *resp)
{
	// TODO: Strip ANSI escape sequences
	int nlinks = 0;
	struct gemini_parser p;
	gemini_parser_init(&p, resp->bio);

	struct winsize ws;
	ioctl(fileno(browser->tty), TIOCGWINSZ, &ws);

	int row = 0, col = 0;
	struct gemini_token tok;
	struct link **next = &browser->links;
	while (gemini_parser_next(&p, &tok) == 0) {
		switch (tok.token) {
		case GEMINI_TEXT:
			// TODO: word wrap
			col += fprintf(browser->tty, "   %s\n",
					trim_ws(tok.text));
			break;
		case GEMINI_LINK:
			col += fprintf(browser->tty, "[%d] %s\n", nlinks++,
				trim_ws(tok.link.text ? tok.link.text : tok.link.url));
			*next = calloc(1, sizeof(struct link));
			(*next)->url = strdup(trim_ws(tok.link.url));
			next = &(*next)->next;
			break;
		case GEMINI_PREFORMATTED:
			continue; // TODO
		case GEMINI_HEADING:
			for (int n = tok.heading.level; n; --n) {
				col += fprintf(browser->tty, "#");
			}
			col += fprintf(browser->tty, " %s\n",
					trim_ws(tok.heading.title));
			break;
		case GEMINI_LIST_ITEM:
			// TODO: Option to disable Unicode
			col += fprintf(browser->tty, " • %s\n",
					trim_ws(tok.list_item));
			break;
		case GEMINI_QUOTE:
			// TODO: Option to disable Unicode
			col += fprintf(browser->tty, " | %s\n",
					trim_ws(tok.quote_text));
			break;
		}

		while (col >= ws.ws_col) {
			col -= ws.ws_col;
			++row;
		}
		++row;
		col = 0;

		// TODO: It would be nice if we could follow links from this
		// prompt
		if (browser->pagination && row >= ws.ws_row - 1) {
			fprintf(browser->tty, "[Enter for more, or q to stop] ");

			size_t n = 0;
			char *l = NULL;
			if (getline(&l, &n, browser->tty) == -1) {
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

static void
display_plaintext(struct browser *browser, struct gemini_response *resp)
{
	// TODO: Strip ANSI escape sequences
	struct winsize ws;
	int row = 0, col = 0;
	ioctl(fileno(browser->tty), TIOCGWINSZ, &ws);

	char buf[BUFSIZ];
	int n;
	while ((n = BIO_read(resp->bio, buf, sizeof(buf)) != 0)) {
		while (n) {
			n -= fwrite(buf, 1, n, browser->tty);
		}
	}

	(void)row; (void)col; // TODO: generalize pagination
}

static void
display_response(struct browser *browser, struct gemini_response *resp)
{
	if (strcmp(resp->meta, "text/gemini") == 0
			|| strncmp(resp->meta, "text/gemini;", 12) == 0) {
		display_gemini(browser, resp);
		return;
	}
	if (strncmp(resp->meta, "text/", 5) == 0) {
		display_plaintext(browser, resp);
		return;
	}
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
			feof(source) ? "EOF" : strerror(ferror(source)));
		return NULL;
	}
	input[n - 1] = '\0'; // Drop LF
	if (tty && resp->status == GEMINI_STATUS_SENSITIVE_INPUT && r != -1) {
		attrs.c_lflag &= ~ECHO;
		tcsetattr(fileno(source), TCSANOW, &attrs);
	}
	return input;
}

static char *
do_requests(struct browser *browser, struct gemini_response *resp)
{
	char *plain_url;
	int nredir = 0;
	bool requesting = true;
	while (requesting) {
		CURLUcode uc = curl_url_get(browser->url,
				CURLUPART_URL, &plain_url, 0);
		assert(uc == CURLUE_OK); // Invariant

		enum gemini_result res = gemini_request(
				plain_url, &browser->opts, resp);
		if (res != GEMINI_OK) {
			fprintf(stderr, "Error: %s\n", gemini_strerr(res, resp));
			requesting = false;
			break;
		}

		char *input;
		switch (gemini_response_class(resp->status)) {
		case GEMINI_STATUS_CLASS_INPUT:
			input = get_input(resp, browser->tty);
			if (!input) {
				requesting = false;
				break;
			}

			char *new_url = gemini_input_url(plain_url, input);
			assert(new_url);
			set_url(browser, new_url, NULL);
			break;
		case GEMINI_STATUS_CLASS_REDIRECT:
			if (++nredir >= 5) {
				requesting = false;
				fprintf(stderr, "Error: maximum redirects (5) exceeded");
				break;
			}
			fprintf(stderr, "Following redirect to %s\n", resp->meta);
			set_url(browser, resp->meta, NULL);
			break;
		case GEMINI_STATUS_CLASS_CLIENT_CERTIFICATE_REQUIRED:
			assert(0); // TODO
		case GEMINI_STATUS_CLASS_TEMPORARY_FAILURE:
		case GEMINI_STATUS_CLASS_PERMANENT_FAILURE:
			requesting = false;
			fprintf(stderr, "Server returned %s %d %s\n",
				resp->status / 10 == 4 ?
				"TEMPORARY FAILURE" : "PERMANENT FALIURE",
				resp->status, resp->meta);
			break;
		case GEMINI_STATUS_CLASS_SUCCESS:
			requesting = false;
			display_response(browser, resp);
			break;
		}

		if (requesting) {
			gemini_response_finish(resp);
		}
	}

	return plain_url;
}

static bool
do_prompts(const char *prompt, struct browser *browser)
{
	bool prompting = true;
	while (prompting) {
		fprintf(browser->tty, "%s", prompt);

		size_t l = 0;
		char *in = NULL;
		ssize_t n = getline(&in, &l, browser->tty);
		if (n == -1 && feof(browser->tty)) {
			return false;
		}
		if (strcmp(in, "q\n") == 0) {
			return false;
		}
		if (strcmp(in, "b\n") == 0) {
			if (!browser->history->prev) {
				fprintf(stderr, "At beginning of history\n");
				continue;
			}
			browser->history = browser->history->prev;
			set_url(browser, browser->history->url, NULL);
			break;
		}
		if (strcmp(in, "f\n") == 0) {
			if (!browser->history->next) {
				fprintf(stderr, "At end of history\n");
				continue;
			}
			browser->history = browser->history->next;
			set_url(browser, browser->history->url, NULL);
			break;
		}

		struct link *link = browser->links;
		char *endptr;
		int linksel = (int)strtol(in, &endptr, 10);
		if (endptr[0] == '\n' && linksel >= 0) {
			while (linksel > 0 && link) {
				link = link->next;
				--linksel;
			}

			if (!link) {
				fprintf(stderr, "Error: no such link.\n");
			} else {
				set_url(browser, link->url, &browser->history);
				break;
			}
		}
		free(in);
	}
	return true;
}

int
main(int argc, char *argv[])
{
	struct browser browser = {
		.pagination = true,
		.url = curl_url(),
		.tty = fopen("/dev/tty", "w+"),
	};

	int c;
	while ((c = getopt(argc, argv, "hP")) != -1) {
		switch (c) {
		case 'P':
			browser.pagination = false;
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
		set_url(&browser, argv[optind], &browser.history);
	} else {
		usage(argv[0]);
		return 1;
	}

	SSL_load_error_strings();
	ERR_load_crypto_strings();
	browser.opts.ssl_ctx = SSL_CTX_new(TLS_method());

	bool run = true;
	struct gemini_response resp;
	while (run) {
		static char prompt[4096];
		char *plain_url = do_requests(&browser, &resp);

		snprintf(prompt, sizeof(prompt), "\n%s%s at %s\n"
			"[n]: follow Nth link; [o <url>]: open URL; "
			"[b]ack; [f]orward; "
			"[q]uit\n"
			"=> ",
			resp.status == GEMINI_STATUS_SUCCESS ? " " : "",
			resp.status == GEMINI_STATUS_SUCCESS ? resp.meta : "",
			plain_url);
		gemini_response_finish(&resp);

		run = do_prompts(prompt, &browser);

		struct link *link = browser.links;
		while (link) {
			struct link *next = link->next;
			free(link->url);
			free(link);
			link = next;
		}
		browser.links = NULL;
	}

	history_free(browser.history);
	SSL_CTX_free(browser.opts.ssl_ctx);
	curl_url_cleanup(browser.url);
	return 0;
}
