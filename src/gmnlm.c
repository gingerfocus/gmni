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
	bool pagination, unicode;
	struct gemini_options opts;

	FILE *tty;
	char *plain_url;
	struct Curl_URL *url;
	struct link *links;
	struct history *history;
	bool running;
};

enum prompt_result {
	PROMPT_AGAIN,
	PROMPT_MORE,
	PROMPT_QUIT,
	PROMPT_ANSWERED,
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

static enum prompt_result
do_prompts(const char *prompt, struct browser *browser)
{
	enum prompt_result result;
	fprintf(browser->tty, "%s", prompt);

	size_t l = 0;
	char *in = NULL;
	ssize_t n = getline(&in, &l, browser->tty);
	if (n == -1 && feof(browser->tty)) {
		result = PROMPT_QUIT;
		goto exit;
	}
	if (strcmp(in, "\n") == 0) {
		result = PROMPT_MORE;
		goto exit;
	}
	if (strcmp(in, "q\n") == 0) {
		result = PROMPT_QUIT;
		goto exit;
	}
	if (strcmp(in, "b\n") == 0) {
		if (!browser->history->prev) {
			fprintf(stderr, "At beginning of history\n");
			result = PROMPT_AGAIN;
			goto exit;
		}
		browser->history = browser->history->prev;
		set_url(browser, browser->history->url, NULL);
		result = PROMPT_ANSWERED;
		goto exit;
	}
	if (strcmp(in, "f\n") == 0) {
		if (!browser->history->next) {
			fprintf(stderr, "At end of history\n");
			result = PROMPT_AGAIN;
			goto exit;
		}
		browser->history = browser->history->next;
		set_url(browser, browser->history->url, NULL);
		result = PROMPT_ANSWERED;
		goto exit;
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
			result = PROMPT_ANSWERED;
			goto exit;
		}
	}

	in[n - 1] = 0; // Remove LF
	set_url(browser, in, &browser->history);
	result = PROMPT_ANSWERED;
exit:
	free(in);
	return result;
}

static char *
trim_ws(char *in)
{
	while (*in && isspace(*in)) ++in;
	return in;
}

static int
wrap(FILE *f, char *s, struct winsize *ws, int *row, int *col)
{
	if (!s[0]) {
		fprintf(f, "\n");
		return 0;
	}
	for (int i = 0; s[i]; ++i) {
		switch (s[i]) {
		case '\n':
			assert(0); // Not supposed to happen
		case '\t':
			*col = *col + (8 - *col % 8);
			break;
		default:
			if (iscntrl(s[i])) {
				s[i] = '.';
			}
			*col += 1;
			break;
		}

		if (*col >= ws->ws_col) {
			int j = i--;
			while (&s[i] != s && !isspace(s[i])) --i;
			if (&s[i] == s) {
				i = j;
			}
			char c = s[i];
			s[i] = 0;
			int n = fprintf(f, "%s\n", s);
			s[i] = c;
			*row += 1;
			*col = 0;
			return n;
		}
	}
	return fprintf(f, "%s\n", s) - 1;
}

static bool
display_gemini(struct browser *browser, struct gemini_response *resp)
{
	int nlinks = 0;
	struct gemini_parser p;
	gemini_parser_init(&p, resp->bio);

	struct winsize ws;
	ioctl(fileno(browser->tty), TIOCGWINSZ, &ws);

	char *text = NULL;
	int row = 0, col = 0;
	struct gemini_token tok;
	struct link **next = &browser->links;
	while (text != NULL || gemini_parser_next(&p, &tok) == 0) {
		switch (tok.token) {
		case GEMINI_TEXT:
			col += fprintf(browser->tty, "   ");
			if (text == NULL) {
				text = tok.text;
			}
			break;
		case GEMINI_LINK:
			if (text == NULL) {
				col += fprintf(browser->tty, "%d) ", nlinks++);
				text = trim_ws(tok.link.text ? tok.link.text : tok.link.url);
				*next = calloc(1, sizeof(struct link));
				(*next)->url = strdup(trim_ws(tok.link.url));
				next = &(*next)->next;
			} else {
				col += fprintf(browser->tty, "   ");
			}
			break;
		case GEMINI_PREFORMATTED:
			continue; // TODO
		case GEMINI_HEADING:
			if (text == NULL) {
				for (int n = tok.heading.level; n; --n) {
					col += fprintf(browser->tty, "#");
				}
				switch (tok.heading.level) {
				case 1:
					col += fprintf(browser->tty, "  ");
					break;
				case 2:
				case 3:
					col += fprintf(browser->tty, " ");
					break;
				}
				text = trim_ws(tok.heading.title);
			} else {
				col += fprintf(browser->tty, "   ");
			}
			break;
		case GEMINI_LIST_ITEM:
			if (text == NULL) {
				col += fprintf(browser->tty, " %s ",
					browser->unicode ? "•" : "*");
				text = trim_ws(tok.list_item);
			} else {
				col += fprintf(browser->tty, "   ");
			}
			break;
		case GEMINI_QUOTE:
			if (text == NULL) {
				col += fprintf(browser->tty, " %s ",
					browser->unicode ? "|" : "|");
				text = trim_ws(tok.quote_text);
			} else {
				col += fprintf(browser->tty, "   ");
			}
			break;
		}

		if (text) {
			int w = wrap(browser->tty, text, &ws, &row, &col);
			text += w;
			if (text[0] && row < ws.ws_row - 4) {
				continue;
			}

			if (!text[0]) {
				text = NULL;
			}
		}

		while (col >= ws.ws_col) {
			col -= ws.ws_col;
			++row;
		}
		++row; col = 0;

		if (browser->pagination && row >= ws.ws_row - 4) {
			char prompt[4096];
			snprintf(prompt, sizeof(prompt), "\n%s at %s\n"
				"[Enter]: read more; [N]: follow Nth link; %s%s[q]uit; or type a URL\n"
				"(more) => ", resp->meta, browser->plain_url,
				browser->history->prev ? "[b]ack; " : "",
				browser->history->next ? "[f]orward; " : "");
			enum prompt_result result = PROMPT_AGAIN;
			while (result == PROMPT_AGAIN) {
				result = do_prompts(prompt, browser);
			}

			switch (result) {
			case PROMPT_AGAIN:
			case PROMPT_MORE:
				break;
			case PROMPT_QUIT:
				browser->running = false;
				return true;
			case PROMPT_ANSWERED:
				return true;
			}

			row = col = 0;
		}
	}

	gemini_parser_finish(&p);
	return false;
}

static bool
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
	return false;
}

static bool
display_response(struct browser *browser, struct gemini_response *resp)
{
	if (strcmp(resp->meta, "text/gemini") == 0
			|| strncmp(resp->meta, "text/gemini;", 12) == 0) {
		return display_gemini(browser, resp);
	}
	if (strncmp(resp->meta, "text/", 5) == 0) {
		return display_plaintext(browser, resp);
	}
	assert(0); // TODO: Deal with other mimetypes
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

// Returns true to skip prompting
static bool
do_requests(struct browser *browser, struct gemini_response *resp)
{
	int nredir = 0;
	bool requesting = true;
	while (requesting) {
		CURLUcode uc = curl_url_get(browser->url,
				CURLUPART_URL, &browser->plain_url, 0);
		assert(uc == CURLUE_OK); // Invariant

		enum gemini_result res = gemini_request(browser->plain_url,
				&browser->opts, resp);
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

			char *new_url = gemini_input_url(
				browser->plain_url, input);
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
			return display_response(browser, resp);
		}

		if (requesting) {
			gemini_response_finish(resp);
		}
	}

	return false;
}

int
main(int argc, char *argv[])
{
	struct browser browser = {
		.pagination = true,
		.unicode = true,
		.url = curl_url(),
		.tty = fopen("/dev/tty", "w+"),
	};

	int c;
	while ((c = getopt(argc, argv, "hPU")) != -1) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'P':
			browser.pagination = false;
			break;
		case 'U':
			browser.unicode = false;
			break;
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

	struct gemini_response resp;
	browser.running = true;
	while (browser.running) {
		static char prompt[4096];
		if (do_requests(&browser, &resp)) {
			// Skip prompts
			goto next;
		}

		snprintf(prompt, sizeof(prompt), "\n%s at %s\n"
			"[N]: follow Nth link; %s%s[q]uit; or type a URL\n"
			"=> ",
			resp.status == GEMINI_STATUS_SUCCESS ? resp.meta : "",
			browser.plain_url,
			browser.history->prev ? "[b]ack; " : "",
			browser.history->next ? "[f]orward; " : "");
		gemini_response_finish(&resp);

		enum prompt_result result = PROMPT_AGAIN;
		while (result == PROMPT_AGAIN || result == PROMPT_MORE) {
			result = do_prompts(prompt, &browser);
		}
		switch (result) {
		case PROMPT_AGAIN:
		case PROMPT_MORE:
			assert(0);
		case PROMPT_QUIT:
			browser.running = false;
			break;
		case PROMPT_ANSWERED:
			break;
		}

next:;
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
