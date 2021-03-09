#include <assert.h>
#include <bearssl.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <gmni/certs.h>
#include <gmni/gmni.h>
#include <gmni/tofu.h>
#include <gmni/url.h>
#include <libgen.h>
#include <limits.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include "util.h"

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
	int max_width;
	struct gemini_options opts;
	struct gemini_tofu tofu;
	enum tofu_action tofu_mode;

	FILE *tty;
	char *meta;
	char *plain_url;
	char *page_title;
	struct Curl_URL *url;
	struct link *links;
	struct history *history;
	bool running;

	bool searching;
	regex_t regex;
};

enum prompt_result {
	PROMPT_AGAIN,
	PROMPT_MORE,
	PROMPT_QUIT,
	PROMPT_ANSWERED,
	PROMPT_NEXT,
};

const char *default_bookmarks =
	"# Welcome to gmni\n\n"
	"Links:\n\n"
	// TODO: sub out the URL for the appropriate geminispace version once
	// sr.ht supports gemini
	"=> https://sr.ht/~sircmpwn/gmni The gmni browser\n"
	"=> gemini://gemini.circumlunar.space The gemini protocol\n\n"
	"This file can be found at %s and may be edited at your pleasure.\n\n"
	"Bookmarks:\n"
	;

const char *help_msg =
	"The following commands are available:\n\n"
	"q\tQuit\n"
	"N\tFollow Nth link (where N is a number)\n"
	"p[N]\tShow URL of Nth link (where N is a number)\n"
	"b[N]\tJump back N entries in history, N is optional, default 1\n"
	"f[N]\tJump forward N entries in history, N is optional, default 1\n"
	"H\tView all page history\n"
	"m\tSave bookmark\n"
	"M\tBrowse bookmarks\n"
	"r\tReload the page\n"
	"d <path>\tDownload page to <path>\n"
	"|<prog>\tPipe page into program\n"
	"\n"
	"Other commands include:\n\n"
	"<Enter>\tread more lines\n"
	"<url>\tgo to url\n"
	"/<text>\tsearch for text (POSIX regular expression)\n"
	;

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
	free(history->url);
	free(history);
}

static bool
set_url(struct browser *browser, char *new_url, struct history **history)
{
	if (curl_url_set(browser->url, CURLUPART_URL, new_url, 0) != CURLUE_OK) {
		fprintf(stderr, "Error: invalid URL\n");
		return false;
	}
	if (browser->plain_url != NULL) {
		free(browser->plain_url);
	}
	curl_url_get(browser->url, CURLUPART_URL, &browser->plain_url, 0);
	if (history) {
		struct history *next = calloc(1, sizeof(struct history));
		curl_url_get(browser->url, CURLUPART_URL, &next->url, 0);
		next->prev = *history;
		if (*history) {
			if ((*history)->next) {
				history_free((*history)->next);
			}
			(*history)->next = next;
		}
		*history = next;
	}
	return true;
}

static char *
get_data_pathfmt()
{
	const struct pathspec paths[] = {
		{.var = "GMNIDATA", .path = "/%s"},
		{.var = "XDG_DATA_HOME", .path = "/gmni/%s"},
		{.var = "HOME", .path = "/.local/share/gmni/%s"}
	};
	return getpath(paths, sizeof(paths) / sizeof(paths[0]));
}

static char *
trim_ws(char *in)
{
	while (*in && isspace(*in)) ++in;
	return in;
}

static void
save_bookmark(struct browser *browser)
{
	char *path_fmt = get_data_pathfmt();
	static char path[PATH_MAX+1];
	static char dname[PATH_MAX+1];
	size_t n;

	n = snprintf(path, sizeof(path), path_fmt, "bookmarks.gmi");
	assert(n < sizeof(path));
	strncpy(dname, dirname(path), sizeof(dname)-1);
	if (mkdirs(dname, 0755) != 0) {
		snprintf(path, sizeof(path), path_fmt, "bookmarks.gmi");
		free(path_fmt);
		fprintf(stderr, "Error creating directory %s: %s\n",
				dirname(path), strerror(errno));
		return;
	}

	snprintf(path, sizeof(path), path_fmt, "bookmarks.gmi");
	free(path_fmt);
	FILE *f = fopen(path, "a");
	if (!f) {
		fprintf(stderr, "Error opening %s for writing: %s\n",
				path, strerror(errno));
		return;
	}

	char *title = browser->page_title;
	if (title) {
		title = trim_ws(browser->page_title);
	}

	fprintf(f, "=> %s%s%s\n", browser->plain_url,
		title ? " " : "", title ? title : "");
	fclose(f);

	fprintf(browser->tty, "Bookmark saved: %s\n",
		title ? title : browser->plain_url);
}

static void
open_bookmarks(struct browser *browser)
{
	char *path_fmt = get_data_pathfmt();
	static char path[PATH_MAX+1];
	static char dname[PATH_MAX+1];
	size_t n;

	n = snprintf(path, sizeof(path), path_fmt, "bookmarks.gmi");
	assert(n < sizeof(path));
	strncpy(dname, dirname(path), sizeof(dname)-1);
	if (mkdirs(dname, 0755) != 0) {
		snprintf(path, sizeof(path), path_fmt, "bookmarks.gmi");
		free(path_fmt);
		fprintf(stderr, "Error creating directory %s: %s\n",
				dirname(path), strerror(errno));
		return;
	}

	snprintf(path, sizeof(path), path_fmt, "bookmarks.gmi");
	free(path_fmt);

	struct stat buf;
	if (stat(path, &buf) == -1 && errno == ENOENT) {
		// TOCTOU, but we almost certainly don't care
		FILE *f = fopen(path, "a");
		if (f == NULL) {
			fprintf(stderr, "Error opening %s for writing: %s\n",
					path, strerror(errno));
			return;
		}
		fprintf(f, default_bookmarks, path);
		fclose(f);
	}

	static char url[PATH_MAX+1+7];
	snprintf(url, sizeof(url), "file://%s", path);
	set_url(browser, url, &browser->history);
}

static void
print_media_parameters(FILE *out, char *params)
{
	if (params == NULL) {
		fprintf(out, "No media parameters\n");
		return;
	}
	for (char *param = strtok(params, ";"); param;
			param = strtok(NULL, ";")) {
		char *value = strchr(param, '=');
		if (value == NULL) {
			fprintf(out, "Invalid media type parameter '%s'\n",
				trim_ws(param));
			continue;
		}
		*value = 0;
		fprintf(out, "%s: ", trim_ws(param));
		*value++ = '=';
		if (*value != '"') {
			fprintf(out, "%s\n", value);
			continue;
		}
		while (value++) {
			switch (*value) {
			case '\0':
				if ((value = strtok(NULL, ";")) != NULL) {
					fprintf(out, ";%c", *value);
				}
				break;
			case '"':
				value = NULL;
				break;
			case '\\':
				if (value[1] == '\0') {
					break;
				}
				value++;
				/* fallthrough */
			default:
				putc(*value, out);
			}
		}
		putc('\n', out);
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

static bool
has_suffix(char *str, char *suff)
{
	size_t suffl = strlen(suff);
	size_t strl = strlen(str);
	if (strl < suffl) {
		return false;
	}
	return strcmp(&str[strl - suffl], suff) == 0;
}

static void
pipe_resp(FILE *out, struct gemini_response resp, char *cmd) {
	char buf[BUFSIZ];
	int pfd[2];
	if (pipe(pfd) == -1) {
		perror("pipe");
		return;
	}
	pid_t pid;
	switch ((pid = fork())) {
	case -1:
		perror("fork");
		return;
	case 0:
		close(pfd[1]);
		dup2(pfd[0], STDIN_FILENO);
		close(pfd[0]);
		execlp("sh", "sh", "-c", cmd, NULL);
		perror("exec");
		_exit(1);
	}
	close(pfd[0]);
	FILE *f = fdopen(pfd[1], "w");
	// XXX: may affect history, do we care?
	for (int n = 1; n > 0;) {
		if (resp.sc) {
			n = br_sslio_read(&resp.body, buf, BUFSIZ);
		} else {
			n = read(resp.fd, buf, BUFSIZ);
		}
		if (n < 0) {
			n = 0;
		}
		ssize_t w = 0;
		while (w < (ssize_t)n) {
			ssize_t x = fwrite(&buf[w], 1, n - w, f);
			if (ferror(f)) {
				fprintf(stderr, "Error: write: %s\n",
					strerror(errno));
				return;
			}
			w += x;
		}
	}
	fclose(f);
	int status;
	waitpid(pid, &status, 0);
	if (status != 0) {
		fprintf(out, "Command exited %d\n", status);
	}
}

static enum gemini_result
do_requests(struct browser *browser, struct gemini_response *resp)
{
	int nredir = 0;
	bool requesting = true;
	enum gemini_result res;
		
	char *scheme;
	CURLUcode uc = curl_url_get(browser->url,
		CURLUPART_SCHEME, &scheme, 0);
	assert(uc == CURLUE_OK); // Invariant

	char *host = NULL;
	struct gmni_client_certificate client_cert = {0};
	const struct pathspec paths[] = {
		{.var = "GMNIDATA", .path = "/certs/%s.%s"},
		{.var = "XDG_DATA_HOME", .path = "/gmni/certs/%s.%s"},
		{.var = "HOME", .path = "/.local/share/gmni/certs/%s.%s"}
	};
	char *path_fmt = getpath(paths, sizeof(paths) / sizeof(paths[0]));
	char certpath[PATH_MAX+1], keypath[PATH_MAX+1];
	size_t n = 0;

	if (strcmp(scheme, "gemini") == 0) {
		CURLUcode uc = curl_url_get(browser->url,
			CURLUPART_HOST, &host, 0);
		assert(uc == CURLUE_OK);

		n = snprintf(certpath, sizeof(certpath), path_fmt, host, "crt");
		assert(n < sizeof(certpath));
		FILE *certin = fopen(certpath, "r");
		if (certin) {
			n = snprintf(keypath, sizeof(keypath), path_fmt, host, "key");
			assert(n < sizeof(keypath));

			FILE *skin = fopen(keypath, "r");
			if (gmni_ccert_load(&client_cert, certin, skin)) {
				browser->opts.client_cert = NULL;
				fprintf(stderr, "Unable to load client certificate for host %s", host);
			} else {
				browser->opts.client_cert = &client_cert;
			}
		} else {
			browser->opts.client_cert = NULL;
		}
		free(host);
	}

	while (requesting) {
		if (strcmp(scheme, "file") == 0) {
			requesting = false;

			char *path;
			uc = curl_url_get(browser->url,
				CURLUPART_PATH, &path, 0);
			if (uc != CURLUE_OK) {
				resp->status = GEMINI_STATUS_BAD_REQUEST;
				break;
			}

			int fd = open(path, O_RDONLY);
			if (fd < 0) {
				resp->status = GEMINI_STATUS_NOT_FOUND;
				// Make sure members of resp evaluate to false,
				// so that gemini_response_finish does not try
				// to free them.
				resp->sc = NULL;
				resp->meta = NULL;
				resp->fd = -1;
				free(path);
				break;
			}

			if (has_suffix(path, ".gmi") || has_suffix(path, ".gemini")) {
				resp->meta = strdup("text/gemini");
			} else if (has_suffix(path, ".txt")) {
				resp->meta = strdup("text/plain");
			} else {
				resp->meta = strdup("application/x-octet-stream");
			}
			free(path);
			resp->status = GEMINI_STATUS_SUCCESS;
			resp->fd = fd;
			resp->sc = NULL;
			res = GEMINI_OK;
			goto out;
		}

		res = gemini_request(browser->plain_url, &browser->opts,
				&browser->tofu, resp);
		if (res != GEMINI_OK) {
			fprintf(stderr, "Error: %s\n", gemini_strerr(res, resp));
			requesting = false;
			resp->status = 70 + res;
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
			if (input[0] == '\0' && browser->history->prev) {
				free(input);
				browser->history = browser->history->prev;
				set_url(browser, browser->history->url, NULL);
				break;
			}

			char *new_url = gemini_input_url(
				browser->plain_url, input);
			free(input);
			assert(new_url);
			set_url(browser, new_url, NULL);
			free(new_url);
			break;
		case GEMINI_STATUS_CLASS_REDIRECT:
			if (++nredir >= 5) {
				requesting = false;
				fprintf(stderr, "Error: maximum redirects (5) exceeded\n");
				break;
			}
			set_url(browser, resp->meta, NULL);
			break;
		case GEMINI_STATUS_CLASS_CLIENT_CERTIFICATE_REQUIRED:
			requesting = false;
			assert(host);
			n = snprintf(certpath, sizeof(certpath), path_fmt, host, "crt");
			assert(n < sizeof(certpath));
			n = snprintf(keypath, sizeof(keypath), path_fmt, host, "key");
			char dname[PATH_MAX + 1];
			posix_dirname(certpath, dname);
			if (mkdirs(dname, 0755) != 0) {
				fprintf(stderr, "Error creating directory %s: %s\n",
						dname, strerror(errno));
				break;
			}
			assert(n < sizeof(keypath));
			fprintf(stderr, "The server requested a client certificate.\n"
				"Presently, this process is not automated.\n"
				"The following OpenSSL command will generate a certificate for this host:\n\n"
				"openssl req -x509 -newkey rsa:4096 \\\n\t-keyout %s \\\n\t-out %s \\\n\t-days 36500 -nodes\n\n"
				"Use the 'r' command to reload the page after creating this certificate.\n",
				keypath, certpath);
			break;
		case GEMINI_STATUS_CLASS_TEMPORARY_FAILURE:
		case GEMINI_STATUS_CLASS_PERMANENT_FAILURE:
			requesting = false;
			fprintf(stderr, "Server returned %s %d %s\n",
				resp->status / 10 == 4 ?
				"TEMPORARY FAILURE" : "PERMANENT FAILURE",
				resp->status, resp->meta);
			break;
		case GEMINI_STATUS_CLASS_SUCCESS:
			goto out;
		}

		if (requesting) {
			gemini_response_finish(resp);
		}
	}

out:
	if (client_cert.key) {
		free(client_cert.key);
	}
	free(scheme);
	return res;
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
	in[n - 1] = 0; // Remove LF
	char *endptr;

	int historyhops = 1;
	int r;
	switch (in[0]) {
	case '\0':
		result = PROMPT_MORE;
		goto exit;
	case 'q':
		if (in[1]) break;
		result = PROMPT_QUIT;
		goto exit;
	case 'b':
		if (in[1]) {
			historyhops =(int)strtol(in+1, &endptr, 10);
		}
		while (historyhops > 0) {
			if (browser->history->prev) {
				browser->history = browser->history->prev;
			}
			historyhops--;
		}
		set_url(browser, browser->history->url, NULL);
		result = PROMPT_ANSWERED;
		goto exit;
	case 'f':
		if (in[1]) {
			historyhops =(int)strtol(in+1, &endptr, 10);
		}
		while (historyhops > 0) {
			if (browser->history->next) {
				browser->history = browser->history->next;
			}
			historyhops--;
		}
		set_url(browser, browser->history->url, NULL);
		result = PROMPT_ANSWERED;
		goto exit;
	case 'H':
		if (in[1]) break;
		struct history *cur = browser->history;
		while (cur->prev) cur = cur->prev;
		while (cur != browser->history) {
			fprintf(browser->tty, "  %s\n", cur->url);
			cur = cur->next;
		}
		fprintf(browser->tty, "* %s\n", cur->url);
		cur = cur->next;
		while (cur) {
			fprintf(browser->tty, "  %s\n", cur->url);
			cur = cur->next;
		}
		result = PROMPT_AGAIN;
		goto exit;
	case 'm':
		if (in[1]) break;
		save_bookmark(browser);
		result = PROMPT_AGAIN;
		goto exit;
	case 'M':
		if (in[1]) break;
		open_bookmarks(browser);
		result = PROMPT_ANSWERED;
		goto exit;
	case '/':
		if (!in[1]) break;
		if ((r = regcomp(&browser->regex, &in[1], REG_EXTENDED)) != 0) {
			static char buf[1024];
			r = regerror(r, &browser->regex, buf, sizeof(buf));
			assert(r < (int)sizeof(buf));
			fprintf(stderr, "Error: %s\n", buf);
			result = PROMPT_AGAIN;
		} else {
			browser->searching = true;
			result = PROMPT_ANSWERED;
		}
		goto exit_re;
	case 'n':
		if (in[1]) break;
		if (browser->searching) {
			result = PROMPT_NEXT;
			goto exit_re;
		} else {
			fprintf(stderr, "Cannot move to next result; we are not searching for anything\n");
			result = PROMPT_AGAIN;
			goto exit;
		}
	case 'p':
		if (!in[1]) break;
		struct link *link = browser->links;
		int linksel = (int)strtol(in+1, &endptr, 10);
		if (!endptr[0] && linksel >= 0) {
			while (linksel > 0 && link) {
				link = link->next;
				--linksel;
			}

			if (!link) {
				fprintf(stderr, "Error: no such link.\n");
			} else {
				fprintf(browser->tty, "=> %s\n", link->url);
				result = PROMPT_AGAIN;
				goto exit;
			}
		} else {
			fprintf(stderr, "Error: invalid argument.\n");
		}
		result = PROMPT_AGAIN;
		goto exit;
	case 'r':
		if (in[1]) break;
		result = PROMPT_ANSWERED;
		goto exit;
	case 'i':
		if (in[1]) break;
		print_media_parameters(browser->tty, browser->meta
				? strchr(browser->meta, ';') : NULL);
		result = PROMPT_AGAIN;
		goto exit;
	case 'd':
		if (in[1] != '\0' && !isspace(in[1])) break;
		struct gemini_response resp;
		char url[1024] = {0};
		strncpy(&url[0], browser->plain_url, sizeof(url)-1);
		// XXX: may affect history, do we care?
		enum gemini_result res = do_requests(browser, &resp);
		if (res != GEMINI_OK) {
			fprintf(stderr, "Error: %s\n",
				gemini_strerr(res, &resp));
			result = PROMPT_AGAIN;
			goto exit;
		}
		set_url(browser, url, NULL);
		download_resp(browser->tty, resp, trim_ws(&in[1]), url);
		gemini_response_finish(&resp);
		result = PROMPT_AGAIN;
		goto exit;
	case '|':
		strncpy(&url[0], browser->plain_url, sizeof(url)-1);
		res = do_requests(browser, &resp);
		if (res != GEMINI_OK) {
			fprintf(stderr, "Error: %s\n",
				gemini_strerr(res, &resp));
			result = PROMPT_AGAIN;
			goto exit;
		}
		pipe_resp(browser->tty, resp, &in[1]);
		gemini_response_finish(&resp);
		set_url(browser, url, NULL);
		result = PROMPT_AGAIN;
		goto exit;
	case '?':
		if (in[1]) break;
		fprintf(browser->tty, "%s", help_msg);
		result = PROMPT_AGAIN;
		goto exit;
	}

	struct link *link = browser->links;
	int linksel = (int)strtol(in, &endptr, 10);
	if ((endptr[0] == '\0' || endptr[0] == '|') && linksel >= 0) {
		while (linksel > 0 && link) {
			link = link->next;
			--linksel;
		}

		if (!link) {
			fprintf(stderr, "Error: no such link.\n");
		} else if (endptr[0] == '|') {
			char url[1024] = {0};
			struct gemini_response resp;
			strncpy(url, browser->plain_url, sizeof(url) - 1);
			set_url(browser, link->url, &browser->history);
			enum gemini_result res = do_requests(browser, &resp);
			if (res != GEMINI_OK) {
				fprintf(stderr, "Error: %s\n",
					gemini_strerr(res, &resp));
				set_url(browser, url, NULL);
				result = PROMPT_AGAIN;
				goto exit;
			}
			pipe_resp(browser->tty, resp, &endptr[1]);
			gemini_response_finish(&resp);
			set_url(browser, url, NULL);
			result = PROMPT_AGAIN;
			goto exit;
		} else {
			assert(endptr[0] == '\0');
			set_url(browser, link->url, &browser->history);
			result = PROMPT_ANSWERED;
			goto exit;
		}
	}

	set_url(browser, in, &browser->history);
	result = PROMPT_ANSWERED;
exit:
	if (browser->searching) {
		browser->searching = false;
		regfree(&browser->regex);
	}
exit_re:
	free(in);
	return result;
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
		case '\r':
			if (!s[i+1]) break;
			/* fallthrough */
		default:
			// skip unicode continuation bytes
			if ((s[i] & 0xc0) == 0x80) break;

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
			int n = fprintf(f, "%s\n", s) - (isspace(c) ? 0 : 1);
			s[i] = c;
			*row += 1;
			*col = 0;
			return n;
		}
	}
	return fprintf(f, "%s\n", s) - 1;
}

static int
resp_read(void *state, void *buf, size_t nbyte)
{
	struct gemini_response *resp = state;
	if (resp->sc) {
		return br_sslio_read(&resp->body, buf, nbyte);
	} else {
		return read(resp->fd, buf, nbyte);
	}
}

static bool
display_gemini(struct browser *browser, struct gemini_response *resp)
{
	int nlinks = 0;
	struct gemini_parser p;
	gemini_parser_init(&p, &resp_read, resp);
	free(browser->page_title);
	browser->page_title = NULL;

	struct winsize ws;
	ioctl(fileno(browser->tty), TIOCGWINSZ, &ws);
	if (browser->max_width != 0 && ws.ws_col > browser->max_width) {
		ws.ws_col = browser->max_width;
	}

	FILE *out = browser->tty;
	bool searching = browser->searching;
	if (searching) {
		out = fopen("/dev/null", "w+");
	}

	char *text = NULL;
	int row = 0, col = 0;
	struct gemini_token tok;
	struct link **next = &browser->links;
	while (text != NULL || gemini_parser_next(&p, &tok) == 0) {
repeat:
		switch (tok.token) {
		case GEMINI_TEXT:
			col += fprintf(out, "   ");
			if (text == NULL) {
				text = tok.text;
			}
			break;
		case GEMINI_LINK:
			if (text == NULL) {
				col += fprintf(out, "%d) ", nlinks++);
				text = trim_ws(tok.link.text ? tok.link.text : tok.link.url);
				*next = calloc(1, sizeof(struct link));
				(*next)->url = strdup(trim_ws(tok.link.url));
				next = &(*next)->next;
			} else {
				col += fprintf(out, "   ");
			}
			break;
		case GEMINI_PREFORMATTED_BEGIN:
			gemini_token_finish(&tok);
			/* fallthrough */
		case GEMINI_PREFORMATTED_END:
			continue; // Not used
		case GEMINI_PREFORMATTED_TEXT:
			if (text == NULL) {
				text = tok.preformatted;
			}
			break;
		case GEMINI_HEADING:
			if (!browser->page_title) {
				browser->page_title = strdup(tok.heading.title);
			}
			if (text == NULL) {
				for (int n = tok.heading.level; n; --n) {
					col += fprintf(out, "#");
				}
				switch (tok.heading.level) {
				case 1:
					col += fprintf(out, "  ");
					break;
				case 2:
				case 3:
					col += fprintf(out, " ");
					break;
				}
				text = trim_ws(tok.heading.title);
			} else {
				col += fprintf(out, "   ");
			}
			break;
		case GEMINI_LIST_ITEM:
			if (text == NULL) {
				col += fprintf(out, " %s ",
					browser->unicode ? "•" : "*");
				text = trim_ws(tok.list_item);
			} else {
				col += fprintf(out, "   ");
			}
			break;
		case GEMINI_QUOTE:
			col += fprintf(out, " %s ",
					browser->unicode ? "┃" : ">");
			if (text == NULL) {
				text = trim_ws(tok.quote_text);
			}
			break;
		}

		if (text && searching) {
			int r = regexec(&browser->regex, text, 0, NULL, 0);
			if (r != 0) {
				text = NULL;
				continue;
			} else {
				fclose(out);
				row = col = 0;
				out = browser->tty;
				text = NULL;
				searching = false;
				goto repeat;
			}
		}

		if (text) {
			int w = wrap(out, text, &ws, &row, &col);
			text += w;
			if (text[0] && row < ws.ws_row - 4) {
				continue;
			}

			if (!text[0]) {
				text = NULL;
			}
		}
		if (text == NULL) {
			gemini_token_finish(&tok);
		}

		while (col >= ws.ws_col) {
			col -= ws.ws_col;
			++row;
		}
		++row; col = 0;

		if (browser->pagination && row >= ws.ws_row - 4) {
			char prompt[4096];
			char *end = NULL;
			if (browser->meta && (end = strchr(resp->meta, ';')) != NULL) {
				*end = 0;
			}
			snprintf(prompt, sizeof(prompt), "\n%s at %s\n"
				"[Enter]: read more; %s[N]: follow Nth link; %s%s[q]uit; [?]; or type a URL\n"
				"(more) => ", resp->meta, browser->plain_url,
				browser->searching ? "[n]ext result; " : "",
				browser->history->prev ? "[b]ack; " : "",
				browser->history->next ? "[f]orward; " : "");
			if (end != NULL) {
				*end = ';';
			}
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
				if (text != NULL) {
					gemini_token_finish(&tok);
				}
				gemini_parser_finish(&p);
				return true;
			case PROMPT_ANSWERED:
				if (text != NULL) {
					gemini_token_finish(&tok);
				}
				gemini_parser_finish(&p);
				return true;
			case PROMPT_NEXT:
				searching = true;
				out = fopen("/dev/null", "w");
				break;
			}

			row = col = 0;
		}
	}

	gemini_token_finish(&tok);
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
	for (int n = 1; n > 0;) {
		if (resp->sc) {
			n = br_sslio_read(&resp->body, buf, BUFSIZ);
		} else {
			n = read(resp->fd, buf, BUFSIZ);
		}
		if (n < 0) {
			n = 0;
		}
		ssize_t w = 0;
		while (w < (ssize_t)n) {
			ssize_t x = fwrite(&buf[w], 1, n - w, browser->tty);
			if (ferror(browser->tty)) {
				fprintf(stderr, "Error: write: %s\n",
					strerror(errno));
				return 1;
			}
			w += x;
		}
	}

	(void)row; (void)col; // TODO: generalize pagination
	return false;
}

static bool
display_response(struct browser *browser, struct gemini_response *resp)
{
	if (gemini_response_class(resp->status) != GEMINI_STATUS_CLASS_SUCCESS) {
		return false;
	}
	if (strcmp(resp->meta, "text/gemini") == 0
			|| strncmp(resp->meta, "text/gemini;", 12) == 0) {
		return display_gemini(browser, resp);
	}
	if (strncmp(resp->meta, "text/", 5) == 0) {
		return display_plaintext(browser, resp);
	}
	fprintf(stderr, "Media type %s is unsupported, use \"d <path>\" to download this page\n",
		resp->meta);
	return false;
}

static enum tofu_action
tofu_callback(enum tofu_error error, const char *fingerprint,
	struct known_host *khost, void *data)
{
	struct browser *browser = data;
	if (browser->tofu_mode != TOFU_ASK) {
		return browser->tofu_mode;
	}

	static char prompt[8192];
	switch (error) {
	case TOFU_VALID:
		assert(0); // Invariant
	case TOFU_INVALID_CERT:
		snprintf(prompt, sizeof(prompt),
			"The server presented an invalid certificate. If you choose to proceed, "
			"you should not disclose personal information or trust the contents of the page.\n"
			"trust [o]nce; [a]bort\n"
			"=> ");
		break;
	case TOFU_UNTRUSTED_CERT:;
		char *host;
		if (curl_url_get(browser->url, CURLUPART_HOST, &host, 0) != CURLUE_OK) {
			fprintf(stderr, "Error: invalid URL %s\n",
				browser->plain_url);
			return TOFU_FAIL;
		}
		snprintf(prompt, sizeof(prompt),
			"The certificate offered by %s is of unknown trust. "
			"Its fingerprint is: \n"
			"%s\n\n"
			"If you knew the fingerprint to expect in advance, verify that this matches.\n"
			"Otherwise, it should be safe to trust this certificate.\n\n"
			"[t]rust always; trust [o]nce; [a]bort\n"
			"=> ", host, fingerprint);
		free(host);
		break;
	case TOFU_FINGERPRINT_MISMATCH:
		fprintf(browser->tty,
			"The certificate offered by this server DOES NOT MATCH the one we have on file.\n"
			"/!\\ Someone may be eavesdropping on or manipulating this connection. /!\\\n"
			"The unknown certificate's fingerprint is:\n"
			"%s\n\n"
			"The expected fingerprint is:\n"
			"%s\n\n"
			"If you're certain that this is correct, edit %s:%d\n",
			fingerprint, khost->fingerprint,
			browser->tofu.known_hosts_path, khost->lineno);
		return TOFU_FAIL;
	}

	bool prompting = true;
	while (prompting) {
		fprintf(browser->tty, "%s", prompt);

		size_t sz = 0;
		char *line = NULL;
		if (getline(&line, &sz, browser->tty) == -1) {
			free(line);
			return TOFU_FAIL;
		}
		if (line[1] != '\n') {
			free(line);
			continue;
		}

		char c = line[0];
		free(line);

		switch (c) {
		case 't':
			if (error == TOFU_INVALID_CERT) {
				break;
			}
			return TOFU_TRUST_ALWAYS;
		case 'o':
			return TOFU_TRUST_ONCE;
		case 'a':
			return TOFU_FAIL;
		}
	}

	return TOFU_FAIL;
}

int
main(int argc, char *argv[])
{
	struct browser browser = {
		.pagination = true,
		.tofu_mode = TOFU_ASK,
		.unicode = true,
		.url = curl_url(),
		.tty = fopen("/dev/tty", "w+"),
		.meta = NULL,
	};

	int c;
	while ((c = getopt(argc, argv, "hj:PUW:")) != -1) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'j':
			if (strcmp(optarg, "fail") == 0) {
				browser.tofu_mode = TOFU_FAIL;
			} else if (strcmp(optarg, "once") == 0) {
				browser.tofu_mode = TOFU_TRUST_ONCE;
			} else if (strcmp(optarg, "always") == 0) {
				browser.tofu_mode = TOFU_TRUST_ALWAYS;
			} else {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'P':
			browser.pagination = false;
			break;
		case 'U':
			browser.unicode = false;
			break;
		case 'W':
			browser.max_width = strtoul(optarg, NULL, 10);
			break;
		default:
			fprintf(stderr, "fatal: unknown flag %c\n", c);
			curl_url_cleanup(browser.url);
			return 1;
		}
	}

	if (optind == argc - 1) {
		if (!set_url(&browser, argv[optind], &browser.history)) {
			return 1;
		}
	} else {
		open_bookmarks(&browser);
	}

	gemini_tofu_init(&browser.tofu, &tofu_callback, &browser);

	struct gemini_response resp;
	browser.running = true;
	while (browser.running) {
		static char prompt[4096];
		bool skip_prompt = do_requests(&browser, &resp) == GEMINI_OK
			&& display_response(&browser, &resp);
		if (browser.meta) {
			free(browser.meta);
		}
		browser.meta = resp.status == GEMINI_STATUS_SUCCESS
			? strdup(resp.meta) : NULL;
		gemini_response_finish(&resp);
		if (!skip_prompt) {
			char *end = NULL;
			if (browser.meta && (end = strchr(browser.meta, ';')) != NULL) {
				*end = 0;
			}
			snprintf(prompt, sizeof(prompt), "\n%s at %s\n"
				"[N]: follow Nth link; %s%s[q]uit; [?]; or type a URL\n"
				"=> ", browser.meta ? browser.meta
				: "[request failed]", browser.plain_url,
				browser.history->prev ? "[b]ack; " : "",
				browser.history->next ? "[f]orward; " : "");
			if (end != NULL) {
				*end = ';';
			}

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
			case PROMPT_NEXT:
				break;
			}
		}

		struct link *link = browser.links;
		while (link) {
			struct link *next = link->next;
			free(link->url);
			free(link);
			link = next;
		}
		browser.links = NULL;
	}

	gemini_tofu_finish(&browser.tofu);
	struct history *hist = browser.history;
	while (hist && hist->prev) {
		hist = hist->prev;
	}
	history_free(hist);
	curl_url_cleanup(browser.url);
	free(browser.page_title);
	free(browser.plain_url);
	if (browser.meta != NULL) {
		free(browser.meta);
	}
	fclose(browser.tty);
	return 0;
}
