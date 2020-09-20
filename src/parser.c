#include <assert.h>
#include <ctype.h>
#include <openssl/bio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "gmni.h"

void
gemini_parser_init(struct gemini_parser *p, BIO *f)
{
	p->f = f;
	p->bufln = 0;
	p->bufsz = BUFSIZ;
	p->buf = malloc(p->bufsz + 1);
	p->buf[0] = 0;
	BIO_up_ref(p->f);
}

void
gemini_parser_finish(struct gemini_parser *p)
{
	if (!p) {
		return;
	}
	BIO_free(p->f);
	free(p->buf);
}

int
gemini_parser_next(struct gemini_parser *p, struct gemini_token *tok)
{
	memset(tok, 0, sizeof(*tok));

	int eof = 0;
	while (!strstr(p->buf, "\n")) {
		if (p->bufln == p->bufsz) {
			p->bufsz *= 2;
			char *buf = realloc(p->buf, p->bufsz);
			assert(buf);
			p->buf = buf;
		}

		int n = BIO_read(p->f, &p->buf[p->bufln], p->bufsz - p->bufln);
		if (n == -1) {
			return -1;
		} else if (n == 0) {
			eof = 1;
			break;
		}
		p->bufln += n;
		p->buf[p->bufln] = 0;
	}

	// TODO: Collapse multi-line text for the user-agent to wrap
	char *end;
	if ((end = strstr(p->buf, "\n")) != NULL) {
		*end = 0;
	}

	// TODO: Provide whitespace trimming helper function
	if (strncmp(p->buf, "=>", 2) == 0) {
		tok->token = GEMINI_LINK;
		int i = 2;
		while (p->buf[i] && isspace(p->buf[i])) ++i;
		tok->link.url = &p->buf[i];

		for (; p->buf[i]; ++i) {
			if (isspace(p->buf[i])) {
				p->buf[i++] = 0;
				while (isspace(p->buf[i])) ++i;
				if (p->buf[i]) {
					tok->link.text = strdup(&p->buf[i]);
				}
				break;
			}
		}

		tok->link.url = strdup(tok->link.url);
	} else if (strncmp(p->buf, "```", 3) == 0) {
		tok->token = GEMINI_PREFORMATTED; // TODO
		tok->preformatted.text = strdup("<text>");
		tok->preformatted.alt_text = strdup("<alt-text>");
	} else if (p->buf[0] == '#') {
		tok->token = GEMINI_HEADING;
		int level = 1;
		while (p->buf[level] == '#' && level < 3) {
			++level;
		}
		tok->heading.level = level;
		tok->heading.title = strdup(&p->buf[level]);
	} else if (p->buf[0] == '*') {
		tok->token = GEMINI_LIST_ITEM;
		tok->list_item = strdup(&p->buf[1]);
	} else if (p->buf[0] == '>') {
		tok->token = GEMINI_QUOTE;
		tok->quote_text = strdup(&p->buf[1]);
	} else {
		tok->token = GEMINI_TEXT;
		tok->text = strdup(p->buf);
	}

	if (end && end + 1 < p->buf + p->bufln) {
		size_t len = end - p->buf + 1;
		memmove(p->buf, end + 1, p->bufln - len);
		p->bufln -= len;
	} else {
		p->buf[0] = 0;
		p->bufln = 0;
	}

	return eof;
}

void
gemini_token_finish(struct gemini_token *tok)
{
	if (!tok) {
		return;
	}

	switch (tok->token) {
	case GEMINI_TEXT:
		free(tok->text);
		break;
	case GEMINI_LINK:
		free(tok->link.text);
		free(tok->link.url);
		break;
	case GEMINI_PREFORMATTED:
		free(tok->preformatted.text);
		free(tok->preformatted.alt_text);
		break;
	case GEMINI_HEADING:
		free(tok->heading.title);
		break;
	case GEMINI_LIST_ITEM:
		free(tok->list_item);
		break;
	case GEMINI_QUOTE:
		free(tok->quote_text);
		break;
	}
}
