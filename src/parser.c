#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmni/gmni.h>

void
gemini_parser_init(struct gemini_parser *p,
	int (*read)(void *state, void *buf, size_t nbyte),
	void *state)
{
	p->read = read;
	p->state = state;
	p->bufln = 0;
	p->bufsz = BUFSIZ;
	p->buf = malloc(p->bufsz + 1);
	p->buf[0] = 0;
	p->preformatted = false;
}

void
gemini_parser_finish(struct gemini_parser *p)
{
	if (!p) {
		return;
	}
	free(p->buf);
}

int
gemini_parser_next(struct gemini_parser *p, struct gemini_token *tok)
{
	memset(tok, 0, sizeof(*tok));

	int eof = 0;
	while (!strchr(p->buf, '\n')) {
		while (p->bufln >= p->bufsz - 1) {
			p->bufsz *= 2;
			p->buf = realloc(p->buf, p->bufsz);
			assert(p->buf);
		}

		int n = p->read(p->state, &p->buf[p->bufln], p->bufsz - p->bufln - 1);
		if (n == -1) {
			return -1;
		} else if (n == 0) {
			eof = p->bufln == 0;
			break;
		}
		p->bufln += n;
		p->buf[p->bufln] = 0;
	}

	char *end;
	if ((end = strchr(p->buf, '\n')) != NULL) {
		*end = 0;
	}

	if (p->preformatted) {
		if (strncmp(p->buf, "```", 3) == 0) {
			tok->token = GEMINI_PREFORMATTED_END;
			p->preformatted = false;
		} else {
			tok->token = GEMINI_PREFORMATTED_TEXT;
			tok->preformatted = strdup(p->buf);
		}
	} else if (strncmp(p->buf, "=>", 2) == 0) {
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
		tok->token = GEMINI_PREFORMATTED_BEGIN;
		if (p->buf[3]) {
			tok->preformatted = strdup(&p->buf[3]);
		}
		p->preformatted = true;
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
		p->buf[p->bufln] = 0;
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
	case GEMINI_PREFORMATTED_BEGIN:
		free(tok->preformatted);
		break;
	case GEMINI_PREFORMATTED_TEXT:
		free(tok->preformatted);
		break;
	case GEMINI_PREFORMATTED_END:
		// Nothing to free
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
